package goauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/KaiserWerk/goauth2/storage"
)

// HandleDeviceCodeAuthorizationRequest handles the request to initiate the device code flow by returning the
// device code, the user code and a validation URL.
func (s *Server) HandleDeviceCodeAuthorizationRequest(w http.ResponseWriter, r *http.Request) error { // Step 1
	if r.Method != http.MethodPost {
		http.Error(w, "disallowed method", http.StatusBadRequest)
		return fmt.Errorf("method %s not allowed", r.Method)
	}

	if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		http.Error(w, "wrong content type header", http.StatusBadRequest)
		return fmt.Errorf("expected content type header to be 'application/x-www-form-urlencoded'. got '%s'", ct)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "error reading request body", http.StatusBadRequest)
		return fmt.Errorf("failed to read request body: %s", err.Error())
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		http.Error(w, "malformed request body", http.StatusBadRequest)
		return fmt.Errorf("failed to parse request body: %s", err.Error())
	}

	if !values.Has("client_id") {
		http.Error(w, "missing request parameter", http.StatusBadRequest)
		return fmt.Errorf("missing request parameter '%s'", "client_id")
	}

	// TODO: check if valid client

	userCode := generateCode(6)
	req := storage.DeviceCodeRequest{
		ClientID: values.Get("client_id"),
		Response: storage.DeviceCodeResponse{
			DeviceCode:              generateCode(60),
			UserCode:                userCode,
			VerificationURI:         s.PublicBaseURL + "/device",
			VerificationURIComplete: s.PublicBaseURL + "/device?user_code=" + userCode,
			ExpiresIn:               1800,
			Interval:                5,
		},
	}
	if err := s.Storage.DeviceCodeRequestStorage.Add(req); err != nil {
		http.Error(w, "failed to store request", http.StatusInternalServerError)
		return fmt.Errorf("failed to store request: %s", err.Error())
	}

	if err := json.NewEncoder(w).Encode(req.Response); err != nil {
		http.Error(w, "failed to write JSON", http.StatusInternalServerError)
		return fmt.Errorf("failed to write JSON: %s", err.Error())
	}

	return nil
}

func (s *Server) HandleDeviceCodeUserAuthorization(w http.ResponseWriter, r *http.Request, loginURL string) error {
	redirectURL := r.URL.Path
	if redirectURL != "" {
		loginURL += "?redirect_uri=" + redirectURL
	}
	_, err := s.isLoggedIn(r)
	if err != nil {
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return nil
	}
	// user is certainly logged in from here on

	if r.Method == http.MethodGet {
		// TODO: set data!
		data := struct {
			Message         string
			ApplicationName string
		}{
			Message:         "",
			ApplicationName: "My Cool Test App",
		}
		if err := executeTemplate(w, s.Template.DeviceCode, data); err != nil {
			http.Error(w, "failed to find template", http.StatusNotFound)
			return fmt.Errorf("failed to find template: %s", err.Error())
		}
		return nil
	} else if r.Method == http.MethodPost {
		userCode := r.FormValue("_user_code")
		if userCode == "" {
			http.Error(w, "empty user code", http.StatusBadRequest)
			return fmt.Errorf("user failed to provide a user code")
		}

		deviceRequest, err := s.Storage.DeviceCodeRequestStorage.Get(userCode)
		if err != nil {
			http.Error(w, "failed to find device code request", http.StatusNotFound)
			return fmt.Errorf("failed to find device code request")
		}

		deviceRequest.TokenResponse = storage.DeviceCodeTokenResponse{
			AccessToken: generateCode(120),
			TokenType:   "Bearer",
			ExpiresIn:   86400,
		}

		if err := s.Storage.DeviceCodeRequestStorage.Update(deviceRequest); err != nil {
			http.Error(w, "failed to update device code request", http.StatusNotFound)
			return fmt.Errorf("failed to update device code request: %s", err.Error())
		}

		http.Error(w, "success. you can close this window.", http.StatusOK)
		return nil
	}

	return nil
}

func (s *Server) HandleDeviceTokenRequest(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		http.Error(w, "disallowed method", http.StatusBadRequest)
		return fmt.Errorf("method %s not allowed", r.Method)
	}

	if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		http.Error(w, "wrong content type header", http.StatusBadRequest)
		return fmt.Errorf("expected content type header to be 'application/x-www-form-urlencoded'. got '%s'", ct)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "error reading request body", http.StatusBadRequest)
		return fmt.Errorf("failed to read request body: %s", err.Error())
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		http.Error(w, "malformed request body", http.StatusBadRequest)
		return fmt.Errorf("failed to parse request body: %s", err.Error())
	}

	if !values.Has("client_id") || !values.Has("grant_type") || !values.Has("device_code") {
		http.Error(w, "missing request parameter(s)", http.StatusBadRequest)
		return fmt.Errorf("missing request parameter(s)")
	}

	deviceRequest, err := s.Storage.DeviceCodeRequestStorage.Find(values.Get("device_code"), values.Get("client_id"))
	if err != nil {
		http.Error(w, "failed to find request", http.StatusBadRequest)
		return fmt.Errorf("failed to find request: %s", err.Error())
	}

	if deviceRequest.TokenResponse.AccessToken == "" {
		http.Error(w, `{"error": "authorization_pending"}`, http.StatusOK)
	} else {
		if err := json.NewEncoder(w).Encode(deviceRequest.TokenResponse); err != nil {
			http.Error(w, "failed to serialize JSON", http.StatusBadRequest)
			return fmt.Errorf("failed to serialize JSON: %s", err.Error())
		}
	}

	return nil
}

func (s *Server) HandleUserLogin(w http.ResponseWriter, r *http.Request) error {
	_, err := s.isLoggedIn(r)
	if err == nil {
		http.Error(w, "You are already logged in! You can perform authorizations now.", http.StatusOK)
		return nil
	}

	if r.Method == http.MethodGet {
		if err := executeTemplate(w, s.Template.Login, nil); err != nil {
			http.Error(w, "failed to find template", http.StatusNotFound)
			return fmt.Errorf("failed to find template '%s'", "login.gohtml")
		}
		return nil
	} else if r.Method == http.MethodPost {
		username := r.FormValue("_username")
		password := r.FormValue("_password")
		u, err := s.Storage.UserStorage.GetByUsername(username)
		if err != nil {
			http.Error(w, "failed to find user", http.StatusNotFound)
			return err
		}

		if u.Password != password {
			http.Error(w, "passwords didn't match", http.StatusNotFound)
			return fmt.Errorf("passwords didn't match")
		}

		session := storage.Session{
			ID:     generateCode(45),
			UserID: u.ID,
		}
		if err := s.Storage.SessionStorage.Add(session); err != nil {
			http.Error(w, "failed to add session", http.StatusNotFound)
			return fmt.Errorf("failed to add session: %s", err.Error())
		}

		http.SetCookie(w, &http.Cookie{
			Name:    "GOAUTH_SID",
			Value:   session.ID,
			Expires: time.Now().Add(30 * 24 * time.Hour),
		})

		if red := r.URL.Query().Get("redirect_uri"); red != "" {
			http.Redirect(w, r, red, http.StatusSeeOther)
		}

		return nil
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
	return fmt.Errorf("method not allowed")
}

func (s *Server) isLoggedIn(r *http.Request) (storage.User, error) {
	sid, err := getSessionIDFromRequest(r)
	if err != nil || sid == "" {
		return storage.User{}, nil
	}

	session, err := s.Storage.SessionStorage.Get(sid)
	if err != nil {
		return storage.User{}, fmt.Errorf("user had session ID, but was not found")
	}

	user, err := s.Storage.UserStorage.Get(session.UserID)
	if err != nil {
		return storage.User{}, fmt.Errorf("valid session, but didn't find user")
	}

	return user, nil
}

func getSessionIDFromRequest(r *http.Request) (string, error) {
	c, err := r.Cookie("GOAUTH_SID")
	if err != nil {
		return "", err
	}

	return c.Value, nil
}

func generateCode(length int) string {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return base64.RawStdEncoding.EncodeToString(b)
}

func executeTemplate(w io.Writer, content []byte, data interface{}) error {
	tmpl := template.Must(template.New("").Parse(string(content)))
	if err := tmpl.Execute(w, data); err != nil {
		return err
	}

	return nil
}

//func ExecuteTemplate(w io.Writer, file string, data interface{}) error {
//	tmplContent, err := GetTemplate(file)
//	if err != nil {
//		return err
//	}
//
//	tmpl := template.Must(template.New(file).Parse(string(tmplContent)))
//	if err = tmpl.Execute(w, data); err != nil {
//		return err
//	}
//
//	return nil
//}
