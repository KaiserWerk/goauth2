package goauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"time"
)

type TokenResponse struct {
	AccessToken string
	Expires     uint64
	Scopes      []string
	State       string
}

type Server struct {
	PublicBaseURL            string
	DeviceCodeRequestStorage DeviceCodeStorage
	SessionStorage           SessionStorage
	UserStorage              UserStorage
	ClientStorage            ClientStorage
	TokenStorage             TokenStorage
	TokenSource              TokenSource
	EnabledGrantTypes        []GrantType
	EnablePKCE               bool
}

func (s *Server) HandleAuthorizationRequest(w http.ResponseWriter, r *http.Request) error {
	// if the user is not logged in
	// redirect to login page with redirect back url

	q := r.URL.Query()
	responseType := q.Get("response_type")
	grantType := q.Get("authorization_code")
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	scope := q.Get("scope")
	state := q.Get("state")
	fmt.Println("response type:", responseType)
	fmt.Println("grant type:", grantType)
	fmt.Println("client id:", clientID)
	fmt.Println("redirect uri:", redirectURI)
	fmt.Println("scope:", scope)
	fmt.Println("state:", state)
	switch {
	case responseType == "code":
		if r.Method == http.MethodGet {
			// write authorize template
		} else if r.Method == http.MethodPost {
			username := r.FormValue("_username")
			password := r.FormValue("_password")
			u, err := s.UserStorage.GetByUsername(username)
			if err != nil {
				http.Error(w, "failed to find user", http.StatusNotFound)
				return err
			}

			if u.Password != password {

			}
		}
	}

	http.Error(w, "failed", http.StatusInternalServerError)

	return errors.New("undefined grant type")
}

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

	userCode := generateCode(8)
	req := DeviceCodeRequest{
		ClientID: values.Get("client_id"),
		Response: DeviceCodeResponse{
			DeviceCode:              generateCode(60),
			UserCode:                userCode,
			VerificationURI:         s.PublicBaseURL + "/device",
			VerificationURIComplete: s.PublicBaseURL + "/device?user_code=" + userCode,
			ExpiresIn:               1800,
			Interval:                5,
		},
	}
	if err := s.DeviceCodeRequestStorage.Add(req); err != nil {
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
		if err := ExecuteTemplate(w, "device_code.gohtml", data); err != nil {
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

		deviceRequest, err := s.DeviceCodeRequestStorage.Get(userCode)
		if err != nil {
			http.Error(w, "failed to find device code request", http.StatusNotFound)
			return fmt.Errorf("failed to find device code request")
		}

		deviceRequest.TokenResponse = DeviceCodeTokenResponse{
			AccessToken: generateCode(120),
			TokenType:   "bearer",
			ExpiresIn:   86400,
		}

		if err := s.DeviceCodeRequestStorage.Update(deviceRequest); err != nil {
			http.Error(w, "failed to update device code request", http.StatusNotFound)
			return fmt.Errorf("failed to update device code request")
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

	deviceRequest, err := s.DeviceCodeRequestStorage.Find(values.Get("device_code"), values.Get("client_id"))
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
		if err := ExecuteTemplate(w, "login.gohtml", nil); err != nil {
			http.Error(w, "failed to find template", http.StatusNotFound)
			return fmt.Errorf("failed to find template '%s'", "login.gohtml")
		}
		return nil
	} else if r.Method == http.MethodPost {
		username := r.FormValue("_username")
		password := r.FormValue("_password")
		u, err := s.UserStorage.GetByUsername(username)
		if err != nil {
			http.Error(w, "failed to find user", http.StatusNotFound)
			return err
		}

		if u.Password != password {
			http.Error(w, "passwords didn't match", http.StatusNotFound)
			return fmt.Errorf("passwords didn't match")
		}

		session := Session{
			ID:     generateCode(45),
			UserID: u.ID,
		}
		if err := s.SessionStorage.Add(session); err != nil {
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

func (s *Server) isLoggedIn(r *http.Request) (User, error) {
	sid, err := getSessionIDFromRequest(r)
	if err != nil || sid == "" {
		return User{}, nil
	}

	session, err := s.SessionStorage.Get(sid)
	if err != nil {
		return User{}, fmt.Errorf("user had session ID, but was not found")
	}

	user, err := s.UserStorage.Get(session.UserID)
	if err != nil {
		return User{}, fmt.Errorf("valid session, but didn't find user")
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

func ExecuteTemplate(w io.Writer, file string, data interface{}) error {
	tmplContent, err := GetTemplate(file)
	if err != nil {
		return err
	}

	tmpl := template.Must(template.New(file).Parse(string(tmplContent)))
	if err = tmpl.Execute(w, data); err != nil {
		return err
	}

	return nil
}
