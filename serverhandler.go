package goauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/KaiserWerk/goauth2/storage"
)

var (
	ErrLoggedIn = errors.New("user is already logged in")
)

func (s *Server) HandleClientCredentialsTokenRequest(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return fmt.Errorf("expected method '%s', got '%s'", http.MethodPost, r.Method)
	}

	return nil
}

func (s *Server) HandleResourceOwnerCredentialsTokenRequest(w http.ResponseWriter, r *http.Request) error {

	return nil
}

/* Device Code */

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

	userCode, err := s.TokenSource.Token(6)
	if err != nil {
		http.Error(w, "failed to generate user code", http.StatusInternalServerError)
		return fmt.Errorf("failed to generate user code: %s", err.Error())
	}

	deviceCode, err := s.TokenSource.Token(0)
	if err != nil {
		http.Error(w, "failed to generate device code", http.StatusInternalServerError)
		return fmt.Errorf("failed to generate device code: %s", err.Error())
	}

	req := storage.DeviceCodeRequest{
		ClientID: values.Get("client_id"),
		Response: storage.DeviceCodeResponse{
			DeviceCode:              deviceCode,
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

func (s *Server) HandleDeviceCodeUserAuthorization(w http.ResponseWriter, r *http.Request) error {
	_, err := s.isLoggedIn(r)
	if err != nil {
		http.Redirect(w, r, fmt.Sprintf("%s?redirect_uri=%s", s.URLs.Login, url.QueryEscape(s.URLs.DeviceCodeUserAuthorization)), http.StatusSeeOther)
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

		accessToken, err := s.TokenSource.Token(0)
		if err != nil {
			http.Error(w, "failed to generate access token", http.StatusInternalServerError)
			return fmt.Errorf("failed to generate user code: %s", err.Error())
		}

		deviceRequest.TokenResponse = storage.DeviceCodeTokenResponse{
			AccessToken: accessToken,
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

/* User authentication */

func (s *Server) HandleUserLogin(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("content-Type", "text/html; charset=utf8")
	user, err := s.isLoggedIn(r)
	if err == nil && user.Username != "" {
		fmt.Fprintln(w, template.HTML("You are already logged in! You can perform authorizations now. <a href='"+s.URLs.Logout+"'>Log out</a>"))
		return nil
	}

	if errors.Is(err, ErrLoggedIn) {
		http.Error(w, "You are already logged in!", http.StatusOK)
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

		sessionID, err := s.TokenSource.Token(0)
		if err != nil {
			http.Error(w, "failed to generate session ID", http.StatusInternalServerError)
			return fmt.Errorf("failed to generate session ID: %s", err.Error())
		}
		session := storage.Session{
			ID:      sessionID,
			UserID:  u.ID,
			Expires: time.Now().Add(30 * 24 * time.Hour),
		}
		if err := s.Storage.SessionStorage.Add(session); err != nil {
			http.Error(w, "failed to add session", http.StatusNotFound)
			return fmt.Errorf("failed to add session: %s", err.Error())
		}

		http.SetCookie(w, &http.Cookie{
			Name:    s.Session.CookieName,
			Value:   session.ID,
			Expires: time.Now().Add(30 * 24 * time.Hour),
		})

		fmt.Fprintln(w, "Login successful!")

		if red := r.URL.Query().Get("redirect_uri"); red != "" {
			unesc, err := url.QueryUnescape(red)
			if err != nil {
				http.Error(w, "invalid redirect URI", http.StatusBadRequest)
				return fmt.Errorf("invalid redirect URI '%s': %s", red, err.Error())
			}
			http.Redirect(w, r, unesc, http.StatusSeeOther)
			return nil
		}

		return nil
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
	return fmt.Errorf("method not allowed")
}

func (s *Server) HandleUserLogout(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("content-Type", "text/html; charset=utf8")
	sid, err := s.getSessionID(r)
	if err != nil || sid == "" {
		http.Error(w, "you are not logged in!", http.StatusNotFound)
		return fmt.Errorf("user is not logged in")
	}

	if err = s.Storage.SessionStorage.Remove(sid); err != nil {
		http.Error(w, "failed to remove user session!", http.StatusInternalServerError)
		return fmt.Errorf("failed to remove user session: %s", err.Error())
	}

	fmt.Fprintln(w, template.HTML("success! you are logged out. <a href='"+s.URLs.Login+"'>Log in again</a>"))
	return nil
}

/* helpers */

func (s *Server) isLoggedIn(r *http.Request) (storage.User, error) {
	sid, err := s.getSessionID(r)
	if err != nil || sid == "" {
		return storage.User{}, fmt.Errorf("user is not logged in")
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

func (s *Server) getSessionID(r *http.Request) (string, error) {
	c, err := r.Cookie(s.Session.CookieName)
	if err != nil {
		return "", err
	}

	return c.Value, nil
}

func executeTemplate(w io.Writer, content []byte, data interface{}) error {
	if content == nil {
		return fmt.Errorf("template content was nil")
	}
	tmpl := template.Must(template.New("").Parse(string(content)))
	return tmpl.Execute(w, data)
}
