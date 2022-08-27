package goauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KaiserWerk/goauth2/storage"
)

var (
	ErrLoggedIn = errors.New("user is already logged in")
)

/* Client Credentials Grant */

// HandleClientCredentialsRequest expects a POST request sending client ID and client secret of a client
// and, in case of correct credentials, exchanges them for an access token.
func (s *Server) HandleClientCredentialsRequest(w http.ResponseWriter, r *http.Request) error {
	defer r.Body.Close()
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return fmt.Errorf("expected method '%s', got '%s'", http.MethodPost, r.Method)
	}

	if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		http.Error(w, "wrong content type header", http.StatusBadRequest)
		return fmt.Errorf("expected content type header to be 'application/x-www-form-urlencoded'. got '%s'", ct)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "error reading request body", http.StatusBadRequest)
		return fmt.Errorf("failed to read request body: %w", err)
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		http.Error(w, "malformed request body", http.StatusBadRequest)
		return fmt.Errorf("failed to parse request body: %w", err)
	}

	if !values.Has("grant_type") {
		http.Error(w, "missing request parameter", http.StatusBadRequest)
		return fmt.Errorf("missing request parameter '%s'", "grant_type")
	}

	if gt := values.Get("grant_type"); gt != "client_credentials" {
		http.Error(w, "invalid grant type parameter", http.StatusBadRequest)
		return fmt.Errorf("expected grant type '%s', got '%s'", "client_credentials", gt)
	}

	// check if clientID and clientSecret are in header or body
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = values.Get("client_id")
		clientSecret = values.Get("client_secret")
	}

	if clientID == "" || clientSecret == "" {
		http.Error(w, "missing client credentials", http.StatusBadRequest)
		return fmt.Errorf("missing client credentials")
	}

	client, err := s.Storage.ClientStorage.Get(clientID)
	if err != nil {
		http.Error(w, "could not find client", http.StatusNotFound)
		return fmt.Errorf("failed to get client by ID '%s': %w", clientID, err)
	}

	if client.Secret != clientSecret {
		http.Error(w, "incorrect credentials", http.StatusNotFound)
		return fmt.Errorf("failed to confirm correct password for client by ID '%s'", clientID)
	}

	accessToken, err := s.TokenGenerator.Generate(s.Policies.AccessTokenLength)
	if err != nil {
		http.Error(w, "failed to create access token", http.StatusInternalServerError)
		return fmt.Errorf("failed to create access token: %w", err)
	}

	resp := storage.Token{
		AccessToken: accessToken,
		ExpiresIn:   uint64(s.Policies.AccessTokenLifetime.Seconds()),
		TokenType:   "Bearer",
	}

	if err = s.Storage.TokenStorage.Set(resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return fmt.Errorf("failed to store token: %w", err)
	}

	if err = json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	return nil
}

/* Resource Owner Password Credentials Grant */

// HandleResourceOwnerPasswordCredentialsRequest expects a POST request sending username and password of a resource
// owner and, in case of correct credentials, exchanges them for an access token.
func (s *Server) HandleResourceOwnerPasswordCredentialsRequest(w http.ResponseWriter, r *http.Request) error {
	defer r.Body.Close()
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return fmt.Errorf("expected method '%s', got '%s'", http.MethodPost, r.Method)
	}

	if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		http.Error(w, "wrong content type header", http.StatusBadRequest)
		return fmt.Errorf("expected content type header to be 'application/x-www-form-urlencoded'. got '%s'", ct)
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "failed authentication", http.StatusUnauthorized)
		return fmt.Errorf("failed authentication")
	}

	user, err := s.Storage.UserStorage.GetByUsername(username)
	if err != nil {
		http.Error(w, "unknown credentials", http.StatusUnauthorized)
		return fmt.Errorf("failed to find user '%s': %s", username, err.Error())
	}

	if user.Password != password {
		http.Error(w, "unknown credentials", http.StatusUnauthorized)
		return fmt.Errorf("incorrect password for user '%s'", username)
	}

	accessToken, err := s.TokenGenerator.Generate(0)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return fmt.Errorf("failed to generate access token: %s", err.Error())
	}

	t := storage.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   uint64(s.Policies.AccessTokenLifetime.Seconds()),
	}

	if err = s.Storage.TokenStorage.Set(t); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return fmt.Errorf("failed to store token: %s", err.Error())
	}

	if err = json.NewEncoder(w).Encode(t); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return fmt.Errorf("failed to marshal JSON response: %s", err.Error())
	}

	return nil
}

/* Implicit Grant */

func (s *Server) HandleImplicitAuthorizationRequest(w http.ResponseWriter, r *http.Request) error {
	_, err := s.isLoggedIn(r)
	if err != nil {
		http.Redirect(w, r, fmt.Sprintf("%s?%s&redirect_back=%s", s.URLs.Login, r.URL.RawQuery, url.QueryEscape(s.URLs.Implicit)), http.StatusSeeOther)
		return nil
	}

	// get the client ID
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		http.Error(w, "missing required request parameter client_id", http.StatusBadRequest)
		return fmt.Errorf("missing URL parameter 'client_id'")
	}

	// check if a client with this ID exists and if so, fetch it
	client, err := s.Storage.ClientStorage.Get(clientID)
	if err != nil {
		http.Error(w, "invalid client ID", http.StatusBadRequest)
		return fmt.Errorf("the client ID '%s' was not found: %s", clientID, err.Error())
	}

	// check if a redirect URL is set and valid
	redirectURIRaw := r.URL.Query().Get("redirect_uri")
	redirectURL, err2 := url.QueryUnescape(redirectURIRaw)
	_, err3 := url.ParseRequestURI(redirectURL)
	if redirectURIRaw == "" || err2 != nil || err3 != nil {
		http.Error(w, "missing or invalid parameter redirect_uri", http.StatusBadRequest)
		return fmt.Errorf("failed to parse 'redirect_uri' parameter as URL: missing: %t / err: %v / err %v", redirectURIRaw == "", err2, err3)
	}

	// check if the redirect URL is in the client's list of registered redirect URLs
	found := false
	for _, e := range client.RedirectURLs {
		if e == redirectURL {
			found = true
			break
		}
	}
	if !found {
		s.ErrorRedirect(w, r, redirectURL, InvalidRequest, "callback URL not registered for client", "")
		return fmt.Errorf("callback URL '%s' is not registered for client '%s'", redirectURL, client)
	}

	// get the state parameter and check for emptiness
	state := r.URL.Query().Get("state")
	if state == "" {
		s.ErrorRedirect(w, r, redirectURL, InvalidRequest, "missing required request parameter state", "")
		return fmt.Errorf("invalid empty value for parameter 'state'")
	}

	// get the scope parameter and check for emptiness
	scopeRaw := r.URL.Query().Get("scope")
	if scopeRaw == "" {
		s.ErrorRedirect(w, r, redirectURL, InvalidRequest, "missing required request parameter scope", state)
		return fmt.Errorf("missing URL parameter 'scope'")
	}

	// parse the scope values
	scope, err := url.QueryUnescape(scopeRaw)
	if err != nil {
		http.Error(w, "invalid value for parameter 'scope'", http.StatusBadRequest)
		return fmt.Errorf("failed to unescape 'scope 'parameter: %s", err.Error())
	}
	scopes := strings.Split(scope, " ")

	// check the response type (currently only token)
	responseType := r.URL.Query().Get("response_type")
	if responseType != "token" { // only response type 'token' is supported by implicit flow?
		s.ErrorRedirect(w, r, redirectURL, InvalidRequest, "parameter response_type missing or invalid", state)
		return fmt.Errorf("invalid value '%s' for parameter 'response_type'", responseType)
	}

	// check the response type (currently only fragment)
	responseMode := r.URL.Query().Get("response_mode")
	if responseMode != "fragment" { // only response mode 'fragment' is supported by implicit flow?
		s.ErrorRedirect(w, r, redirectURL, InvalidRequest, "parameter response_mode missing or invalid", state)
		return fmt.Errorf("invalid value '%s' for parameter 'response_mode'", responseMode)
	}

	// determine whether to present or process the form
	if r.Method == http.MethodGet {
		data := struct {
			Scopes          []string
			CancelURL       string
			Message         string
			ApplicationName string
		}{
			Scopes:          scopes,
			CancelURL:       fmt.Sprintf("%s?error=canceled", redirectURL),
			ApplicationName: client.ApplicationName,
		}
		if err = executeTemplate(w, s.Template.ImplicitGrant, data); err != nil {
			s.ErrorRedirect(w, r, redirectURL, ServerError, "template error", state)
			return fmt.Errorf("template error: %w", err)
		}
	} else if r.Method == http.MethodPost {
		_ = r.ParseForm()

		// compare the accepted scopes with the initially requested scopes. has to be fewer or equal number and
		// accepted values must be in initial scope
		var acceptedScopes storage.Scope = r.Form["_accepted_scopes"]
		for _, as := range acceptedScopes {
			if !isStringInSlice(scopes, as) {
				s.ErrorRedirect(w, r, redirectURL, InvalidScope, "user authorized scopes did not match initial scopes", state)
				return fmt.Errorf("scope '%s' was not in the initial scope", as)
			}
		}

		// generate access token
		accessToken, err := s.TokenGenerator.Generate(0)
		if err != nil {
			values := url.Values{}
			values.Add("error", "server_error")
			values.Add("error_description", "internal error")
			values.Add("state", state)
			target := fmt.Sprintf("%s#%s", redirectURL, values.Encode())
			http.Redirect(w, r, target, http.StatusSeeOther)
			return fmt.Errorf("failed to generate access token: %s", err.Error())
		}

		// declare the token info
		token := storage.Token{
			ClientID:    clientID,
			AccessToken: accessToken,
			TokenType:   "Bearer",
			ExpiresIn:   uint64(s.Policies.AccessTokenLifetime.Seconds()),
			Scope:       acceptedScopes,
			State:       state,
		}

		// store the token info
		if err = s.Storage.TokenStorage.Set(token); err != nil {
			values := url.Values{}
			values.Add("error", "server_error")
			values.Add("error_description", "internal error")
			values.Add("state", state)
			target := fmt.Sprintf("%s#%s", redirectURL, values.Encode())
			http.Redirect(w, r, target, http.StatusSeeOther)
			return fmt.Errorf("failed to generate refesh token: %s", err.Error())
		}

		// redirect back with the response in the URL fragment
		values := url.Values{}
		values.Add("access_token", token.AccessToken)
		values.Add("token_type", token.TokenType)
		values.Add("expires_in", fmt.Sprintf("%d", token.ExpiresIn))
		values.Add("scope", token.Scope.String())
		values.Add("state", token.State)

		target := fmt.Sprintf("%s#%s", redirectURL, values.Encode())
		http.Redirect(w, r, target, http.StatusFound)
	}

	return nil
}

func isStringInSlice(sl []string, s string) bool {
	for _, e := range sl {
		if e == s {
			return true
		}
	}

	return false
}

/* Device Code */

// HandleDeviceCodeAuthorizationRequest handles the request to initiate the device code flow by returning the
// device code, the user code and a validation URL. This is step 1 of 3.
func (s *Server) HandleDeviceCodeAuthorizationRequest(w http.ResponseWriter, r *http.Request) error {
	defer r.Body.Close()
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

	// check if the client ID exists
	_, err = s.Storage.ClientStorage.Get(values.Get("client_id"))
	if err != nil {
		http.Error(w, "invalid client ID", http.StatusBadRequest)
		return fmt.Errorf("no such client with ID '%s' found: %s", values.Get("client_id"), err.Error())
	}

	userCode, err := s.UserCodeGenerator.Generate()
	if err != nil {
		http.Error(w, "failed to generate user code", http.StatusInternalServerError)
		return fmt.Errorf("failed to generate user code: %s", err.Error())
	}

	deviceCode, err := s.TokenGenerator.Generate(0)
	if err != nil {
		http.Error(w, "failed to generate device code", http.StatusInternalServerError)
		return fmt.Errorf("failed to generate device code: %s", err.Error())
	}

	req := storage.DeviceCodeRequest{
		ClientID: values.Get("client_id"),
		Response: storage.DeviceCodeResponse{
			DeviceCode:              deviceCode,
			UserCode:                userCode,
			VerificationURI:         s.PublicBaseURL + s.URLs.DeviceCode,
			VerificationURIComplete: s.PublicBaseURL + s.URLs.DeviceCode + "?user_code=" + userCode,
			ExpiresIn:               300, // user has 5 minutes to authorize
			Interval:                5,   // polling every 5 seconds is okay
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

// HandleDeviceCodeUserAuthorization displays a template that allows the user authorize or cancel the request.
// This is step 2 of 3.
func (s *Server) HandleDeviceCodeUserAuthorization(w http.ResponseWriter, r *http.Request) error {
	_, err := s.isLoggedIn(r)
	if err != nil {
		http.Redirect(w, r, fmt.Sprintf("%s?redirect_back=%s", s.URLs.Login, url.QueryEscape(s.URLs.DeviceCode)), http.StatusSeeOther)
		return nil
	}
	// user is certainly logged in from here on

	// TODO handle client_id from request

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

		accessToken, err := s.TokenGenerator.Generate(0)
		if err != nil {
			http.Error(w, "failed to generate access token", http.StatusInternalServerError)
			return fmt.Errorf("failed to generate user code: %s", err.Error())
		}

		deviceRequest.TokenResponse = storage.Token{
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

// HandleDeviceTokenRequest exchanges a device code for an access token. This is step 3 of 3.
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

// HandleUserLogin displays the login template on a GET request and handles the login process on
// a POST request. On success, HandleUserLogin sets a session cookie and saves the session, linked to
// the user.
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

		sessionID, err := s.TokenGenerator.Generate(0)
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
			Name:     s.Session.CookieName,
			Value:    session.ID,
			Expires:  time.Now().Add(30 * 24 * time.Hour),
			SameSite: http.SameSiteStrictMode,
			Secure:   s.Session.Secure,
		})

		//fmt.Fprintln(w, "Login successful!")

		// if a redirect is available, perform it
		if red := r.URL.Query().Get("redirect_back"); red != "" {
			unEsc, err := url.QueryUnescape(red)
			if err != nil {
				http.Error(w, "invalid redirect URI", http.StatusBadRequest)
				return fmt.Errorf("invalid redirect back URI '%s': %s", red, err.Error())
			}
			q := r.URL.Query()
			q.Del("redirect_back")
			redir := fmt.Sprintf("%s?%s", unEsc, q.Encode())
			//fmt.Fprintln(w, "redirecting to "+redir)
			http.Redirect(w, r, redir, http.StatusFound)
			return nil
		}

		return nil
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
	return fmt.Errorf("method '%s' not allowed", r.Method)
}

// HandleUserLogout reads the session cookie and removes the session linked to the user, effectively logging
// the user out.
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
