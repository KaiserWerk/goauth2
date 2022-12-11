package goauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/KaiserWerk/goauth2/types"
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
		_ = s.ErrorResponse(w, http.StatusMethodNotAllowed, InvalidRequest, "method not allowed")
		return fmt.Errorf("expected method '%s', got '%s'", http.MethodPost, r.Method)
	}

	if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "incorrect content type header")
		return fmt.Errorf("expected content type header to be 'application/x-www-form-urlencoded'. got '%s'", ct)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		_ = s.ErrorResponse(w, http.StatusBadRequest, ServerError, "error reading request body")
		return fmt.Errorf("failed to read request body: %w", err)
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "malformed request body")
		return fmt.Errorf("failed to parse request body: %w", err)
	}

	if !values.Has("grant_type") {
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "request parameter grant_type missing")
		return fmt.Errorf("missing request parameter '%s'", "grant_type")
	}

	if gt := values.Get("grant_type"); gt != "client_credentials" {
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "request parameter grant_type invalid")
		return fmt.Errorf("expected grant type '%s', got '%s'", "client_credentials", gt)
	}

	// check if clientID and clientSecret are in header or body
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = values.Get("client_id")
		clientSecret = values.Get("client_secret")
	}

	if clientID == "" || clientSecret == "" {
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "missing client credentials")
		return fmt.Errorf("missing client credentials")
	}

	client, err := s.Storage.ClientStorage.Get(clientID)
	if err != nil {
		_ = s.ErrorResponse(w, http.StatusNotFound, UnauthorizedClient, "client not found or unauthorized")
		return fmt.Errorf("failed to get client by ID '%s': %w", clientID, err)
	}

	if client.GetSecret() != clientSecret {
		_ = s.ErrorResponse(w, http.StatusNotFound, UnauthorizedClient, "incorrect client credentials")
		return fmt.Errorf("failed to confirm correct password for client by ID '%s'", clientID)
	}

	accessToken, err := s.TokenGenerator.Generate(s.Policies.AccessTokenLength)
	if err != nil {
		_ = s.ErrorResponse(w, http.StatusInternalServerError, ServerError, "internal error")
		return fmt.Errorf("failed to create access token: %w", err)
	}

	resp := storage.Token{
		AccessToken: accessToken,
		ExpiresIn:   uint64(s.Policies.AccessTokenLifetime.Seconds()),
		TokenType:   "Bearer",
	}

	if err = s.Storage.TokenStorage.Add(resp); err != nil {
		_ = s.ErrorResponse(w, http.StatusInternalServerError, ServerError, "internal error")
		return fmt.Errorf("failed to store token: %w", err)
	}

	if err = json.NewEncoder(w).Encode(resp); err != nil {
		_ = s.ErrorResponse(w, http.StatusInternalServerError, ServerError, "internal error")
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
		_ = s.ErrorResponse(w, http.StatusMethodNotAllowed, InvalidRequest, "method not allowed")
		return fmt.Errorf("expected method '%s', got '%s'", http.MethodPost, r.Method)
	}

	if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "incorrect content type header")
		return fmt.Errorf("expected content type header to be 'application/x-www-form-urlencoded'. got '%s'", ct)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "failed to read request body")
		return err
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "failed to parse request body")
		return err
	}

	grantType := values.Get("grant_type")
	if grantType != "password" {
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "parameter grant_type missing or invalid")
		return fmt.Errorf("parameter grant_type missing or invalid")
	}
	username := values.Get("username")
	password := values.Get("password")

	if username == "" || password == "" {
		_ = s.ErrorResponse(w, http.StatusUnauthorized, AccessDenied, "resource owner password credentials missing or invalid")
		return fmt.Errorf("resource owner password credentials missing or invalid")
	}

	// TODO rework
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		_ = s.ErrorResponse(w, http.StatusUnauthorized, UnauthorizedClient, "failed client authentication")
		return fmt.Errorf("failed client basic authentication")
	}

	client, err := s.Storage.ClientStorage.Get(clientID)
	if err != nil {
		_ = s.ErrorResponse(w, http.StatusUnauthorized, UnauthorizedClient, "failed client authentication")
		return fmt.Errorf("client with ID '%s' could not be found", clientID)
	}

	// only require client authentication from confidential clients
	if client.IsConfidential() {
		if client.GetSecret() != clientSecret {
			_ = s.ErrorResponse(w, http.StatusUnauthorized, UnauthorizedClient, "failed client authentication")
			return fmt.Errorf("client secret does not match")
		}
	}

	user, err := s.Storage.UserStorage.GetByUsername(username)
	if err != nil {
		_ = s.ErrorResponse(w, http.StatusBadRequest, AccessDenied, "failed resource owner authentication")
		return fmt.Errorf("failed to find user with username '%s': %s", username, err.Error())
	}

	if !user.DoesPasswordMatch(password) {
		_ = s.ErrorResponse(w, http.StatusBadRequest, AccessDenied, "failed resource owner authentication")
		return fmt.Errorf("incorrect password for user '%s'", username)
	}

	accessToken, err := s.TokenGenerator.Generate(0)
	if err != nil {
		_ = s.ErrorResponse(w, http.StatusBadRequest, AccessDenied, "failed resource owner authentication")
		return fmt.Errorf("failed to generate access token: %s", err.Error())
	}

	t := storage.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   uint64(s.Policies.AccessTokenLifetime.Seconds()),
	}

	if err = s.Storage.TokenStorage.Add(t); err != nil {
		_ = s.ErrorResponse(w, http.StatusInternalServerError, ServerError, "internal error")
		return fmt.Errorf("failed to store token: %s", err.Error())
	}

	if err = json.NewEncoder(w).Encode(t); err != nil {
		_ = s.ErrorResponse(w, http.StatusInternalServerError, ServerError, "internal error")
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
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "missing required request parameter client_id")
		return fmt.Errorf("missing URL parameter 'client_id'")
	}

	// check if a client with this ID exists and if so, fetch it
	client, err := s.Storage.ClientStorage.Get(clientID)
	if err != nil {
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "invalid client_id")
		return fmt.Errorf("the client ID '%s' was not found: %s", clientID, err.Error())
	}

	// check if a redirect URL is set and valid
	redirectURIRaw := r.URL.Query().Get("redirect_uri")
	redirectURL, err2 := url.QueryUnescape(redirectURIRaw)
	_, err3 := url.ParseRequestURI(redirectURL)
	if redirectURIRaw == "" || err2 != nil || err3 != nil {
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "missing or invalid parameter redirect_uri")
		return fmt.Errorf("failed to parse 'redirect_uri' parameter as URL: missing: %t / err: %v / err %v", redirectURIRaw == "", err2, err3)
	}

	// check if the redirect URL is in the client's list of registered redirect URLs
	if !client.HasRedirectURL(redirectURL) {
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
			ApplicationName: client.GetApplicationName(),
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
			Scope:       &acceptedScopes,
			State:       state,
		}

		// store the token info
		if err = s.Storage.TokenStorage.Add(token); err != nil {
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

		deviceRequest.SetTokenResponse(storage.Token{
			AccessToken: accessToken,
			TokenType:   "Bearer",
			ExpiresIn:   86400,
		})

		if err := s.Storage.DeviceCodeRequestStorage.Update(deviceRequest); err != nil {
			http.Error(w, "failed to update device code request", http.StatusNotFound)
			return fmt.Errorf("failed to update device code request: %s", err.Error())
		}

		http.Error(w, "success. you can close this window.", http.StatusOK)
		return nil
	}

	return nil
}

// HandleDeviceCodeTokenRequest exchanges a device code for an access token. This is step 3 of 3.
func (s *Server) HandleDeviceCodeTokenRequest(w http.ResponseWriter, r *http.Request) error {
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

	if deviceRequest.GetTokenResponse().AccessToken == "" {
		http.Error(w, `{"error": "authorization_pending"}`, http.StatusOK)
	} else {
		if err := json.NewEncoder(w).Encode(deviceRequest.GetTokenResponse()); err != nil {
			http.Error(w, "failed to serialize JSON", http.StatusBadRequest)
			return fmt.Errorf("failed to serialize JSON: %s", err.Error())
		}
	}

	return nil
}

/* Authorization Code Grant */

// HandleAuthorizationCodeAuthorizationRequest handles the initial user authorization of scopes and returns a code. This is step 1 of 2.
func (s *Server) HandleAuthorizationCodeAuthorizationRequest(w http.ResponseWriter, r *http.Request) error {
	_, err := s.isLoggedIn(r)
	if err != nil {
		http.Redirect(w, r, fmt.Sprintf("%s?%s&redirect_back=%s", s.URLs.Login, r.URL.RawQuery, url.QueryEscape(s.URLs.AuthorizationCode)), http.StatusSeeOther)
		return nil
	}

	var (
		codeChallenge       = ""
		codeChallengeMethod = ""
	)

	// check query parameter
	responseType := r.URL.Query().Get("response_type")
	if responseType != "code" {
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "parameter response_type missing or invalid")
		return fmt.Errorf("parameter response_type missing or invalid")
	}

	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "parameter client_id missing")
		return fmt.Errorf("parameter client_id missing")
	}

	client, err := s.Storage.ClientStorage.Get(clientID)
	if err != nil {
		_ = s.ErrorResponse(w, http.StatusUnauthorized, UnauthorizedClient, "parameter client_id invalid")
		return fmt.Errorf("parameter client_id invalid")
	}

	redirectURLRaw := r.URL.Query().Get("redirect_uri")
	if redirectURLRaw != "" {
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "parameter redirect_uri missing")
		return fmt.Errorf("parameter redirect_uri missing")
	}

	redirectURL, err := url.QueryUnescape(redirectURLRaw)
	if err != nil {
		s.ErrorRedirect(w, r, redirectURL, InvalidRequest, "parameter redirect_uri has invalid value", "")
		return fmt.Errorf("parameter redirect_uri has invalid value")
	}

	_, err = url.ParseRequestURI(redirectURL)
	if err != nil {
		s.ErrorRedirect(w, r, redirectURL, InvalidRequest, "parameter redirect_uri has invalid value", "")
		return fmt.Errorf("parameter redirect_uri has invalid value")
	}

	state := r.URL.Query().Get("state")
	if state == "" {
		s.ErrorRedirect(w, r, redirectURL, InvalidRequest, "parameter state missing", state)
		return fmt.Errorf("parameter state missing")
	}

	scopeRaw := r.URL.Query().Get("scope")
	if scopeRaw == "" {
		s.ErrorRedirect(w, r, redirectURL, InvalidRequest, "parameter scope missing", state)
		return fmt.Errorf("parameter scope missing")
	}

	scope, err := url.QueryUnescape(scopeRaw)
	if err != nil {
		s.ErrorRedirect(w, r, redirectURL, InvalidRequest, "parameter scope has invalid value", state)
		return fmt.Errorf("parameter scope has invalid value")
	}
	scopes := strings.Split(scope, " ")

	if s.Flags.PKCE {
		codeChallenge = r.URL.Query().Get("code_challenge")
		if codeChallenge == "" {
			s.ErrorRedirect(w, r, redirectURL, InvalidRequest, "parameter code_challenge missing", state)
			return fmt.Errorf("parameter code_challenge missing")
		}

		codeChallengeMethod = r.URL.Query().Get("code_challenge_method")
		if codeChallenge == "" {
			s.ErrorRedirect(w, r, redirectURL, InvalidRequest, "parameter code_challenge_method missing", state)
			return fmt.Errorf("parameter code_challenge_method missing")
		}

		if codeChallengeMethod != "plain" && codeChallengeMethod != "S256" {
			s.ErrorRedirect(w, r, redirectURL, InvalidRequest, "parameter code_challenge_method invalid", state)
			return fmt.Errorf("parameter code_challenge_method invalid")
		}
	}

	if r.Method == http.MethodGet {
		data := struct {
			Scopes          []string
			CancelURL       string
			Message         string
			ApplicationName string
		}{
			Scopes:          scopes,
			CancelURL:       fmt.Sprintf("%s?error=canceled", redirectURL),
			ApplicationName: client.GetApplicationName(),
		}
		if err = executeTemplate(w, s.Template.AuthorizationCode, data); err != nil {
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

		ac, err := s.TokenGenerator.Generate(0)
		if err != nil {
			s.ErrorRedirect(w, r, redirectURL, ServerError, "internal error", state)
			return fmt.Errorf("failed to generate authorization code: %w", err)
		}

		authCodeReq := storage.AuthorizationCodeRequest{
			ClientID: clientID,
			Code:     ac,
			Scope:    &acceptedScopes,
		}

		if s.Flags.PKCE {
			if codeChallenge == "" {
				s.ErrorRedirect(w, r, redirectURL, InvalidRequest, "parameter code_challenge missing", state)
				return fmt.Errorf("parameter code_challenge missing")
			}
			authCodeReq.CodeChallenge = codeChallenge
			authCodeReq.CodeChallengeMethod = codeChallengeMethod
		}

		if err = s.Storage.AuthorizationCodeRequestStorage.Insert(authCodeReq); err != nil {
			s.ErrorRedirect(w, r, redirectURL, ServerError, "internal error", state)
			return fmt.Errorf("failed to insert authorization code request: %w", err)
		}

		values := url.Values{}
		values.Add("state", state)
		values.Add("code", ac)

		target := fmt.Sprintf("%s?%s", redirectURL, values.Encode())
		http.Redirect(w, r, target, http.StatusOK)
		return nil
	}

	http.Error(w, "method not allowed", http.StatusNotAcceptable)
	return fmt.Errorf("method '%s' not allowed", r.Method)
}

// HandleAuthorizationCodeTokenRequest exchanges a code for an access token. This is step 2 of 2.
func (s *Server) HandleAuthorizationCodeTokenRequest(w http.ResponseWriter, r *http.Request) error {
	defer r.Body.Close()
	if r.Method != http.MethodPost {
		_ = s.ErrorResponse(w, http.StatusMethodNotAllowed, InvalidRequest, "method not allowed")
		return fmt.Errorf("method '%s' not allowed", r.Method)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "invalid request body")
		return fmt.Errorf("could not read request body: %w", err)
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "invalid request body")
		return fmt.Errorf("could not parse request body: %w", err)
	}

	grantType := values.Get("grant_type")
	if grantType != "authorization_code" {
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "parameter grant_type missing or invalid")
		return fmt.Errorf("parameter grant_type missing or invalid")
	}

	code := values.Get("code")
	if code == "" {
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "parameter code missing")
		return fmt.Errorf("parameter code missing")
	}

	clientID := values.Get("client_id")
	var clientSecret string
	var ok bool
	if clientID == "" {
		clientID, clientSecret, ok = r.BasicAuth()
		if !ok {
			_ = s.ErrorResponse(w, http.StatusBadRequest, UnauthorizedClient, "client_id or authentication missing")
			return fmt.Errorf("client_id or authentication missing")
		}
	}

	client, err := s.Storage.ClientStorage.Get(clientID)
	if err != nil {
		_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "client_id missing")
		return fmt.Errorf("client_id missing")
	}

	if client.GetSecret() != clientSecret {
		_ = s.ErrorResponse(w, http.StatusBadRequest, UnauthorizedClient, "client authentication failed")
		return fmt.Errorf("client secret not matching")
	}

	at, err := s.TokenGenerator.Generate(0)
	if err != nil {
		_ = s.ErrorResponse(w, http.StatusInternalServerError, ServerError, "internal error")
		return fmt.Errorf("failed to generate access token: %w", err)
	}

	rt, err := s.TokenGenerator.Generate(80)
	if err != nil {
		_ = s.ErrorResponse(w, http.StatusInternalServerError, ServerError, "internal error")
		return fmt.Errorf("failed to generate refresh token: %w", err)
	}

	authCodeReq, err := s.Storage.AuthorizationCodeRequestStorage.Pop(code)
	if err != nil {
		_ = s.ErrorResponse(w, http.StatusNotFound, InvalidRequest, "unknown code")
		return fmt.Errorf("no request entry found for code: %w", err)
	}

	if s.Flags.PKCE {
		codeVerifier := values.Get("code_verifier")
		if codeVerifier == "" {
			_ = s.ErrorResponse(w, http.StatusBadRequest, InvalidRequest, "parameter code_verifier missing")
			return fmt.Errorf("parameter code_verifier missing")
		}

		confirmed := false
		if authCodeReq.GetCodeChallengeMethod() == "plain" {
			confirmed = authCodeReq.GetCodeChallenge() == codeVerifier
		} else if authCodeReq.GetCodeChallengeMethod() == "S256" {
			h := sha256.New()
			h.Write([]byte(codeVerifier))
			confirmed = authCodeReq.GetCodeChallenge() == base64.URLEncoding.EncodeToString(h.Sum(nil))
		}

		if !confirmed {
			_ = s.ErrorResponse(w, http.StatusUnauthorized, InvalidRequest, "failed to verify code challenge")
			return fmt.Errorf("failed to verify code challenge")
		}
	}

	token := storage.Token{
		ClientID:     clientID,
		AccessToken:  at,
		TokenType:    "Bearer",
		ExpiresIn:    uint64(s.Policies.AccessTokenLifetime.Seconds()),
		RefreshToken: rt,
		Scope:        authCodeReq.GetScope(),
	}

	if err = s.Storage.TokenStorage.Add(token); err != nil {
		_ = s.ErrorResponse(w, http.StatusInternalServerError, InvalidRequest, "internal error")
		return fmt.Errorf("failed to store token")
	}

	if err = json.NewEncoder(w).Encode(token); err != nil {
		http.Error(w, "failed to write JSON response", http.StatusInternalServerError)
		return fmt.Errorf("failed to write JSON response")
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
	if err == nil && user.GetUsername() != "" {
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

		if !u.DoesPasswordMatch(password) {
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
			UserID:  u.GetID(),
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

func (s *Server) HandleTokenIntrospectionRequest(w http.ResponseWriter, r *http.Request) error {
	defer r.Body.Close()
	var resp types.IntrospectionResponse
	if r.Method != http.MethodPost {
		_ = writeIntrospectionResponse(w, resp, http.StatusBadRequest)
		return fmt.Errorf("method %s not allowed", r.Method)
	}

	if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		_ = writeIntrospectionResponse(w, resp, http.StatusBadRequest)
		return fmt.Errorf("expected content type header to be 'application/x-www-form-urlencoded'. got '%s'", ct)
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		resp.Error = "invalid_client"
		resp.Error = "The client authentication was invalid"
		_ = writeIntrospectionResponse(w, resp, http.StatusUnauthorized)
		return fmt.Errorf("failed basic auth")
	}

	client, err := s.Storage.ClientStorage.Get(clientID)
	if err != nil {
		_ = writeIntrospectionResponse(w, resp, http.StatusBadRequest)
		return fmt.Errorf("error getting client: %w", err)
	}

	if client.GetID() != clientID || client.GetSecret() != clientSecret {
		_ = writeIntrospectionResponse(w, resp, http.StatusBadRequest)
		return fmt.Errorf("error authenticating client: %w", err)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		_ = writeIntrospectionResponse(w, resp, http.StatusBadRequest)
		return fmt.Errorf("failed to read request body: %s", err.Error())
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		_ = writeIntrospectionResponse(w, resp, http.StatusBadRequest)
		return fmt.Errorf("failed to parse request body: %s", err.Error())
	}

	if !values.Has("token") {
		_ = writeIntrospectionResponse(w, resp, http.StatusBadRequest)
		return fmt.Errorf("missing request parameter '%s'", "token")
	}

	accessToken := values.Get("token")
	token, err := s.Storage.TokenStorage.FindByAccessToken(accessToken)
	if err != nil {
		_ = writeIntrospectionResponse(w, resp, http.StatusBadRequest)
		return fmt.Errorf("failed to find token by access token: %w", err)
	}

	if token.IsValid() {
		resp.Active = true
		resp.ClientID = clientID
		resp.Scope = token.GetScope()
		resp.Expires = uint64(token.GetGeneratedAt().Add(time.Duration(token.GetExpiresIn()) * time.Second).Unix())
	}

	_ = writeIntrospectionResponse(w, resp, http.StatusOK)
	return nil
}

func writeIntrospectionResponse(w http.ResponseWriter, resp types.IntrospectionResponse, statusCode int) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	data, err := json.MarshalIndent(resp, "", "\t")
	if err != nil {
		return err
	}
	http.Error(w, string(data), statusCode)
	return nil
}

/* helpers */
func (s *Server) isLoggedIn(r *http.Request) (storage.OAuth2User, error) {
	sid, err := s.getSessionID(r)
	if err != nil || sid == "" {
		return storage.User{}, fmt.Errorf("user is not logged in")
	}

	session, err := s.Storage.SessionStorage.Get(sid)
	if err != nil {
		return storage.User{}, fmt.Errorf("user had session ID, but was not found")
	}

	user, err := s.Storage.UserStorage.Get(session.GetUserID())
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

func isStringInSlice(sl []string, s string) bool {
	for _, e := range sl {
		if e == s {
			return true
		}
	}

	return false
}
