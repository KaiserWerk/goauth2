package goauth

import (
	"github.com/KaiserWerk/goauth2/usercode"
	"sync"
	"time"

	"github.com/KaiserWerk/goauth2/assets"

	"github.com/KaiserWerk/goauth2/storage"
	"github.com/KaiserWerk/goauth2/token"
	"github.com/KaiserWerk/goauth2/types"
)

type (
	// Storage contains the storage implementations required for operations.
	Storage struct {
		DeviceCodeRequestStorage storage.DeviceCodeStorage
		SessionStorage           storage.SessionStorage
		UserStorage              storage.UserStorage
		ClientStorage            storage.ClientStorage
		TokenStorage             storage.TokenStorage
	}
	// Templates contains the templates displayed for the user
	Templates struct {
		Login             []byte
		AuthorizationCode []byte
		ImplicitGrant     []byte
		DeviceCode        []byte
	}
	// Flags contains feature flags for the authorization code grant to enable/disable particular features.
	Flags struct {
		// PKCE = Proof Key for Code Exchange
		PKCE bool
		// OIDC = OpenID Connect
		OIDC bool
	}
	// Policies represents constraints and requirements for proper operation.
	Policies struct {
		DeviceCodeLength   int
		UserCodeLength     int
		AccessTokenLength  int
		RefreshTokenLength int
		ClientSecretLength int
		// IDTokenLength only relates to OpenID Connect
		IDTokenLength int

		SessionLifetime      time.Duration
		AccessTokenLifetime  time.Duration
		RefreshTokenLifetime time.Duration
	}
	// Session contains session and cookie settings
	Session struct {
		CookieName string
		HTTPOnly   bool
		Secure     bool
	}
	// URLs contains paths and/or URLs to the endpoints/routes defined by the caller.
	URLs struct {
		Login             string
		Logout            string
		DeviceCode        string
		AuthorizationCode string
		Implicit          string
	}
	// A Server handles all HTTP requests relevant to the OAuth2 authorization processes. A Server must not be modified
	// after first use.
	Server struct {
		// PublicBaseURL is the public facing URL containing scheme, hostname and port, if required.
		// it is used to construct redirect URLs.
		PublicBaseURL string
		// Storage contains the necessary storage implementations.
		Storage Storage
		// Template contains HTML templates as byte slices used for displaying to the user, e.g. login form.
		Template Templates
		// Flags are feature flags meant to enable certain features.
		Flags Flags
		// Policies can restrict how certain values have to be restricted, e.g. the length of certain strings or the
		// validitdy durations.
		Policies Policies
		// Session contains session and cookie configuration values.
		Session Session
		// URLs contain paths and URLs for internal redirects.
		URLs URLs
		// TokenGenerator is a source used to generate tokens.
		TokenGenerator    token.TokenGenerator
		UserCodeGenerator usercode.Generator

		grantTypes []types.GrantType
		m          *sync.RWMutex
	}
)

// NewDefaultServer returns a *Server with set default values:
//
//  • PublicBaseURL: is set to 'http://localhost' without a port. It is required for redirect-based authorization flows.
//
//  • Storage: each store uses a corresponding in-memory implementation, e.g. MemoryClientStorage.
//
//  • Templates: the default templates from this library are used. They are not overly pretty, but they get their job done.
//
//  • Flags: all flags remain at their default value.
//
//  • Policies: sensible lengths and lifetime which ensure a certain degree of security.
//
//  • TokenGenerator: uses a ready-to-use in-memory implementation, namely DefaultTokenGenerator.
//
//  • grantTypes: all implemented grant types are listed here.
//
// You should probably alter the PublicBaseURL and add at least one Client and one User.
func NewDefaultServer() *Server {
	return &Server{
		PublicBaseURL: "http://localhost",
		Storage: Storage{
			DeviceCodeRequestStorage: storage.NewMemoryDeviceCodeRequestStorage(),
			SessionStorage:           storage.NewMemorySessionStorage(),
			UserStorage:              storage.NewMemoryUserStorage(),
			ClientStorage:            storage.NewMemoryClientStorage(),
			TokenStorage:             storage.NewMemoryTokenStorage(),
		},
		Template: Templates{
			Login:             assets.LoginPageTemplate,
			AuthorizationCode: assets.AuthorizationCodeTemplate,
			ImplicitGrant:     assets.ImplicitFlowTemplate,
			DeviceCode:        assets.DeviceCodeTemplate,
		},
		Flags: Flags{},
		Policies: Policies{
			DeviceCodeLength:     70,
			UserCodeLength:       6,
			AccessTokenLength:    120,
			RefreshTokenLength:   80,
			ClientSecretLength:   75,
			IDTokenLength:        255,
			SessionLifetime:      30 * 24 * time.Hour,
			AccessTokenLifetime:  1 * time.Hour,
			RefreshTokenLifetime: 24 * time.Hour,
		},
		Session: Session{
			CookieName: "GOAUTH_SID",
			HTTPOnly:   true,
			Secure:     false,
		},
		URLs: URLs{
			Login:             "/user_login",
			Logout:            "/user_logout",
			DeviceCode:        "/device",
			AuthorizationCode: "/authorize",
			Implicit:          "/implicit",
		},
		TokenGenerator:    token.DefaultTokenGenerator,
		UserCodeGenerator: usercode.DefaultUCGenerator,
		grantTypes: []types.GrantType{
			types.AuthorizationCode,
			types.DeviceCode,
			types.Implicit,
			types.ClientCredentials,
			types.ResourceOwnerPasswordCredentials,
		},

		m: new(sync.RWMutex),
	}
}

// NewEmptyServer returns a *Server with just the base setup.
func NewEmptyServer() *Server {
	return &Server{
		grantTypes: make([]types.GrantType, 0, 5),
		m:          new(sync.RWMutex),
	}
}

// AddGrantType adds the given grant type to the current list of enabled grant types for the server s.
// A grant type not listed might not be available, depending on the caller's usage.
// You can use this call to change the availability of a given grant type while the Server is in use.
func (s *Server) AddGrantType(gt types.GrantType) {
	s.m.Lock()
	defer s.m.Unlock()
	for _, t := range s.grantTypes {
		if gt == t {
			return
		}
	}
	s.grantTypes = append(s.grantTypes, gt)
}

// RemoveGrantType removes the given grant type from the current list of enabled grant types for the server s.
// You can use this call to change the availability of a given grant type while the Server is in use.
func (s *Server) RemoveGrantType(gt types.GrantType) {
	s.m.Lock()
	defer s.m.Unlock()
	for i, t := range s.grantTypes {
		if gt == t {
			s.grantTypes[i] = s.grantTypes[len(s.grantTypes)-1]
			s.grantTypes = s.grantTypes[:len(s.grantTypes)-1]
		}
	}
}

// ResetGrantTypes empties the internal list of enabled grant types.
func (s *Server) ResetGrantTypes() {
	s.m.Lock()
	s.grantTypes = make([]types.GrantType, 0, 5)
	s.m.Unlock()
}

func (s *Server) HasGrantType(gt types.GrantType) bool {
	s.m.RLock()
	defer s.m.RUnlock()
	for _, t := range s.grantTypes {
		if gt == t {
			return true
		}
	}

	return false
}

// HandleAuthorizationCodeRequest previously did something.
//
// Deprecated: do not use it now
//func (s *Server) HandleAuthorizationCodeRequest(w http.ResponseWriter, r *http.Request) error {
//	// if the user is not logged in
//	// redirect to login page with redirect back url
//
//	q := r.URL.Query()
//	responseType := q.Get("response_type")
//	grantType := q.Get("authorization_code")
//	clientID := q.Get("client_id")
//	redirectURI := q.Get("redirect_uri")
//	scope := q.Get("scope")
//	state := q.Get("state")
//	fmt.Println("response type:", responseType)
//	fmt.Println("grant type:", grantType)
//	fmt.Println("client id:", clientID)
//	fmt.Println("redirect uri:", redirectURI)
//	fmt.Println("scope:", scope)
//	fmt.Println("state:", state)
//	switch {
//	case responseType == "code":
//		if r.Method == http.MethodGet {
//			// write authorize template
//		} else if r.Method == http.MethodPost {
//			username := r.FormValue("_username")
//			password := r.FormValue("_password")
//			u, err := s.UserStorage.GetByUsername(username)
//			if err != nil {
//				http.Error(w, "failed to find user", http.StatusNotFound)
//				return err
//			}
//
//			if u.Password != password {
//
//			}
//		}
//	}
//
//	http.Error(w, "failed", http.StatusInternalServerError)
//
//	return errors.New("undefined grant type")
//}
