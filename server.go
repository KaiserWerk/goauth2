package goauth

import (
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
	// Flags contains feature flages to enable/disable particular features.
	Flags struct {
		// PKCE is not currently implemented
		PKCE bool
		// OIDC (= OpenID Connect) is not currently implemented
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
	Session struct {
		CookieName string
		HTTPOnly   bool
	}
	URLs struct {
		Login                       string
		Logout                      string
		DeviceCodeUserAuthorization string
	}
	// A Server handles all HTTP requests relevant to the OAuth2 authorization processes. A Server must not be modified
	// after first use.
	Server struct {
		PublicBaseURL string
		Storage       Storage
		Template      Templates
		Flags         Flags
		Policies      Policies
		Session       Session
		URLs          URLs
		TokenSource   token.TokenSource
		GrantTypes    []types.GrantType
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
//  • TokenSource: uses a ready-to-use in-memory implementation, namely DefaultTokenSource.
//
//  • GrantTypes: all implemented grant types are listed here.
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
		},
		URLs: URLs{
			Login:                       "/user_login",
			Logout:                      "/user_logout",
			DeviceCodeUserAuthorization: "/device",
		},
		TokenSource: token.DefaultTokenSource,
		GrantTypes:  []types.GrantType{types.DeviceCode, types.AuthorizationCode},
	}
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
