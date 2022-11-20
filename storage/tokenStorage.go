package storage

type (
	// An OAuth2Token represents the (meta)data related to a successfully executed authorization process.
	// You can use your own implementation or the existing Token{}.
	OAuth2Token interface {
		GetClientID() string
		SetClientID(string)
		GetAccessToken() string
		SetAccessToken(string)
		GetTokenType() string
		SetTokenType(string)
		GetExpiresIn() uint64
		SetExpiresIn(uint64)
		GetRefreshToken() string
		SetRefreshToken(string)
		GetScope() *Scope
		SetScope(*Scope)
		SetRawScope(s string)
		GetState() string
		SetState(string)
		GetCodeChallenge() string
		SetCodeChallenge(string)
		GetAuthorizationCode() string
		SetAuthorizationCode(string)
	}

	// A TokenStorage takes care of storing a supplied token associated with the given client ID.
	// A token must be unique.
	TokenStorage interface {
		FindByCodeChallenge(string) (OAuth2Token, error)
		FindByAccessToken(string) (OAuth2Token, error)
		Set(OAuth2Token) error
	}
)
