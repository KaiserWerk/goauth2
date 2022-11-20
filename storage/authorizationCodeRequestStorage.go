package storage

type (
	OAuth2AuthorizationCodeRequest interface {
		GetClientID() string
		SetClientID(string)
		GetCode() string
		SetCode(string)
		GetScope() *Scope
		SetScope(*Scope)
		GetCodeChallenge() string
		SetCodeChallenge(string)
		GetCodeChallengeMethod() string
		SetCodeChallengeMethod(string)
	}
	// AuthorizationCodeRequestStorage stores Authorization code requests.
	// For in-memory implementations, Close() should be a no-op.
	AuthorizationCodeRequestStorage interface {
		Pop(string) (OAuth2AuthorizationCodeRequest, error)
		Insert(OAuth2AuthorizationCodeRequest) error
		Close() error
	}
)
