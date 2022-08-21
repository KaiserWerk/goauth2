package storage

type Token struct {
	ClientID     string   `json:"-"`
	AccessToken  string   `json:"access_token"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    uint64   `json:"expires_in"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	Scope        []string `json:"scope,omitempty"`
	State        string   `json:"state,omitempty"`
}

// A TokenStorage takes care of storing a supplied token associated with the given client ID.
// A token must be unique.
type TokenStorage interface {
	Get(string) (Token, error)
	Set(Token) error
}
