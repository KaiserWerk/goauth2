package storage

import "time"

// A Token is a ready-to-use implementation of the OAuth2Token interface.
type Token struct {
	ClientID          string    `json:"-"`
	AccessToken       string    `json:"access_token"`
	TokenType         string    `json:"token_type"`
	ExpiresIn         uint64    `json:"expires_in"`
	RefreshToken      string    `json:"refresh_token,omitempty"`
	State             string    `json:"state,omitempty"`
	CodeChallenge     string    `json:"code_challenge,omitempty"`
	AuthorizationCode string    `json:"authorization_code,omitempty"`
	Scope             *Scope    `json:"scope,omitempty"`
	GeneratedAt       time.Time `json:"-"`
}

func (t Token) GetClientID() string {
	return t.ClientID
}

func (t Token) SetClientID(id string) {
	t.ClientID = id
}

func (t Token) GetAccessToken() string {
	return t.AccessToken
}

func (t Token) SetAccessToken(at string) {
	t.AccessToken = at
}

func (t Token) GetTokenType() string {
	return t.TokenType
}

func (t Token) SetTokenType(tt string) {
	t.TokenType = tt
}

func (t Token) GetExpiresIn() uint64 {
	return t.ExpiresIn
}

func (t Token) SetExpiresIn(ex uint64) {
	t.ExpiresIn = ex
}

func (t Token) GetRefreshToken() string {
	return t.RefreshToken
}

func (t Token) SetRefreshToken(rt string) {
	t.RefreshToken = rt
}

func (t Token) GetScope() *Scope {
	return t.Scope
}

func (t Token) SetScope(scope *Scope) {
	t.Scope = scope
}

func (t Token) SetRawScope(raw string) {

}

func (t Token) GetState() string {
	return t.State
}

func (t Token) SetState(s string) {
	t.State = s
}

func (t Token) GetCodeChallenge() string {
	return t.CodeChallenge
}

func (t Token) SetCodeChallenge(cc string) {
	t.CodeChallenge = cc
}

func (t Token) GetAuthorizationCode() string {
	return t.AuthorizationCode
}

func (t Token) SetAuthorizationCode(ac string) {
	t.AuthorizationCode = ac
}

func (t Token) GetGeneratedAt() time.Time {
	return t.GeneratedAt
}

func (t Token) SetGeneratedAt(ga time.Time) {
	t.GeneratedAt = ga
}

func (t Token) IsValid() bool {
	return t.GetAccessToken() != "" && !t.IsExpired()
}

func (t Token) IsExpired() bool {
	return t.GetGeneratedAt().Add(time.Duration(t.GetExpiresIn()) * time.Second).After(time.Now())
}
