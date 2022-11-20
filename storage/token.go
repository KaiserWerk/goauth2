package storage

// A Token is a ready-to-use implementation of the OAuth2Token interface.
type Token struct {
	ClientID          string `json:"-"`
	AccessToken       string `json:"access_token"`
	TokenType         string `json:"token_type"`
	ExpiresIn         uint64 `json:"expires_in"`
	RefreshToken      string `json:"refresh_token,omitempty"`
	Scope             Scope  `json:"scope,omitempty"`
	State             string `json:"state,omitempty"`
	CodeChallenge     string `json:"code_challenge,omitempty"`
	AuthorizationCode string `json:"authorization_code,omitempty"`
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
	//TODO implement me
	panic("implement me")
}

func (t Token) GetTokenType() string {
	//TODO implement me
	panic("implement me")
}

func (t Token) SetTokenType(tt string) {
	//TODO implement me
	panic("implement me")
}

func (t Token) GetExpiresIn() uint64 {
	//TODO implement me
	panic("implement me")
}

func (t Token) SetExpiresIn(ex uint64) {
	//TODO implement me
	panic("implement me")
}

func (t Token) GetRefreshToken() string {
	//TODO implement me
	panic("implement me")
}

func (t Token) SetRefreshToken(rt string) {
	//TODO implement me
	panic("implement me")
}

func (t Token) GetScope() *Scope {
	//TODO implement me
	panic("implement me")
}

func (t Token) SetScope(scope *Scope) {
	//TODO implement me
	panic("implement me")
}

func (t Token) SetRawScope(raw string) {
	//TODO implement me
	panic("implement me")
}

func (t Token) GetState() string {
	//TODO implement me
	panic("implement me")
}

func (t Token) SetState(s string) {
	//TODO implement me
	panic("implement me")
}

func (t Token) GetCodeChallenge() string {
	//TODO implement me
	panic("implement me")
}

func (t Token) SetCodeChallenge(cc string) {
	//TODO implement me
	panic("implement me")
}

func (t Token) GetAuthorizationCode() string {
	//TODO implement me
	panic("implement me")
}

func (t Token) SetAuthorizationCode(ac string) {
	//TODO implement me
	panic("implement me")
}
