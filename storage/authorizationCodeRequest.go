package storage

type AuthorizationCodeRequest struct {
	ClientID            string
	Code                string
	Scope               *Scope
	CodeChallenge       string
	CodeChallengeMethod string
}

func (a AuthorizationCodeRequest) GetClientID() string {
	return a.ClientID
}

func (a AuthorizationCodeRequest) SetClientID(id string) {
	a.ClientID = id
}

func (a AuthorizationCodeRequest) GetCode() string {
	return a.Code
}

func (a AuthorizationCodeRequest) SetCode(code string) {
	a.Code = code
}

func (a AuthorizationCodeRequest) GetScope() *Scope {
	return a.Scope
}

func (a AuthorizationCodeRequest) SetScope(scope *Scope) {
	a.Scope = scope
}

func (a AuthorizationCodeRequest) GetCodeChallenge() string {
	return a.CodeChallenge
}

func (a AuthorizationCodeRequest) SetCodeChallenge(challenge string) {
	a.CodeChallenge = challenge
}

func (a AuthorizationCodeRequest) GetCodeChallengeMethod() string {
	return a.CodeChallengeMethod
}

func (a AuthorizationCodeRequest) SetCodeChallengeMethod(method string) {
	a.CodeChallengeMethod = method
}
