package storage

type AuthorizationCodeRequest struct {
	ClientID            string
	Code                string
	Scope               Scope
	CodeChallenge       string
	CodeChallengeMethod string
}

type AuthorizationCodeRequestStorage interface {
	Pop(string) (AuthorizationCodeRequest, error)
	Insert(AuthorizationCodeRequest) error
}
