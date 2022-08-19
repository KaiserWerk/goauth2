package types

type TokenResponse struct {
	AccessToken string
	Expires     uint64
	Scopes      []string
	State       string
}
