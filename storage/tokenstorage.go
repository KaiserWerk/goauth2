package storage

import (
	"fmt"
	"net/url"
	"strings"
)

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

type Scope []string

func (s Scope) MarshalJSON() ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("scope is nil")
	}
	return []byte(url.QueryEscape(strings.Join(s, " "))), nil
}

func (s Scope) UnmarshalJSON(d []byte) error {
	if s == nil {
		return fmt.Errorf("scope is nil")
	}
	unEscaped, err := url.QueryUnescape(string(d))
	if err != nil {
		return err
	}

	s = append(s, strings.Split(unEscaped, " ")...)
	return nil
}

func (s Scope) String() string {
	return url.QueryEscape(strings.Join(s, " "))
}

// A TokenStorage takes care of storing a supplied token associated with the given client ID.
// A token must be unique.
type TokenStorage interface {
	Get(string) (Token, error)
	Set(Token) error
}
