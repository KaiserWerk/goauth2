package storage

import "time"

type Token struct {
	ClientID      string
	Token         string
	Expiry        time.Time
	RefreshToken  string
	RefreshExpiry time.Time
}

// A TokenStorage takes care of storing a supplied token associated with the given client ID.
// A token must be unique.
type TokenStorage interface {
	Get(ts string) (Token, error)
	Set(t Token) error
}
