package storage

import "time"

type OAuth2Session interface {
	GetID() string
	SetID(string)
	GetUserID() uint
	SetUserID(uint)
	GetExpires() time.Time
	SetExpires(t time.Time)
}

// A SessionStorage stores sessions and related meta information.
// For in-memory implementations, Close() should be a no-op.
type SessionStorage interface {
	Get(string) (OAuth2Session, error)
	Add(OAuth2Session) error
	Remove(string) error
	Close() error
}
