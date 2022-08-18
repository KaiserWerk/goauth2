package goauth

import "time"

type Session struct {
	ID      string
	UserID  uint
	Expires time.Time
}

type SessionStorage interface {
	Get(string) (Session, error)
	Add(Session) error
	Remove(string) error
}
