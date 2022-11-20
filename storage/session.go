package storage

import "time"

type Session struct {
	ID      string
	UserID  uint
	Expires time.Time
}

func (s Session) GetID() string {
	return s.ID
}

func (s Session) SetID(id string) {
	s.ID = id
}

func (s Session) GetUserID() uint {
	return s.UserID
}

func (s Session) SetUserID(id uint) {
	s.UserID = id
}

func (s Session) GetExpires() time.Time {
	return s.Expires
}

func (s Session) SetExpires(t time.Time) {
	s.Expires = t
}
