package goauth

type Session struct {
	ID     string
	UserID uint
}

type SessionStorage interface {
	Get(string) (Session, error)
	Add(Session) error
	Remove(string) error
}
