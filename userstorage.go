package goauth

// A User represents a resource owner.
type User struct {
	ID       uint
	Username string
	Email    string
	Password string
	Disabled bool
}

type UserStorage interface {
	Get(id uint) (User, error)
	GetByUsername(name string) (User, error)
	Add(user User) error
	Edit(user User) error
	Remove(id uint) error
}
