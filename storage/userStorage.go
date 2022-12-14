package storage

type (
	OAuth2User interface {
		GetID() uint
		SetID(uint)
		GetUsername() string
		SetUsername(string)
		GetEmail() string
		SetEmail(string)
		GetPassword() string
		SetPassword(string)
		DoesPasswordMatch(string) bool
		IsDisabled() bool
		SetDisabled(bool)
	}

	// A UserStorage stores information about users (resource owners).
	// For in-memory implementations, Close() should be a no-op.
	UserStorage interface {
		Get(id uint) (OAuth2User, error)
		GetByUsername(name string) (OAuth2User, error)
		Add(user OAuth2User) error
		Edit(user OAuth2User) error
		Remove(id uint) error
		Close() error
	}
)
