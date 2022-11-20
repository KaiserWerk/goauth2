package storage

// A User represents a resource owner.
type User struct {
	ID       uint
	Username string
	Email    string
	Password string
	Disabled bool
}

func (u User) GetID() uint {
	return u.ID
}

func (u User) SetID(id uint) {
	u.ID = id
}

func (u User) GetUsername() string {
	return u.Username
}

func (u User) SetUsername(username string) {
	u.Username = username
}

func (u User) GetEmail() string {
	return u.Email
}

func (u User) SetEmail(email string) {
	u.Email = email
}

func (u User) GetPassword() string {
	return u.Password
}

func (u User) SetPassword(password string) {
	u.Password = password
}

func (u User) DoesPasswordMatch(password string) bool {
	return u.Password == password
}

func (u User) IsDisabled() bool {
	return u.Disabled
}

func (u User) SetDisabled(d bool) {
	u.Disabled = d
}
