package storage

type OAuth2Client interface {
	GetID() string
	SetID(string)
	GetSecret() string
	SetSecret(string)
	IsConfidential() bool
	SetConfidential(bool)
	GetApplicationName() string
	SetApplicationName(string)
	HasRedirectURL(string) bool
	AddRedirectURL(string)
	RemoveRedirectURL(string)
	ClearRedirectURLS()
}

// ClientStorage is the interface that must be implemented to act as a client storage
// For in-memory implementations, Close() should be a no-op.
type ClientStorage interface {
	Get(string) (OAuth2Client, error)
	Set(client OAuth2Client) error
	Close() error
}
