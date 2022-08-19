package token

// TokenSource implements just the method Token(), which must return a cryptographically secure random string.
type TokenSource interface {
	Token() (string, error)
}
