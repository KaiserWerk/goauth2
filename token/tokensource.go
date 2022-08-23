package token

// TokenGenerator implements just the method Token(), which must return a cryptographically secure random string and an error.
type TokenGenerator interface {
	Token(int) (string, error)
}
