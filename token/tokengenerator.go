package token

// TokenGenerator implements just the method Generate(), which must return a cryptographically secure random string and an error.
type TokenGenerator interface {
	Generate(int) (string, error)
}
