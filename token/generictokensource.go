package token

import (
	"crypto/rand"
	"encoding/base64"
)

type GenericTokenSource struct {
	tokenLen int
}

// Token returns cryptographically secure randomly generated string.
func (ts *GenericTokenSource) Token(length int) (string, error) {
	if length == 0 {
		length = ts.tokenLen
	}
	b := make([]byte, length)
	_, err := rand.Read(b)
	return base64.URLEncoding.EncodeToString(b), err
}
