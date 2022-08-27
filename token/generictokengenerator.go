package token

import (
	"crypto/rand"
	"encoding/base64"
)

type GenericTokenGenerator struct {
	tokenLen int
}

// NewGenericTokenGenerator returns a new *GenericTokenGenerator generating tokens with the given length.
func NewGenericTokenGenerator(tokenLen int) *GenericTokenGenerator {
	return &GenericTokenGenerator{tokenLen: tokenLen}
}

// Token returns cryptographically secure randomly generated string, encoded with base64 raw standard encoding.
func (tg *GenericTokenGenerator) Generate(length int) (string, error) {
	if length == 0 {
		length = tg.tokenLen
	}
	b := make([]byte, length)
	_, err := rand.Read(b)
	return base64.RawStdEncoding.EncodeToString(b), err
}
