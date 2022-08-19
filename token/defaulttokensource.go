package token

import (
	"crypto/rand"
	"encoding/base64"
)

type defaultTokenSource struct {
	tokenLen int
}

var DefaultTokenSource TokenSource = &defaultTokenSource{120}

func (src *defaultTokenSource) Token() (string, error) {
	b := make([]byte, src.tokenLen)
	_, err := rand.Read(b)
	return base64.URLEncoding.EncodeToString(b), err
}
