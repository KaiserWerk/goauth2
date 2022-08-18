package goauth

import (
	"crypto/rand"
	"encoding/base64"
)

type defaultTokenSource struct{}

var DefaultTokenSource TokenSource = &defaultTokenSource{}

func (src *defaultTokenSource) Token() (string, error) {
	b := make([]byte, 120)
	_, err := rand.Read(b)
	return base64.URLEncoding.EncodeToString(b), err
}
