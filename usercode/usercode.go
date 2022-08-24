package usercode

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
)

type Generator interface {
	Generate() (string, error)
}

type UCGenerator struct{}

var DefaultUserCodeGenerator = &UCGenerator{}

// Generate generates a user code with length 9 in the form of 'XXXX-XXXX'
func (ucg *UCGenerator) Generate() (string, error) {
	b := make([]byte, 9)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	b[4] = byte('-') // yes, a dash

	str := base64.RawStdEncoding.EncodeToString(b)
	str = strings.ToUpper(str)

	return str, nil
}
