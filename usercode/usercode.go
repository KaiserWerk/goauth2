package usercode

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

type Generator interface {
	Generate() (string, error)
}

type UCGenerator struct{}

var DefaultUserCodeGenerator = &UCGenerator{}

// Generate generates a user code with length 9 in the form of 'XXXX-XXXX'
func (ucg *UCGenerator) Generate() (string, error) {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	var builder strings.Builder
	str := base32.StdEncoding.EncodeToString(b)
	builder.WriteString(str[:4])
	builder.WriteString("-") // yes, a dash
	builder.WriteString(str[4:8])

	return builder.String(), nil
}
