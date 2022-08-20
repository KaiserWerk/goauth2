package sessionauthenticator

import (
	"net/http"

	"github.com/KaiserWerk/goauth2/storage"
)

type SessionAuthenticator interface {
	IsUserLoggedIn(*http.Request) (storage.User, error)
	GetSessionID(*http.Request) (string, error)
}
