package goauth

// A Client represents an application. A Client's ID must be unique.
type Client struct {
	ID              string
	Secret          string
	ApplicationName string
}

type ClientStorage interface {
	Get(string) (Client, error)
	Set(Client) error
}
