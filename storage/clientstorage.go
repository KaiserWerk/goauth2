package storage

import "fmt"

// A Client represents an application. A Client's ID must be unique.
type Client struct { // TODO rework this into an interface
	ID              string
	Secret          string
	ApplicationName string
	RedirectURLs    []string
}

// ClientStorage is the interface that must be implemented to act as a client storage
type ClientStorage interface {
	Get(string) (Client, error)
	Set(Client) error
}

func (c *Client) String() string {
	return fmt.Sprintf("%s (%s)", c.ApplicationName, c.ID)
}
