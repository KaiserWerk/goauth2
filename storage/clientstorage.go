package storage

import "fmt"

// A Client represents an application. A Client's ID must be unique.
type Client struct {
	ID              string
	Secret          string
	ApplicationName string
	RedirectURLs    []string
}

type ClientStorage interface {
	Get(string) (Client, error)
	Set(Client) error
}

func (c *Client) String() string {
	return fmt.Sprintf("%s (%s)", c.ApplicationName, c.ID)
}
