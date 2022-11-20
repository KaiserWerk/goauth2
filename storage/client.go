package storage

import "fmt"

// A Client represents an application. A Client's ID must be unique.
type Client struct {
	ID           string
	Secret       string
	Confidential bool
	AppName      string
	RedirectURLs []string
}

func (c *Client) GetID() string {
	return c.ID
}

func (c *Client) SetID(id string) {
	c.ID = id
}

func (c *Client) GetSecret() string {
	return c.Secret
}

func (c *Client) SetSecret(s string) {
	c.Secret = s
}

func (c *Client) IsConfidential() bool {
	return c.Confidential
}

func (c *Client) SetConfidential(b bool) {
	c.Confidential = b
}

func (c *Client) GetApplicationName() string {
	return c.AppName
}

func (c *Client) SetApplicationName(appName string) {
	c.AppName = appName
}

func (c *Client) HasRedirectURL(u string) bool {
	for _, ru := range c.RedirectURLs {
		if ru == u {
			return true
		}
	}

	return false
}

func (c *Client) AddRedirectURL(u string) {
	if !c.HasRedirectURL(u) {
		c.RedirectURLs = append(c.RedirectURLs, u)
	}
}

func (c *Client) RemoveRedirectURL(u string) {
	var (
		i  = 0
		ru string
	)
	for i, ru = range c.RedirectURLs {
		if ru == u {
			break
		}
	}

	c.RedirectURLs[i] = c.RedirectURLs[len(c.RedirectURLs)-1] // move last element to position of item to remove
	c.RedirectURLs = c.RedirectURLs[:len(c.RedirectURLs)-1]   // last element now exists twice, so cut it off
}

func (c *Client) ClearRedirectURLS() {
	c.RedirectURLs = make([]string, 0, 10)
}

func (c *Client) String() string {
	return fmt.Sprintf("%s (%s)", c.AppName, c.ID)
}

func NewClient(id, secret, appName string) Client {
	return Client{
		ID:           id,
		Secret:       secret,
		Confidential: false,
		AppName:      appName,
		RedirectURLs: make([]string, 0, 10),
	}
}
