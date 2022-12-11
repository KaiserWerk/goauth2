package types

import "github.com/KaiserWerk/goauth2/storage"

type IntrospectionResponse struct {
	Active   bool          `json:"active"`
	Scope    storage.Scope `json:"scope,omitempty"`
	ClientID string        `json:"client_id,omitempty"`
	Username string        `json:"username,omitempty"`
	Expires  uint64        `json:"exp,omitempty"`
}
