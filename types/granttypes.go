package types

type GrantType uint8

const (
	AuthorizationCode GrantType = iota
	DeviceCode
	ClientCredentials
	ResourceOwnerPasswordCredentials
)
