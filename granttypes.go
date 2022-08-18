package goauth

type GrantType uint8

const (
	AuthorizationCode GrantType = iota
	DeviceCode
)
