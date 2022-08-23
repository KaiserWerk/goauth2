package types

type GrantType uint8

const (
	AuthorizationCode GrantType = iota
	DeviceCode
	Implicit
	ClientCredentials
	ResourceOwnerPasswordCredentials
)

func (g GrantType) String() string {
	switch g {
	case AuthorizationCode:
		return "authorization_code"
	case DeviceCode:
		return "device_code"
	case Implicit:
		return "implicit"
	case ClientCredentials:
		return "client_credentials"
	case ResourceOwnerPasswordCredentials:
		return "resource_owner_password_credentials"
	}

	return "invalid grant type"
}
