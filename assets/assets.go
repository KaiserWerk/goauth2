package assets

import (
	_ "embed"
)

// The LoginPageTemplate is the HTML template used for showing the login form to the user.
//go:embed templates/login.gohtml
var LoginPageTemplate []byte

// The DeviceCodeTemplate is the HTML template used for the Device Code Grant.
//go:embed templates/device_code.gohtml
var DeviceCodeTemplate []byte

// The ImplicitGrantTemplate is the HTML template used for the Implicit Grant.
//go:embed templates/implicit_flow.gohtml
var ImplicitGrantTemplate []byte

// The AuthorizationCodeTemplate is the HTML template used for the Authorization Code Grant and will, by default,
// also be used for PKCE and OpenID Connect.
//go:embed templates/authorization_code.gohtml
var AuthorizationCodeTemplate []byte
