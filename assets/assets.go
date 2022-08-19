package assets

import (
	_ "embed"
)

//go:embed templates/login.gohtml
var LoginPageTemplate []byte

//go:embed templates/device_code.gohtml
var DeviceCodeTemplate []byte

//go:embed templates/implicit_flow.gohtml
var ImplicitFlowTemplate []byte

//go:embed templates/authorization_code.gohtml
var AuthorizationCodeTemplate []byte
