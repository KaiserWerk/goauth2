package storage

type DeviceCodeRequest struct {
	ClientID      string
	Response      DeviceCodeResponse
	TokenResponse Token
}

type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               uint64 `json:"expires_in"`
	Interval                uint64 `json:"interval"`
}

func (d *DeviceCodeRequest) GetClientID() string {
	return d.ClientID
}

func (d *DeviceCodeRequest) SetClientID(id string) {
	d.ClientID = id
}

func (d *DeviceCodeRequest) GetResponse() DeviceCodeResponse {
	return d.Response
}

func (d *DeviceCodeRequest) SetResponse(response DeviceCodeResponse) {
	d.Response = response
}

func (d *DeviceCodeRequest) GetTokenResponse() Token {
	return d.TokenResponse
}

func (d *DeviceCodeRequest) SetTokenResponse(token Token) {
	d.TokenResponse = token
}
