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

type DeviceCodeStorage interface {
	Get(string) (DeviceCodeRequest, error)
	Find(string, string) (DeviceCodeRequest, error)
	Add(DeviceCodeRequest) error
	Update(DeviceCodeRequest) error
}
