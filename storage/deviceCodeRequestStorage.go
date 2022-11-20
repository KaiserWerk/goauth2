package storage

type (
	OAuth2DeviceCodeRequest interface {
		GetClientID() string
		SetClientID(string)
		GetResponse() DeviceCodeResponse
		SetResponse(DeviceCodeResponse)
		GetTokenResponse() Token
		SetTokenResponse(Token)
	}
	// DeviceCodeStorage stores device codes.
	// For in-memory implementations, Close() should be a no-op.
	DeviceCodeStorage interface {
		Get(string) (OAuth2DeviceCodeRequest, error)
		Find(string, string) (OAuth2DeviceCodeRequest, error)
		Add(OAuth2DeviceCodeRequest) error
		Update(OAuth2DeviceCodeRequest) error
		Close() error
	}
)
