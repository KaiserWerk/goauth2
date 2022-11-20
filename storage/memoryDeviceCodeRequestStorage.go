package storage

import (
	"errors"
	"sync"
)

var (
	ErrDeviceCodeRequestEntryExists   = errors.New("DeviceCodeRequest entry with this ID already exists")
	ErrDeviceCodeRequestEntryNotFound = errors.New("DeviceCodeRequest entry not found")
)

type DeviceCodeRequestStorage struct {
	m        *sync.RWMutex
	requests map[string]OAuth2DeviceCodeRequest
}

func NewMemoryDeviceCodeRequestStorage() *DeviceCodeRequestStorage {
	return &DeviceCodeRequestStorage{
		m:        new(sync.RWMutex),
		requests: make(map[string]OAuth2DeviceCodeRequest),
	}
}

func (dcrs *DeviceCodeRequestStorage) Get(userCode string) (OAuth2DeviceCodeRequest, error) {
	dcrs.m.RLock()
	defer dcrs.m.RUnlock()
	if r, found := dcrs.requests[userCode]; found {
		return r, nil
	}

	return DeviceCodeRequest{}, nil
}

func (dcrs *DeviceCodeRequestStorage) Find(deviceCode, clientID string) (OAuth2DeviceCodeRequest, error) {
	dcrs.m.RLock()
	defer dcrs.m.RUnlock()

	for _, e := range dcrs.requests {
		if e.GetClientID() == clientID && e.GetResponse().DeviceCode == deviceCode {
			return e, nil
		}
	}

	return DeviceCodeRequest{}, ErrDeviceCodeRequestEntryNotFound
}

func (dcrs *DeviceCodeRequestStorage) Add(request OAuth2DeviceCodeRequest) error {
	dcrs.m.Lock()
	defer dcrs.m.Unlock()

	if _, found := dcrs.requests[request.GetResponse().UserCode]; found {
		return ErrDeviceCodeRequestEntryExists
	}

	dcrs.requests[request.GetResponse().UserCode] = request
	return nil
}

func (dcrs *DeviceCodeRequestStorage) Update(request OAuth2DeviceCodeRequest) error {
	dcrs.m.Lock()
	defer dcrs.m.Unlock()

	if _, found := dcrs.requests[request.GetResponse().UserCode]; !found {
		return ErrDeviceCodeRequestEntryNotFound
	}

	dcrs.requests[request.GetResponse().UserCode] = request
	return nil
}

func (dcrs *DeviceCodeRequestStorage) Close() error {
	return nil
}
