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
	requests map[string]DeviceCodeRequest
}

func NewMemoryDeviceCodeRequestStorage() *DeviceCodeRequestStorage {
	return &DeviceCodeRequestStorage{
		m:        new(sync.RWMutex),
		requests: make(map[string]DeviceCodeRequest),
	}
}

func (dcrs *DeviceCodeRequestStorage) Get(userCode string) (DeviceCodeRequest, error) {
	dcrs.m.RLock()
	defer dcrs.m.RUnlock()
	if r, found := dcrs.requests[userCode]; found {
		return r, nil
	}

	return DeviceCodeRequest{}, nil
}

func (dcrs *DeviceCodeRequestStorage) Find(deviceCode, clientID string) (DeviceCodeRequest, error) {
	dcrs.m.RLock()
	defer dcrs.m.RUnlock()

	for _, e := range dcrs.requests {
		if e.ClientID == clientID && e.Response.DeviceCode == deviceCode {
			return e, nil
		}
	}

	return DeviceCodeRequest{}, ErrDeviceCodeRequestEntryNotFound
}

func (dcrs *DeviceCodeRequestStorage) Add(request DeviceCodeRequest) error {
	dcrs.m.Lock()
	defer dcrs.m.Unlock()

	if _, found := dcrs.requests[request.Response.UserCode]; found {
		return ErrDeviceCodeRequestEntryExists
	}

	dcrs.requests[request.Response.UserCode] = request
	return nil
}

func (dcrs *DeviceCodeRequestStorage) Update(request DeviceCodeRequest) error {
	dcrs.m.Lock()
	defer dcrs.m.Unlock()

	if _, found := dcrs.requests[request.Response.UserCode]; !found {
		return ErrDeviceCodeRequestEntryNotFound
	}

	dcrs.requests[request.Response.UserCode] = request
	return nil
}
