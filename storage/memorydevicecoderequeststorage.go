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

func (dars *DeviceCodeRequestStorage) Get(userCode string) (DeviceCodeRequest, error) {
	dars.m.RLock()
	defer dars.m.RUnlock()
	if r, found := dars.requests[userCode]; found {
		return r, nil
	}

	return DeviceCodeRequest{}, nil
}

func (dars *DeviceCodeRequestStorage) Find(deviceCode, clientID string) (DeviceCodeRequest, error) {
	dars.m.RLock()
	defer dars.m.RUnlock()

	for _, e := range dars.requests {
		if e.ClientID == clientID && e.Response.DeviceCode == deviceCode {
			return e, nil
		}
	}

	return DeviceCodeRequest{}, ErrDeviceCodeRequestEntryNotFound
}

func (dars *DeviceCodeRequestStorage) Add(request DeviceCodeRequest) error {
	dars.m.Lock()
	defer dars.m.Unlock()

	if _, found := dars.requests[request.Response.UserCode]; found {
		return ErrDeviceCodeRequestEntryExists
	}

	dars.requests[request.Response.UserCode] = request
	return nil
}

func (dars *DeviceCodeRequestStorage) Update(request DeviceCodeRequest) error {
	dars.m.Lock()
	defer dars.m.Unlock()

	if _, found := dars.requests[request.Response.UserCode]; !found {
		return ErrDeviceCodeRequestEntryNotFound
	}

	dars.requests[request.Response.UserCode] = request
	return nil
}
