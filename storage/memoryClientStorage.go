package storage

import (
	"errors"
	"sync"
)

var (
	ErrClientEntryExists   = errors.New("client entry with this ID already exists")
	ErrClientEntryNotFound = errors.New("client entry not found")
)

type MemoryClientStorage struct {
	m       *sync.RWMutex
	clients map[string]OAuth2Client
}

func NewMemoryClientStorage() *MemoryClientStorage {
	return &MemoryClientStorage{
		m:       new(sync.RWMutex),
		clients: make(map[string]OAuth2Client),
	}
}

func (cs *MemoryClientStorage) Get(id string) (OAuth2Client, error) {
	cs.m.RLock()
	defer cs.m.RUnlock()
	c, found := cs.clients[id]
	if !found {
		return nil, ErrClientEntryNotFound
	}

	return c, nil
}

func (cs *MemoryClientStorage) Add(client OAuth2Client) error {
	cs.m.Lock()
	defer cs.m.Unlock()
	_, found := cs.clients[client.GetID()]
	if found {
		return ErrClientEntryExists
	}
	cs.clients[client.GetID()] = client
	return nil
}

func (cs *MemoryClientStorage) Edit(client OAuth2Client) error {
	cs.m.Lock()
	defer cs.m.Unlock()
	_, found := cs.clients[client.GetID()]
	if !found {
		return ErrClientEntryNotFound
	}

	cs.clients[client.GetID()] = client
	return nil
}

func (cs *MemoryClientStorage) Remove(client OAuth2Client) error {
	cs.m.Lock()
	defer cs.m.Unlock()
	delete(cs.clients, client.GetID())
	return nil
}

func (_ *MemoryClientStorage) Close() error {
	return nil
}
