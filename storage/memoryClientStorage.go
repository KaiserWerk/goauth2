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
	clients map[string]Client
}

func NewMemoryClientStorage() *MemoryClientStorage {
	return &MemoryClientStorage{
		m:       new(sync.RWMutex),
		clients: make(map[string]Client),
	}
}

func (cs *MemoryClientStorage) Get(id string) (Client, error) {
	cs.m.RLock()
	defer cs.m.RUnlock()
	c, found := cs.clients[id]
	if !found {
		return Client{}, ErrClientEntryNotFound
	}

	return c, nil
}

func (cs *MemoryClientStorage) Set(cl Client) error {
	cs.m.Lock()
	defer cs.m.Unlock()
	_, found := cs.clients[cl.ID]
	if found {
		return ErrClientEntryExists
	}
	cs.clients[cl.ID] = cl
	return nil
}
