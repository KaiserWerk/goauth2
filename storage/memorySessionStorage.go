package storage

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrSessionEntryExists   = errors.New("session entry with this ID already exists")
	ErrSessionEntryNotFound = errors.New("session entry not found")
)

type MemorySessionStorage struct {
	m        *sync.RWMutex
	sessions map[string]Session
}

func NewMemorySessionStorage() *MemorySessionStorage {
	return &MemorySessionStorage{
		m:        new(sync.RWMutex),
		sessions: make(map[string]Session),
	}
}

func (ss *MemorySessionStorage) Get(id string) (Session, error) {
	ss.m.RLock()
	defer ss.m.RUnlock()
	if s, found := ss.sessions[id]; found {
		if s.Expires.After(time.Now()) {
			return s, nil
		} else {
			delete(ss.sessions, id)
		}
	}

	return Session{}, ErrSessionEntryNotFound
}

func (ss *MemorySessionStorage) Add(session Session) error {
	ss.m.Lock()
	defer ss.m.Unlock()
	if _, found := ss.sessions[session.ID]; found {
		return ErrSessionEntryExists
	}

	ss.sessions[session.ID] = session
	return nil
}

func (ss *MemorySessionStorage) Remove(id string) error {
	ss.m.Lock()
	defer ss.m.Unlock()
	if _, found := ss.sessions[id]; !found {
		return ErrSessionEntryNotFound
	}
	delete(ss.sessions, id)
	return nil
}
