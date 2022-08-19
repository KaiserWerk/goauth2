package storage

import (
	"errors"
	"sync"
)

var (
	ErrTokenEntryExists   = errors.New("token entry with this ID already exists")
	ErrTokenEntryNotFound = errors.New("token entry not found")
)

type MemoryTokenStorage struct {
	m      *sync.RWMutex
	tokens map[string]Token
}

func NewMemoryTokenStorage() *MemoryTokenStorage {
	return &MemoryTokenStorage{
		m:      new(sync.RWMutex),
		tokens: make(map[string]Token),
	}
}

func (ts *MemoryTokenStorage) Get(str string) (Token, error) {
	ts.m.RLock()
	defer ts.m.RUnlock()
	token, found := ts.tokens[str]
	if !found {
		return Token{}, ErrTokenEntryNotFound
	}

	return token, nil
}

func (ts *MemoryTokenStorage) Set(t Token) error {
	ts.m.Lock()
	defer ts.m.Unlock()
	_, found := ts.tokens[t.Token]
	if found {
		return ErrTokenEntryExists
	}
	ts.tokens[t.Token] = t
	return nil
}
