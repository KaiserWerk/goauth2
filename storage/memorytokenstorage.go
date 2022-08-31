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

func (ts *MemoryTokenStorage) FindByAccessToken(at string) (Token, error) {
	ts.m.RLock()
	defer ts.m.RUnlock()
	token, found := ts.tokens[at]
	if !found {
		return Token{}, ErrTokenEntryNotFound
	}

	return token, nil
}

func (ts *MemoryTokenStorage) FindByCodeChallenge(cc string) (Token, error) {
	ts.m.RLock()
	defer ts.m.RUnlock()

	for _, t := range ts.tokens {
		if t.CodeChallenge == cc {
			return t, nil
		}
	}

	return Token{}, ErrTokenEntryNotFound
}

func (ts *MemoryTokenStorage) Set(t Token) error {
	ts.m.Lock()
	defer ts.m.Unlock()
	_, found := ts.tokens[t.AccessToken]
	if found {
		return ErrTokenEntryExists
	}
	ts.tokens[t.AccessToken] = t
	return nil
}
