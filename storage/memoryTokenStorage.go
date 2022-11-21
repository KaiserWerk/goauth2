package storage

import (
	"errors"
	"sync"
)

var (
	ErrTokenEntryExists   = errors.New("token entry with this access string already exists")
	ErrTokenEntryNotFound = errors.New("token entry not found")
)

type MemoryTokenStorage struct {
	m      *sync.RWMutex
	tokens map[string]OAuth2Token
}

func NewMemoryTokenStorage() *MemoryTokenStorage {
	return &MemoryTokenStorage{
		m:      new(sync.RWMutex),
		tokens: make(map[string]OAuth2Token),
	}
}

func (ts *MemoryTokenStorage) FindByAccessToken(at string) (OAuth2Token, error) {
	ts.m.RLock()
	defer ts.m.RUnlock()
	token, found := ts.tokens[at]
	if !found {
		return nil, ErrTokenEntryNotFound
	}

	return token, nil
}

func (ts *MemoryTokenStorage) FindByCodeChallenge(cc string) (OAuth2Token, error) {
	ts.m.RLock()
	defer ts.m.RUnlock()

	for _, t := range ts.tokens {
		if t.GetCodeChallenge() == cc {
			return t, nil
		}
	}

	return nil, ErrTokenEntryNotFound
}

func (ts *MemoryTokenStorage) Add(t OAuth2Token) error {
	ts.m.Lock()
	defer ts.m.Unlock()
	_, found := ts.tokens[t.GetAccessToken()]
	if found {
		return ErrTokenEntryExists
	}
	ts.tokens[t.GetAccessToken()] = t
	return nil
}

func (ts *MemoryTokenStorage) Remove(t OAuth2Token) error {
	ts.m.Lock()
	defer ts.m.Unlock()
	delete(ts.tokens, t.GetAccessToken())
	return nil
}

func (_ *MemoryTokenStorage) Close() error {
	return nil
}
