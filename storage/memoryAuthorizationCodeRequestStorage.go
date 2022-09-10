package storage

import (
	"errors"
	"sync"
)

var (
	ErrAuthorizationCodeRequestEntryExists   = errors.New("authorization code request entry with this ID already exists")
	ErrAuthorizationCodeRequestEntryNotFound = errors.New("authorization code request entry not found")
)

type MemoryAuthorizationCodeRequestStorage struct {
	m        *sync.Mutex
	requests map[string]AuthorizationCodeRequest
}

func NewMemoryAuthorizationCodeRequestStorage() *MemoryAuthorizationCodeRequestStorage {
	return &MemoryAuthorizationCodeRequestStorage{
		m:        new(sync.Mutex),
		requests: make(map[string]AuthorizationCodeRequest),
	}
}

func (s *MemoryAuthorizationCodeRequestStorage) Pop(code string) (AuthorizationCodeRequest, error) {
	s.m.Lock()
	defer s.m.Unlock()

	if req, found := s.requests[code]; found {
		delete(s.requests, code)
		return req, nil
	}

	return AuthorizationCodeRequest{}, ErrAuthorizationCodeRequestEntryNotFound
}

func (s *MemoryAuthorizationCodeRequestStorage) Insert(request AuthorizationCodeRequest) error {
	s.m.Lock()
	defer s.m.Unlock()

	if _, found := s.requests[request.Code]; found {
		return ErrAuthorizationCodeRequestEntryExists
	}

	s.requests[request.Code] = request
	return nil
}
