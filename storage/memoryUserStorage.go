package storage

import (
	"errors"
	"sync"
)

var (
	ErrUserEntryExists   = errors.New("user entry with this ID already exists")
	ErrUserEntryNotFound = errors.New("user entry not found")
)

type MemoryUserStorage struct {
	m     *sync.RWMutex
	users map[uint]OAuth2User
}

func NewMemoryUserStorage() *MemoryUserStorage {
	return &MemoryUserStorage{
		m:     new(sync.RWMutex),
		users: make(map[uint]OAuth2User),
	}
}

func (us *MemoryUserStorage) Get(id uint) (OAuth2User, error) {
	us.m.RLock()
	defer us.m.RUnlock()
	c, found := us.users[id]
	if !found {
		return nil, ErrUserEntryNotFound
	}

	return c, nil
}

func (us *MemoryUserStorage) GetByUsername(name string) (OAuth2User, error) {
	us.m.RLock()
	defer us.m.RUnlock()

	for _, e := range us.users {
		if e.GetUsername() == name {
			return e, nil
		}
	}

	return nil, ErrUserEntryNotFound
}

func (us *MemoryUserStorage) Add(user OAuth2User) error {
	us.m.Lock()
	defer us.m.Unlock()
	_, found := us.users[user.GetID()]
	if found {
		return ErrUserEntryExists
	}
	us.users[user.GetID()] = user
	return nil
}

func (us *MemoryUserStorage) Edit(user OAuth2User) error {
	us.m.Lock()
	defer us.m.Unlock()
	_, found := us.users[user.GetID()]
	if !found {
		return ErrUserEntryNotFound
	}
	us.users[user.GetID()] = user
	return nil
}

func (us *MemoryUserStorage) Remove(id uint) error {
	us.m.Lock()
	defer us.m.Unlock()
	_, found := us.users[id]
	if !found {
		return ErrUserEntryNotFound
	}

	delete(us.users, id)
	return nil
}

func (s *MemoryUserStorage) Close() error {
	return nil
}
