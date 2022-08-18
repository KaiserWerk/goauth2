package goauth

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
	users map[uint]User
}

func NewMemoryUserStorage() *MemoryUserStorage {
	return &MemoryUserStorage{
		m:     new(sync.RWMutex),
		users: make(map[uint]User),
	}
}

func (us *MemoryUserStorage) Get(id uint) (User, error) {
	us.m.RLock()
	defer us.m.RUnlock()
	c, found := us.users[id]
	if !found {
		return User{}, ErrUserEntryNotFound
	}

	return c, nil
}

func (us *MemoryUserStorage) GetByUsername(name string) (User, error) {
	us.m.RLock()
	defer us.m.RUnlock()

	for _, e := range us.users {
		if e.Username == name {
			return e, nil
		}
	}

	return User{}, nil
}

func (us *MemoryUserStorage) Add(user User) error {
	us.m.Lock()
	defer us.m.Unlock()
	_, found := us.users[user.ID]
	if found {
		return ErrUserEntryExists
	}
	us.users[user.ID] = user
	return nil
}

func (us *MemoryUserStorage) Edit(user User) error {
	us.m.Lock()
	defer us.m.Unlock()
	_, found := us.users[user.ID]
	if !found {
		return ErrUserEntryNotFound
	}
	us.users[user.ID] = user
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
