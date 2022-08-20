package sessionauthenticator

//import (
//	"fmt"
//	"net/http"
//
//	"github.com/KaiserWerk/goauth2/storage"
//)
//
//type MemorySessionAuthenticator struct {
//}
//
//func (sa *MemorySessionAuthenticator) IsUserLoggedIn(r *http.Request) (storage.User, error) {
//	sid, err := sa.GetSessionID(r)
//	if err != nil || sid == "" {
//		return storage.User{}, nil
//	}
//
//	session, err := s.Storage.SessionStorage.Get(sid)
//	if err != nil {
//		return storage.User{}, fmt.Errorf("user had session ID, but was not found")
//	}
//
//	user, err := s.Storage.UserStorage.Get(session.UserID)
//	if err != nil {
//		return storage.User{}, fmt.Errorf("valid session, but didn't find user")
//	}
//
//	return user, nil
//}
//
//func (sa *MemorySessionAuthenticator) GetSessionID(r *http.Request) (string, error) {
//	//TODO implement me
//	panic("implement me")
//}
