package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	goauth "github.com/KaiserWerk/goauth2"
	"github.com/KaiserWerk/goauth2/storage"
)

func main() {
	goauthSrv := goauth.NewDefaultServer()
	goauthSrv.PublicBaseURL = "http://localhost:7777"
	goauthSrv.URLs.AuthorizationCode = "/authorization"
	goauthSrv.Flags.PKCE = false

	goauthSrv.Storage.UserStorage.Add(storage.User{
		ID:       1,
		Username: "tim",
		Password: "test",
	})
	goauthSrv.Storage.ClientStorage.Add(storage.Client{
		ID:           "my-test-app",
		Secret:       "123456",
		AppName:      "My Test App",
		Confidential: false,
	})

	router := http.NewServeMux()

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "welcome to the goauth2 test server!")
	})

	router.HandleFunc(goauthSrv.URLs.AuthorizationCode, func(w http.ResponseWriter, r *http.Request) {
		if err := goauthSrv.HandleAuthorizationCodeAuthorizationRequest(w, r); err != nil {
			fmt.Println("HandleAuthorizationCodeAuthorizationRequest:", err.Error())
		}
	})

	router.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := goauthSrv.HandleAuthorizationCodeTokenRequest(w, r); err != nil {
			fmt.Println("HandleAuthorizationCodeTokenRequest:", err.Error())
		}
	})

	router.HandleFunc("/user_login", func(w http.ResponseWriter, r *http.Request) {
		if err := goauthSrv.HandleUserLogin(w, r); err != nil {
			fmt.Println("HandleUserLogin:", err.Error())
		}
	})

	router.HandleFunc("/user_logout", func(w http.ResponseWriter, r *http.Request) {
		if err := goauthSrv.HandleUserLogout(w, r); err != nil {
			fmt.Println("HandleUserLogout:", err.Error())
		}
	})

	srv := &http.Server{
		Handler:      router,
		Addr:         "localhost:7777",
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
		IdleTimeout:  5 * time.Minute,
	}

	fmt.Println("starting to listen on 7777...")
	log.Fatal(srv.ListenAndServe())
}
