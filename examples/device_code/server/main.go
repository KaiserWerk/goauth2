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

	goauthSrv.Storage.UserStorage.Add(storage.User{
		ID:       1,
		Username: "tim",
		Password: "test",
	})
	goauthSrv.Storage.ClientStorage.Set(storage.Client{
		ID:              "my_cool_test_app",
		Secret:          "9sfe196sgews8r7413423gf",
		ApplicationName: "My Cool Test App",
	})

	router := http.NewServeMux()

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "welcome to the goauth2 test server!")
	})

	router.HandleFunc("/device_authorization", func(w http.ResponseWriter, r *http.Request) {
		if err := goauthSrv.HandleDeviceCodeAuthorizationRequest(w, r); err != nil {
			fmt.Println("HandleDeviceCodeAuthorizationRequest:", err.Error())
		}
	})

	router.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		if err := goauthSrv.HandleDeviceCodeUserAuthorization(w, r); err != nil {
			fmt.Println("HandleDeviceCodeUserAuthorization:", err.Error())
		}
	})

	router.HandleFunc("/device_token", func(w http.ResponseWriter, r *http.Request) {
		if err := goauthSrv.HandleDeviceCodeTokenRequest(w, r); err != nil {
			fmt.Println("HandleDeviceCodeTokenRequest:", err.Error())
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
