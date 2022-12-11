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

	goauthSrv.Storage.ClientStorage.Add(storage.Client{
		ID:           "my_cool_test_app",
		Secret:       "abc123def456",
		AppName:      "My Resource Owner Credentials Test App",
		Confidential: true,
	})
	goauthSrv.Storage.UserStorage.Add(storage.User{
		ID:       1,
		Username: "tim",
		Password: "test",
	})

	router := http.NewServeMux()

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "welcome to the goauth2 test server testing Resource Owner Credentials Flow!")
	})

	router.HandleFunc("/resource_owner_credentials", func(w http.ResponseWriter, r *http.Request) {
		if err := goauthSrv.HandleResourceOwnerPasswordCredentialsRequest(w, r); err != nil {
			fmt.Println("HandleResourceOwnerPasswordCredentialsRequest:", err.Error())
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
