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

	goauthSrv.Storage.ClientStorage.Add(storage.Client{
		ID:      "my_cool_test_app",
		Secret:  "abc123def456",
		AppName: "My Client Credentials Test App",
	})

	router := http.NewServeMux()

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "welcome to the goauth2 test server testing Client Credentials Flow!")
	})

	router.HandleFunc("/client_credentials", func(w http.ResponseWriter, r *http.Request) {
		if err := goauthSrv.HandleClientCredentialsRequest(w, r); err != nil {
			fmt.Println("HandleClientCredentialsRequest:", err.Error())
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
