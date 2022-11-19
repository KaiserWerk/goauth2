package main

import (
	"fmt"
	"log"
	"net/http"

	goauth "github.com/KaiserWerk/goauth2"
	"github.com/KaiserWerk/goauth2/storage"
)

func main() {
	srv := goauth.NewDefaultServer()
	srv.PublicBaseURL = "http://localhost:7777"
	srv.URLs.Implicit = "/authorize"

	srv.Storage.ClientStorage.Set(storage.Client{
		ID:           "00000",
		Secret:       "", // Secret is not needed for implicit flow
		AppName:      "My Cool Implicit App",
		RedirectURLs: []string{"http://localhost:8888/callback"}, // register allowed redirect URLs
	})

	srv.Storage.UserStorage.Add(storage.User{
		ID:       1,
		Username: "tim",
		Password: "test",
	})

	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleImplicitAuthorizationRequest(w, r)
		if err != nil {
			fmt.Println("Implicit flow error:", err.Error())
		}
	})

	http.HandleFunc("/user_login", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleUserLogin(w, r)
		if err != nil {
			fmt.Println("user login error:", err.Error())
		}
	})

	http.HandleFunc("/user_logout", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleUserLogout(w, r)
		if err != nil {
			fmt.Println("user logout error:", err.Error())
		}
	})

	fmt.Println("started listening on port 7777...")
	log.Fatal(http.ListenAndServe("localhost:7777", nil))
}
