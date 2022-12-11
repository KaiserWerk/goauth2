package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

const (
	authServerURL = "http://localhost:7777" // this might or might not be hard-coded, maybe you'll use service discovery

	// client ID/Secret should generally not be hard-coded but instead be
	// taken from a config file, env vars, or similar sources.
	clientID     = "my_cool_test_app"
	clientSecret = "abc123def456"
)

type Response struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        uint64 `json:"expires_in"`
	TokenType        string `json:"token_type"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func main() {
	client := &http.Client{Timeout: 10 * time.Second} // use a proper *http.Client at least for timeouts

	// we omitted the scope here, add it if needed
	resp, err := client.PostForm(authServerURL+"/client_credentials", url.Values{
		"client_id":     []string{clientID},
		"client_secret": []string{clientSecret},
		"grant_type":    []string{"client_credentials"},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\nRaw response:", string(body))

	var r Response
	if err = json.Unmarshal(body, &r); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Parsed response: %+v\n", r)
}
