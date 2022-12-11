package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	authServerURL = "http://localhost:7777" // this might or might not be hard-coded, maybe you'll use service discovery

	// client ID/Secret should generally not be hard-coded but instead be
	// taken from a config file, env vars, or similar sources.
	// client credentials are used for basic auth in this flow
	clientID     = "my_cool_test_app"
	clientSecret = "abc123def456" // in this case, it's a confidential app

	username = "tim"
	password = "test"
)

type response struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        uint64 `json:"expires_in"`
	TokenType        string `json:"token_type"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func main() {
	client := &http.Client{Timeout: 10 * time.Second} // use a proper *http.Client at least for timeouts

	data := url.Values{}
	data.Add("username", username)
	data.Add("password", password)
	data.Add("grant_type", "password")

	req, _ := http.NewRequest(http.MethodPost, authServerURL+"/resource_owner_credentials", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	cont, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Raw response:", string(cont))

	var r response
	if err = json.Unmarshal(cont, &r); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Parsed response: %+v\n", r)
}
