package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// define the types required

type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               uint64 `json:"expires_in"`
	Interval                uint64 `json:"interval"`
}

type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   uint   `json:"expires_in"`
	Error       string `json:"error"`
}

func main() {
	// Device code grant (Device Authorization Grant) is described in
	// RFC 8628: https://www.rfc-editor.org/rfc/rfc8628

	authServerURL := "http://localhost:7777" // this might or might not be hard-coded, maybe you'll use service discovery

	// client ID/Secret should generally not be hard-coded but instead be
	// taken from a config file, env vars, or similar sources.
	clientID := "my_cool_test_app"
	// clientSecret is not needed in this flow

	client := &http.Client{Timeout: 120 * time.Second} // use a proper *http.Client at least for timeouts

	values := url.Values{} // these values can be used in the body with content type application/x-www-form-urlencoded or in the query string
	values.Add("client_id", clientID)

	// alternatively, you could use client.PostForm() instead of declaring a custom request
	req, _ := http.NewRequest(http.MethodPost, authServerURL+"/device_authorization", strings.NewReader(values.Encode()))
	// NewRequest only returns an error when URL is malformed/invalid
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded") // important to set the correct content type!

	resp, err := client.Do(req)
	handleErr(err)

	// 1. step is to obtain a device code (don't show to resource owner) and a user code and
	// a verification URI (which are for the resource owner to see)
	var authResponse DeviceCodeResponse
	err = json.NewDecoder(resp.Body).Decode(&authResponse)
	handleErr(err)

	err = resp.Body.Close()
	handleErr(err)

	now := time.Now()

	// tell resource owner to visit the URL and enter the user code
	fmt.Printf("Please visit the URL '%s' and enter the code '%s' to authorize this app.\n", authResponse.VerificationURI, authResponse.UserCode)
	fmt.Println("Waiting for authorization...")

	// we can re-use this for the request loop below.
	var tokenResponse Token

	// we can re-use these values as well
	values = url.Values{}
	values.Add("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	values.Add("device_code", authResponse.DeviceCode)
	values.Add("client_id", clientID)

	// only loop as long as an error is returned and the time limit is not up yet
	for tokenResponse.AccessToken == "" {

		since := time.Since(now)
		timeout := time.Duration(authResponse.ExpiresIn) * time.Second

		// fmt.Println("Time passed:", since)
		// fmt.Println("Timeout:", timeout)

		if since >= timeout {
			fmt.Println("time limit passed, try again, but be faster")
			os.Exit(-3)
		}

		// POST requests apparently cannot be re-used, so we re-create it
		req, _ = http.NewRequest(http.MethodPost, authServerURL+"/device_token", strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err = client.Do(req)
		handleErr(err)

		err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
		handleErr(err)

		resp.Body.Close()

		// fmt.Printf("token response: %#v\n", tokenResponse)

		// handle the possible error messages:
		//  - authorization_pending
		//  - slow_down
		//  - access_denied
		//  - expired_token

		switch tokenResponse.Error {
		case "authorization_pending":
			// just wait, everything is going fine
		case "slow_down":
			// wait some more
			fmt.Println("Let's wait some more")
			time.Sleep(5 * time.Second)
		case "access_denied":
			// just exit
			fmt.Println("The access was denied because the user canceled.")
			os.Exit(-1)
		case "expired_token":
			// try again
			fmt.Println("expired session; please restart the authorization process.")
			os.Exit(-2)
		}

		// only fire requests at a set interval
		time.Sleep(time.Duration(authResponse.Interval) * time.Second)
	}

	// success!
	// use the Access Token to perform requests against the resource server (the API)
	fmt.Println("Success! Your API Access Token:", tokenResponse.AccessToken)
}

func handleErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
