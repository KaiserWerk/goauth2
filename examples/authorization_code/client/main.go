package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/KaiserWerk/goauth2/storage"
	"io"
	"net/http"
	"net/url"
	"os/signal"
	"syscall"
	"time"
)

type response struct {
	AccessToken      string         `json:"access_token"`
	TokenType        string         `json:"token_type"`
	ExpiresIn        uint64         `json:"expires_in"`
	Scope            *storage.Scope `json:"scope"`
	RefreshToken     string         `json:"refresh_token"`
	Error            string         `json:"error"`
	ErrorDescription string         `json:"error_description"`
}

const (
	authServerURL = "http://localhost:7777"
	authPath      = "/authorization" // see server/main.go:16
	tokenPath     = "/token"

	localRedirectBackURL  = "http://localhost:8888"
	localRedirectBackPath = "/callback"

	// client ID/Secret should generally not be hard-coded but instead be
	// taken from a config file, env vars, or similar sources.
	clientID     = "my-test-app"
	clientSecret = "123456"

	exampleScope = "photo api.read"
)

var (
	state  = generateState()
	client = &http.Client{Timeout: 3 * time.Second}
)

func main() {
	ctx, cf := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	defer cf()

	router := http.NewServeMux()

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		values := url.Values{}
		values.Add("response_type", "code")
		values.Add("client_id", clientID)
		values.Add("redirect_uri", localRedirectBackURL+localRedirectBackPath)
		values.Add("scope", exampleScope)
		values.Add("state", state)

		fmt.Fprint(w, "Please click here to authorize:<br><br>")
		fmt.Fprintf(w, `<a href="%s%s?%s">Authorize</a>`, authServerURL, authPath, values.Encode())
	})

	router.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		defer fmt.Fprintf(w, `<br><a href="%s">Back to start</a><br>`, localRedirectBackURL)
		queryState := r.URL.Query().Get("state")
		queryCode := r.URL.Query().Get("code")
		if queryState == "" || queryCode == "" {
			fmt.Fprint(w, "missing state and/or code parameter")
			return
		}

		if queryState != state {
			fmt.Fprint(w, "state parameter doesnt match")
			return
		}

		fmt.Print("state matches, continuing<br>")

		values := url.Values{}
		values.Add("grant_type", "authorization_code")
		values.Add("client_id", clientID)
		values.Add("client_secret", clientSecret)
		values.Add("code", queryCode)
		values.Add("redirect_uri", localRedirectBackURL+localRedirectBackPath)

		resp, err := client.PostForm(authServerURL+tokenPath, values)
		if err != nil {
			fmt.Fprint(w, "failed to send code exchange request:", err.Error())
			return
		}
		defer resp.Body.Close()

		data, err := io.ReadAll(r.Body)
		if err != nil {
			fmt.Fprint(w, "failed to read response body")
			return
		}

		fmt.Println("Raw response:", string(data))

		var res response
		if err = json.Unmarshal(data, &res); err != nil {
			fmt.Fprint(w, "failed to unmarshal JSON response:", err.Error())
			return
		}

		fmt.Fprintf(w, "Parsed response: %+v<br>", res)
	})

	srv := http.Server{
		Addr:         ":8888",
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  5 * time.Minute,
	}

	go func() {
		<-ctx.Done()

		shCtx, shCf := context.WithTimeout(context.Background(), 5*time.Second)
		defer shCf()
		if err := srv.Shutdown(shCtx); err != nil {
			fmt.Println("server shutdown error:", err.Error())
		}
	}()

	fmt.Println("starting server on port 8888...")
	srv.ListenAndServe()
}

func generateState() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
