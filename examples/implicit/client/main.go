package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
)

//go:embed auth.gohtml
var authTemplate string

func main() {

	authServer := "http://localhost:7777/authorize"
	callback := "http://localhost:8888/callback"
	clientID := "00000"
	state := generateToken()
	fmt.Println("State:", state)

	params := url.Values{}
	params.Add("client_id", clientID)
	params.Add("scope", "api.read api.write profile")
	params.Add("redirect_uri", url.QueryEscape(callback))
	params.Add("response_type", "token")
	params.Add("response_mode", "fragment")
	params.Add("state", state)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, template.HTML(fmt.Sprintf(`<a href="%s?%s">Log in</a>`, authServer, params.Encode())))
	})

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.New("").Parse(authTemplate)
		if err != nil {
			fmt.Println("template parse error:", err.Error())
			return
		}

		err = tmpl.Execute(w, struct{ State string }{State: state})
		if err != nil {
			fmt.Println("template execute error:", err.Error())
		}
	})

	fmt.Println("listening on :8888...")
	log.Fatal(http.ListenAndServe("localhost:8888", nil))

	// authServer := "http://localhost:7777/authorize"
	// callback := "http://localhost"
	// clientID := "00000"
	// state := generateToken()
	// // Secret not needed for implicit flow
	// //clientSecret := "99999"

	// cl := &http.Client{Timeout: 5 * time.Second}
	// req, _ := http.NewRequest(http.MethodGet, authServer, nil)

	// params := url.Values{}
	// params.Add("client_id", clientID)
	// params.Add("scope", "api.read api.write profile")
	// params.Add("redirect_uri", url.QueryEscape(callback))
	// params.Add("response_type", "token")
	// params.Add("response_form", "fragment")
	// params.Add("state", state)

	// req.URL.RawQuery = params.Encode()

	// resp, err := cl.Do(req)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer resp.Body.Close()

	// body, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// fmt.Println("Raw Query:", resp.Request.URL.RawQuery)
	// fmt.Println("Raw Fragment:", resp.Request.URL.RawFragment)
	// fmt.Println("Escaped Fragment:", resp.Request.URL.EscapedFragment())
	// fmt.Printf("Body: %s\n", body)
}

func generateToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
