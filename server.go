package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	domain := os.Getenv("AUTH0_DOMAIN")
	conf := &oauth2.Config{
		ClientID:     os.Getenv("AUTH0_CLIENT_ID"),
		ClientSecret: os.Getenv("AUTH0_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("AUTH0_CALLBACK_URL"),
		Scopes:       []string{"openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://" + domain + "/authorize",
			TokenURL: "https://" + domain + "/oauth/token",
		},
	}

	http.HandleFunc("/callback", func(rw http.ResponseWriter, r *http.Request) {

		code := r.URL.Query().Get("code")

		token, err := conf.Exchange(context.Background(), code)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		// Getting now the userInfo
		client := conf.Client(context.Background(), token)
		resp, err := client.Get("https://" + domain + "/userinfo")
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		var profile map[string]interface{}
		if err = json.NewDecoder(resp.Body).Decode(&profile); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		profile["auth0.token"] = token

		rw.Header().Set("Content-Type", "application/json")
		json.NewEncoder(rw).Encode(&profile)

	})

	http.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {

		v := url.Values{}
		v.Add("response_type", "code")
		v.Add("scope", "openid profile")
		v.Add("client_id", conf.ClientID)
		v.Add("redirect_uri", conf.RedirectURL)
		v.Add("connection", "google-oauth2")

		ru := conf.Endpoint.AuthURL + "?" + v.Encode()

		http.Redirect(rw, r, ru, http.StatusSeeOther)
	})

	err = http.ListenAndServe(":3000", nil)
	if err != nil {
		panic(err)
	}

}
