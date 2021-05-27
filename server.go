package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gxravel/auth/api"
	"github.com/gxravel/auth/conf"
	"github.com/gxravel/auth/utils"
)

var (
	allowedMethods = []string{"POST", "OPTIONS"}
	allowedHeaders = []string{"Accept", "Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization"}
)

func getCORSOptions(headers, origins, methods []string) (options []handlers.CORSOption) {
	options = make([]handlers.CORSOption, 4)
	options[0] = handlers.AllowedHeaders(headers)
	options[1] = handlers.AllowedOrigins(origins)
	options[2] = handlers.AllowedMethods(methods)
	options[3] = handlers.AllowCredentials()
	return
}

func main() {
	config := conf.Get()
	env, err := api.GetDefaultEnvironment(config.ConnectionString, config.RedisDSN)
	if err != nil {
		log.Fatal(err)
	}

	r := mux.NewRouter()
	s := r.PathPrefix("/api/" + utils.LastVersion).Subrouter()

	s.HandleFunc("/login", api.MakeHandler(env.Login)).Methods(http.MethodPost)
	s.HandleFunc("/signup", api.MakeHandler(env.Signup)).Methods(http.MethodPost, http.MethodOptions)
	s.HandleFunc("/refresh_token", api.MakeHandler(env.Refresh)).Methods(http.MethodPost)
	s.HandleFunc("/logout", api.MakeHandler(env.Logout)).Methods(http.MethodPost)

	allowedOrigins := strings.Split(config.AllowedOrigins, ", ")
	corsOptions := getCORSOptions(allowedHeaders, allowedOrigins, allowedMethods)

	address := fmt.Sprint(":", config.Port)
	handler := handlers.CORS(corsOptions...)(r)
	env.Logger.Fatal(http.ListenAndServe(address, handler))
}
