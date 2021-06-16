package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gxravel/auth/internal/conf"
	"github.com/gxravel/auth/pkg/goconst"
	"github.com/pkg/errors"
	"go.uber.org/fx"
)

var (
	allowedMethods = []string{"POST", "OPTIONS"}
	allowedHeaders = []string{"Accept", "Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization"}
)

// responseModel is JSON model of a response.
type responseModel struct {
	Data  map[string]interface{} `json:"data,omitempty"`
	Error *errorModel            `json:"error,omitempty"`
}

// errorModel is JSON model of an error response.
type errorModel struct {
	Message string `json:"msg,omitempty"`
}

type stackTracer interface {
	StackTrace() errors.StackTrace
}

// makeHandler creates http.HandlerFunc out of the customHandler that manages the request.
func makeHandler(customHandler func(http.ResponseWriter, *http.Request) (int, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			return
		}
		code, err := customHandler(w, r)
		if err != nil {
			if stErr, ok := err.(stackTracer); ok {
				st := stErr.StackTrace()
				fmt.Fprintf(os.Stderr, "%v\n%+v\n\n", err, st[0:2])
			} else {
				fmt.Fprintf(os.Stderr, "%v\n", err)
			}
			if code >= http.StatusInternalServerError {
				w.WriteHeader(code)
				return
			}
			sendError(w, code, err.Error())
		}
	}
}

func getCORSOptions(headers, origins, methods []string) (options []handlers.CORSOption) {
	options = make([]handlers.CORSOption, 4)
	options[0] = handlers.AllowedHeaders(headers)
	options[1] = handlers.AllowedOrigins(origins)
	options[2] = handlers.AllowedMethods(methods)
	options[3] = handlers.AllowCredentials()
	return
}

func NewServer(env *Environment, config *conf.Configuration) *http.Server {
	r := mux.NewRouter()
	s := r.PathPrefix("/api/" + goconst.APIVersion).Subrouter()

	s.HandleFunc("/login", makeHandler(env.login)).Methods(http.MethodPost)
	s.HandleFunc("/signup", makeHandler(env.signup)).Methods(http.MethodPost)
	s.HandleFunc("/refresh_token", makeHandler(env.refresh)).Methods(http.MethodPost)
	s.HandleFunc("/logout", makeHandler(env.logout)).Methods(http.MethodPost)

	allowedOrigins := strings.Split(config.AllowedOrigins, ", ")
	corsOptions := getCORSOptions(allowedHeaders, allowedOrigins, allowedMethods)

	handler := handlers.CORS(corsOptions...)(r)
	address := fmt.Sprint(":", config.Port)

	srv := &http.Server{
		Addr:    address,
		Handler: handler,
	}
	return srv
}

type RegisterParams struct {
	fx.In

	Lifecycle fx.Lifecycle
	DB        *sql.DB
	Redis     *redis.Client
	Env       *Environment
	Srv       *http.Server
}

func Register(p RegisterParams) {
	p.Lifecycle.Append(
		fx.Hook{
			OnStart: func(c context.Context) error {
				go func() {
					if err := p.Srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
						p.Env.log.Fatalf("HTTP server shutdown: %v", err)
					}
				}()

				return nil
			},
			OnStop: func(c context.Context) error {
				p.DB.Close()
				p.Redis.Close()
				return nil
			},
		},
	)
}

func sendError(w http.ResponseWriter, code int, message string) {
	response := &responseModel{Error: &errorModel{Message: message}}
	sendJSON(w, code, response)
}

func sendJSON(w http.ResponseWriter, code int, response *responseModel) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		code = http.StatusInternalServerError
		http.Error(w, http.StatusText(http.StatusInternalServerError), code)
	}
}
