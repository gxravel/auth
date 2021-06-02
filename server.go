package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gxravel/auth/internal/conf"
	"github.com/gxravel/auth/internal/db"
	"github.com/gxravel/auth/internal/db/user"
	"github.com/gxravel/auth/pkg/goconst"
	"github.com/gxravel/auth/pkg/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	_ "github.com/go-sql-driver/mysql"
)

const (
	driver   = "mysql"
	logsPath = "logs/logs.json"
	dbName   = "auth"
)

var (
	allowedMethods = []string{"POST", "OPTIONS"}
	allowedHeaders = []string{"Accept", "Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization"}
)

// Environment is set of options used in handlers
type Environment struct {
	Logger *log.Logger
	Users  user.Manager
	Token  jwt.Manager
}

// ResponseModel is JSON model of a response
type ResponseModel struct {
	Data  map[string]interface{} `json:"data,omitempty"`
	Error *ErrorModel            `json:"error,omitempty"`
}

// ErrorModel is JSON model of an error response
type ErrorModel struct {
	Message string `json:"msg,omitempty"`
}

type stackTracer interface {
	StackTrace() errors.StackTrace
}

// makeHandler creates http.HandlerFunc out of the customHandler that manages the request
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

// getDefaultEnvironment returns the default Environment
func getDefaultEnvironment(connectionString, redisDSN string) (env *Environment, err error) {
	logger := log.New()
	logger.SetFormatter(&log.JSONFormatter{})
	logger.SetLevel(log.DebugLevel)
	logFile, err := os.OpenFile(logsPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return
	}
	logger.SetOutput(logFile)
	// logger.SetReportCaller(true)

	connectionString = connectionString + "/" + dbName
	myDB, err := db.Init(driver, connectionString)
	if err != nil {
		return
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr: redisDSN,
	})
	ctx := context.Background()
	_, err = redisClient.Ping(ctx).Result()
	if err != nil {
		return
	}

	jwtConfig := conf.GetJWT()

	jwtEnv := &jwt.Environment{}
	jwtEnv.Init(redisClient, ctx, jwtConfig)

	env = &Environment{Logger: logger, Users: user.New(myDB), Token: jwtEnv}
	return
}

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
	env, err := getDefaultEnvironment(config.ConnectionString, config.RedisDSN)
	if err != nil {
		log.Fatal(err)
	}

	r := mux.NewRouter()
	s := r.PathPrefix("/api/" + goconst.APIVersion).Subrouter()

	s.HandleFunc("/login", makeHandler(env.Login)).Methods(http.MethodPost)
	s.HandleFunc("/signup", makeHandler(env.Signup)).Methods(http.MethodPost)
	s.HandleFunc("/refresh_token", makeHandler(env.Refresh)).Methods(http.MethodPost)
	s.HandleFunc("/logout", makeHandler(env.Logout)).Methods(http.MethodPost)

	allowedOrigins := strings.Split(config.AllowedOrigins, ", ")
	corsOptions := getCORSOptions(allowedHeaders, allowedOrigins, allowedMethods)

	address := fmt.Sprint(":", config.Port)
	handler := handlers.CORS(corsOptions...)(r)
	env.Logger.Fatal(http.ListenAndServe(address, handler))
}

func sendError(w http.ResponseWriter, code int, message string) {
	response := &ResponseModel{Error: &ErrorModel{Message: message}}
	sendJSON(w, code, response)
}

func sendJSON(w http.ResponseWriter, code int, response *ResponseModel) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		code = http.StatusInternalServerError
		http.Error(w, http.StatusText(http.StatusInternalServerError), code)
	}
}
