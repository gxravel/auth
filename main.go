package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/gxravel/auth/database"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/tkanos/gonfig"

	_ "github.com/go-sql-driver/mysql"
)

// Configuration contains the environment variables
type Configuration struct {
	Domain           string `env:"DOMAIN"`
	Port             int    `env:"PORT"`
	ConnectionString string `env:"CONNECTION_STRING"`
	JWTAccess        string `env:"JWT_ACCESS"`
	JWTRefresh       string `env:"JWT_REFRESH"`
	RedisDSN         string `env:"REDIS_DSN"`
}

// Environment is set of options in which the server handles a request
type Environment struct {
	Logger      *log.Logger
	RedisClient *redis.Client
	Users       database.Users
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

const (
	driver   = "mysql"
	logsPath = "logs/logs.json"
)

var (
	config Configuration
)

func getConfigPath() string {
	env := os.Getenv("ENV")
	if len(env) == 0 {
		env = "development"
	}
	filename := []string{"config/", "config.", env, ".json"}
	_, dirname, _, _ := runtime.Caller(0)
	filePath := path.Join(filepath.Dir(dirname), strings.Join(filename, ""))

	return filePath
}

func makeHandler(customHandler func(http.ResponseWriter, *http.Request) (int, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code, err := customHandler(w, r)
		if err != nil {
			if stErr, ok := err.(stackTracer); ok {
				st := stErr.StackTrace()
				fmt.Fprintf(os.Stderr, "%v\n%+v\n", err, st[0:3])
			} else {
				fmt.Fprintf(os.Stderr, "%v\n", err)
			}
			if code >= http.StatusInternalServerError {
				w.WriteHeader(code)
				return
			}
			response := ResponseModel{Error: &ErrorModel{Message: err.Error()}}
			sendJSON(w, code, response)
		}
		return
	}
}

func handleError(code *int, err *error, status int, msg string) {
	*code = status
	if msg != "" {
		*err = errors.New(msg)
	}
}

func sendJSON(w http.ResponseWriter, code int, response ResponseModel) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	err := json.NewEncoder(w).Encode(&response)
	if err != nil {
		code = http.StatusInternalServerError
		http.Error(w, internalError, code)
	}
}

func main() {
	config = Configuration{}
	err := gonfig.GetConf(getConfigPath(), &config)
	if err != nil {
		log.Fatal(err)
	}

	logger := log.New()
	logger.SetFormatter(&log.JSONFormatter{})
	logger.SetLevel(log.DebugLevel)
	logFile, err := os.OpenFile(logsPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	logger.SetOutput(logFile)
	// logger.SetReportCaller(true)

	db, err := database.Init(driver, config.ConnectionString)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	redisClient := redis.NewClient(&redis.Options{
		Addr: config.RedisDSN,
	})
	ctx := context.Background()
	_, err = redisClient.Ping(ctx).Result()
	if err != nil {
		log.Fatal(err)
		return
	}
	defer redisClient.Close()

	env := &Environment{Logger: logger, Users: database.UserModel{DB: db}, RedisClient: redisClient}

	r := mux.NewRouter()
	api := r.PathPrefix("/auth/v1").Subrouter()
	api.HandleFunc("/signin", makeHandler(env.signin)).Methods(http.MethodPost)
	api.HandleFunc("/signup", makeHandler(env.signup)).Methods(http.MethodPost)
	api.HandleFunc("/refresh_token", makeHandler(env.refresh)).Methods(http.MethodPost)
	api.HandleFunc("/signout", makeHandler(env.signout)).Methods(http.MethodPost)

	log.Fatal(http.ListenAndServe(fmt.Sprint(":", config.Port), r))
}
