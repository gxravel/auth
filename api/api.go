package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/gxravel/auth/conf"
	"github.com/gxravel/auth/db"
	"github.com/gxravel/auth/utils"
	"github.com/gxravel/auth/utils/jwt"

	_ "github.com/go-sql-driver/mysql"
)

const (
	driver   = "mysql"
	logsPath = "logs/logs.json"
	dbName   = "auth"
)

// Environment is set of options used in handlers
type Environment struct {
	Logger *log.Logger
	Users  db.Users
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

func configureHeader(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", strings.Join(utils.AllowedOrigins, ", "))
	w.Header().Set("Access-Control-Allow-Methods", strings.Join(utils.AllowedMethods, ", "))
	w.Header().Set("Access-Control-Allow-Headers", strings.Join(utils.AllowedHeaders, ", "))
}

// MakeHandler creates http.HandlerFunc out of the customHandler that manages the request
func MakeHandler(customHandler func(http.ResponseWriter, *http.Request) (int, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		configureHeader(w)
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

// GetDefaultEnvironment returns the default Environment
func GetDefaultEnvironment(connectionString, redisDSN string) (env *Environment, err error) {
	logger := log.New()
	logger.SetFormatter(&log.JSONFormatter{})
	logger.SetLevel(log.DebugLevel)
	logFile, err := os.OpenFile(logsPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return
	}
	defer logFile.Close()
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

	env = &Environment{Logger: logger, Users: db.UserModel{DB: myDB}, Token: jwtEnv}
	return
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
