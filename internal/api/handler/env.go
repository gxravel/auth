package handler

import (
	"context"
	"os"

	"github.com/go-redis/redis/v8"
	"github.com/gxravel/auth/internal/conf"
	"github.com/gxravel/auth/internal/model/user"
	"github.com/gxravel/auth/pkg/jwt"
	log "github.com/sirupsen/logrus"
)

// Environment is set of options used in handlers.
type Environment struct {
	log   *log.Logger
	users user.Manager
	token jwt.Manager
}

func NewLogger() *log.Logger {
	logger := log.New()
	logger.SetFormatter(&log.JSONFormatter{})
	logger.SetLevel(log.DebugLevel)
	logFile, err := os.OpenFile("logs/logs.json", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal(err)
	}
	logger.SetOutput(logFile)
	// logger.SetReportCaller(true)
	return logger
}

func NewRedis(conf *conf.Configuration) *redis.Client {
	cli := redis.NewClient(&redis.Options{
		Addr: conf.RedisDSN,
	})
	ctx := context.Background()
	_, err := cli.Ping(ctx).Result()
	if err != nil {
		log.Fatal(err)
	}
	return cli
}

// NewEnvironment returns the Environment.
func NewEnvironment(log *log.Logger, users user.Manager, token jwt.Manager) *Environment {
	return &Environment{log: log, users: users, token: token}
}
