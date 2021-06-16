package db

import (
	"database/sql"
	"log"
	"time"

	"github.com/gxravel/auth/internal/conf"
)

const (
	connMaxLifeTime = time.Minute * 5
	maxOpenConns    = 30
	maxIdleConns    = maxOpenConns
)

// New opens a database and configures it with default settings.
func New(conf *conf.Configuration) *sql.DB {
	db, err := sql.Open(conf.SQLDriver, conf.ConnectionString+"/"+conf.DBName)
	if err != nil {
		log.Fatal(err)
	}

	db.SetConnMaxLifetime(connMaxLifeTime)
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)

	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}
	return db
}
