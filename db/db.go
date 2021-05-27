package db

import (
	"database/sql"
	"time"
)

const (
	connMaxLifeTime = time.Minute * 5
	maxOpenConns    = 30
	maxIdleConns    = maxOpenConns
)

// Init opens a database and configures it with default settings.
func Init(driver string, connectionString string) (db *sql.DB, err error) {
	db, err = sql.Open(driver, connectionString)
	if err != nil {
		return
	}

	db.SetConnMaxLifetime(connMaxLifeTime)
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)

	err = db.Ping()
	return
}
