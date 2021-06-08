package user_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	. "github.com/gxravel/auth/internal/db/user"

	_ "github.com/go-sql-driver/mysql"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestNew(t *testing.T) {
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "mysql:latest",
		ExposedPorts: []string{"3306/tcp"},
		Env: map[string]string{
			"MYSQL_ROOT_PASSWORD": "root",
			"MYSQL_DATABASE":      "auth",
		},
		WaitingFor: wait.ForLog("MySQL init process done. Ready for start up."),
	}
	mysqlC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mysqlC.Terminate(ctx)
	endpoint, err := mysqlC.Endpoint(ctx, "")
	if err != nil {
		t.Error(err)
	}
	time.Sleep(1 * time.Second)

	connString := "root:root@tcp(" + endpoint + ")/auth"
	db, err := sql.Open("mysql", connString)
	if err != nil {
		t.Error(err)
	}
	err = db.Ping()
	if err != nil {
		t.Error(err)
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS user (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    uid binary(16) not null unique default (uuid_to_bin(uuid())),
    name VARCHAR(255),
    nickname VARCHAR(20) UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    hashed_password varbinary(255) NOT NULL,
    role TINYINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE
);`)
	if err != nil {
		t.Error(err)
	}
	w := New(db)
	user := &User{Email: "i_email@asd.ru", HashedPassword: []byte("hashed-password")}
	_, err = w.New(user)
	if err != nil {
		t.Error(err)
	}
}
