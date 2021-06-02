package user

import "database/sql"

// User is a database model of users.
type User struct {
	UID            string `json:"uid,omitempty"`
	Name           string `json:"name,omitempty"`
	Nickname       string `json:"nickname"`
	Email          string `json:"email"`
	Password       string `json:"password"`
	HashedPassword []byte
	Role           int8 `json:"role,omitempty"`
}

// Users describes methods associated with users.
type Users interface {
	All() (users []User, err error)
	New(user *User) (uid string, err error)
	GetHashedPassword(uid string) (hashedPassword []byte, err error)
}

// UserModel wraps the sql.DB connection pool over users.
type UserModel struct {
	DB *sql.DB
}

// All returns all users. TODO
func (m UserModel) All() (users []User, err error) { return }

// New creates new user and returns it's id.
func (m UserModel) New(user *User) (uid string, err error) {
	tx, err := m.DB.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	res, err := tx.Exec(`insert into user(name, nickname, email, hashed_password) values(?, ?, ?, ?)`,
		user.Name, user.Nickname, user.Email, user.HashedPassword)
	if err != nil {
		return
	}
	id, err := res.LastInsertId()
	if err != nil {
		return
	}
	err = tx.QueryRow(`select bin_to_uuid(uid) from user where id = ?`, id).Scan(&uid)
	if err != nil {
		return
	}
	err = tx.Commit()
	return
}

// GetHashedPassword returns hashed password of the user with specified uuid
func (m UserModel) GetHashedPassword(uid string) (hashedPassword []byte, err error) {
	err = m.DB.QueryRow(`select hashed_password from user where email=?`, uid).Scan(&hashedPassword)
	return
}
