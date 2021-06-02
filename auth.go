package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gxravel/auth/internal/db/user"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

const (
	bcryptCost = bcrypt.DefaultCost
)

func hashPassword(password string) (hashedPassword []byte, err error) {
	hashedPassword, err = bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		err = errors.WithStack(err)
	}
	return
}

func checkPasswordHash(password string, hashedPassword []byte) (err error) {
	return errors.WithStack(bcrypt.CompareHashAndPassword(hashedPassword, []byte(password)))
}

func validateUserCredentials(user *user.User, fullCheck bool) (err error) {
	var reg *regexp.Regexp
	if fullCheck {
		reg = regexp.MustCompile(`^(?i)[0-9a-z]{3,16}$`)
		if !reg.MatchString(user.Nickname) {
			err = errors.New("Invalid nickname: min length: 3, max length: 16, only latin and digits")
			return
		}
		reg = regexp.MustCompile(`^(?i)[a-zа-яё \'\-\.\,]*$`)
		if !reg.MatchString(user.Name) {
			err = errors.New("Invalid name")
			return
		}
	}
	reg = regexp.MustCompile(`^.{4,255}$`)
	if !reg.MatchString(user.Password) {
		err = errors.New("Invalid password: minimum length: 4")
		return
	}
	reg = regexp.MustCompile(`^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$`)
	if !reg.MatchString(user.Email) {
		err = errors.New("Invalid email")
		return
	}
	user.Email = strings.ToLower(user.Email)
	user.Nickname = strings.ToLower(user.Nickname)
	return
}

// signup is a handler that is responsible for signing up user.
func (env *environment) signup(w http.ResponseWriter, r *http.Request) (code int, err error) {
	var user *user.User
	err = json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		env.logger.Debug(err)
		code, err = http.StatusBadRequest, errors.Wrap(err, "failed to decode the request body")
		return
	}
	err = validateUserCredentials(user, true)
	if err != nil {
		env.logger.Debug(err)
		code = http.StatusBadRequest
		return
	}
	user.HashedPassword, err = hashPassword(user.Password)
	if err != nil {
		env.logger.Error(err)
		code = http.StatusInternalServerError
		return
	}
	user.UID, err = env.users.New(user)
	if err != nil {
		regexDuplicate := regexp.MustCompile(".*Duplicate.*(email|nickname).*")
		duplicate := regexDuplicate.FindStringSubmatch(err.Error())
		if len(duplicate) != 0 {
			env.logger.Info(err)
			code, err = http.StatusConflict, errors.New(fmt.Sprintf("The %s is already in use", duplicate[1]))
		} else {
			env.logger.Error(err)
			code, err = http.StatusInternalServerError, errors.WithStack(err)
		}
		return
	}
	data, err := env.token.Set(w, user)
	if err != nil {
		env.logger.Error(err)
		code = http.StatusInternalServerError
		return
	}
	code = http.StatusCreated
	sendJSON(w, code, &responseModel{Data: data})
	return
}

// login is a handler that is responsible for logging in user.
func (env *environment) login(w http.ResponseWriter, r *http.Request) (code int, err error) {
	var user *user.User
	err = json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		env.logger.Debug(err)
		code, err = http.StatusBadRequest, errors.Wrap(err, "failed to decode the request body")
		return
	}
	err = validateUserCredentials(user, false)
	if err != nil {
		env.logger.Debug(err)
		code = http.StatusBadRequest
		return
	}
	hashedPassword, err := env.users.GetHashedPassword(user.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			env.logger.Debug(err)
			code, err = http.StatusUnauthorized, errors.New("Wrong credentials")
		} else {
			env.logger.Error(err)
			code = http.StatusInternalServerError
		}
		return
	}
	err = checkPasswordHash(user.Password, hashedPassword)
	if err != nil {
		env.logger.Debug(err)
		code, err = http.StatusUnauthorized, errors.New("Wrong credentials")
		return
	}
	data, err := env.token.Set(w, user)
	if err != nil {
		env.logger.Error(err)
		code = http.StatusInternalServerError
		return
	}
	code = http.StatusOK
	sendJSON(w, code, &responseModel{Data: data})
	return
}

// refresh returns the token pair: access (body) and refresh (httpOnly cookie).
func (env *environment) refresh(w http.ResponseWriter, r *http.Request) (code int, err error) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		env.logger.Debug(err)
		code, err = http.StatusBadRequest, errors.New("failed to find the cookie")
		return
	}
	claims, err := env.token.Parse(cookie.Value, true)
	if err != nil {
		env.logger.Debug(err)
		code = http.StatusUnauthorized
		return
	}
	err = env.token.CheckIfExists(claims.Id)
	if err != nil {
		env.logger.Debug(err)
		code, err = http.StatusUnauthorized, errors.New("the token has been expired")
		return
	}
	env.token.Delete(claims.Id)
	user := &user.User{
		UID:      claims.Subject,
		Nickname: claims.Nickname,
		Role:     claims.Role,
	}
	data, err := env.token.Set(w, user)
	if err != nil {
		env.logger.Error(err)
		code = http.StatusInternalServerError
		return
	}
	code = http.StatusOK
	sendJSON(w, code, &responseModel{Data: data})
	return
}

// logout is a handler that is responsible for logging out user.
func (env *environment) logout(w http.ResponseWriter, r *http.Request) (code int, err error) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		env.logger.Debug(err)
		code, err = http.StatusBadRequest, errors.New("failed to find the cookie")
		return
	}
	claims, err := env.token.Parse(cookie.Value, true)
	if err != nil {
		env.logger.Debug(err)
		code = http.StatusUnauthorized
		return
	}
	err = env.token.Delete(claims.Id)
	if err != nil {
		env.logger.Error(err)
		err = nil
	}
	code = http.StatusNoContent
	w.WriteHeader(code)
	return
}
