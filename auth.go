package main

import (
	"context"
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

var (
	regDuplicate = regexp.MustCompile(".*Duplicate.*(email|nickname).*")
	regNickname  = regexp.MustCompile(`^(?i)[0-9a-z]{3,16}$`)
	regName      = regexp.MustCompile(`^(?i)[a-zа-яё \'\-\.\,]*$`)
	regPass      = regexp.MustCompile(`^.{4,255}$`)
	regEmail     = regexp.MustCompile(`^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$`)
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
	if fullCheck {
		if !regNickname.MatchString(user.Nickname) {
			err = errors.New("invalid nickname: min length - 3, max length - 16, only latin and digits")
			return
		}
		if !regName.MatchString(user.Name) {
			err = errors.New("invalid name")
			return
		}
	}
	if !regPass.MatchString(user.Password) {
		err = errors.New("invalid password: min length - 4")
		return
	}
	if !regEmail.MatchString(user.Email) {
		err = errors.New("invalid email")
		return
	}
	user.Email = strings.ToLower(user.Email)
	user.Nickname = strings.ToLower(user.Nickname)
	return
}

// signup is a handler that is responsible for signing up user.
func (e *environment) signup(w http.ResponseWriter, r *http.Request) (code int, err error) {
	var user *user.User
	err = json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		e.log.Debug(err)
		code, err = http.StatusBadRequest, errors.Wrap(err, "failed to decode the request body")
		return
	}
	err = validateUserCredentials(user, true)
	if err != nil {
		e.log.Debug(err)
		code = http.StatusBadRequest
		return
	}
	user.HashedPassword, err = hashPassword(user.Password)
	if err != nil {
		e.log.Error(err)
		code = http.StatusInternalServerError
		return
	}
	user.UID, err = e.users.New(user)
	if err != nil {
		duplicate := regDuplicate.FindStringSubmatch(err.Error())
		if len(duplicate) != 0 {
			e.log.Info(err)
			code, err = http.StatusConflict, errors.New(fmt.Sprintf("the %s is already in use", duplicate[1]))
		} else {
			e.log.Error(err)
			code, err = http.StatusInternalServerError, errors.WithStack(err)
		}
		return
	}
	ctx := context.Background()
	data, err := e.token.Set(ctx, w, user)
	if err != nil {
		e.log.Error(err)
		code = http.StatusInternalServerError
		return
	}
	code = http.StatusCreated
	sendJSON(w, code, &responseModel{Data: data})
	return
}

// login is a handler that is responsible for logging in user.
func (e *environment) login(w http.ResponseWriter, r *http.Request) (code int, err error) {
	var user *user.User
	err = json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		e.log.Debug(err)
		code, err = http.StatusBadRequest, errors.Wrap(err, "failed to decode the request body")
		return
	}
	err = validateUserCredentials(user, false)
	if err != nil {
		e.log.Debug(err)
		code = http.StatusBadRequest
		return
	}
	hashedPassword, err := e.users.GetHashedPassword(user.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			e.log.Debug(err)
			code, err = http.StatusUnauthorized, errors.New("wrong credentials")
		} else {
			e.log.Error(err)
			code = http.StatusInternalServerError
		}
		return
	}
	err = checkPasswordHash(user.Password, hashedPassword)
	if err != nil {
		e.log.Debug(err)
		code, err = http.StatusUnauthorized, errors.New("wrong credentials")
		return
	}
	ctx := context.Background()
	data, err := e.token.Set(ctx, w, user)
	if err != nil {
		e.log.Error(err)
		code = http.StatusInternalServerError
		return
	}
	code = http.StatusOK
	sendJSON(w, code, &responseModel{Data: data})
	return
}

// refresh returns the token pair: access (body) and refresh (httpOnly cookie).
func (e *environment) refresh(w http.ResponseWriter, r *http.Request) (code int, err error) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		e.log.Debug(err)
		code, err = http.StatusBadRequest, errors.New("failed to find the cookie")
		return
	}
	claims, err := e.token.Parse(cookie.Value, true)
	if err != nil {
		e.log.Debug(err)
		code = http.StatusUnauthorized
		return
	}
	ctx := context.Background()
	err = e.token.CheckIfExists(ctx, claims.Id)
	if err != nil {
		e.log.Debug(err)
		code, err = http.StatusUnauthorized, errors.New("the token has been expired")
		return
	}
	e.token.Delete(ctx, claims.Id)
	user := &user.User{
		UID:      claims.Subject,
		Nickname: claims.Nickname,
		Role:     claims.Role,
	}
	data, err := e.token.Set(ctx, w, user)
	if err != nil {
		e.log.Error(err)
		code = http.StatusInternalServerError
		return
	}
	code = http.StatusOK
	sendJSON(w, code, &responseModel{Data: data})
	return
}

// logout is a handler that is responsible for logging out user.
func (e *environment) logout(w http.ResponseWriter, r *http.Request) (code int, err error) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		e.log.Debug(err)
		code, err = http.StatusBadRequest, errors.New("failed to find the cookie")
		return
	}
	claims, err := e.token.Parse(cookie.Value, true)
	if err != nil {
		e.log.Debug(err)
		code = http.StatusUnauthorized
		return
	}
	ctx := context.Background()
	err = e.token.Delete(ctx, claims.Id)
	if err != nil {
		e.log.Error(err)
		err = nil
	}
	code = http.StatusNoContent
	w.WriteHeader(code)
	return
}
