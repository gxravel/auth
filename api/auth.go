package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gxravel/auth/db"
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

func validateUserCredentials(user *db.User, fullCheck bool) (err error) {
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

// Signup is a handler that is responsible for signing up user
func (env *Environment) Signup(w http.ResponseWriter, r *http.Request) (code int, err error) {
	var user *db.User
	err = json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		env.Logger.Debug(err)
		code, err = http.StatusBadRequest, errors.Wrap(err, "failed to decode the request body")
		return
	}
	err = validateUserCredentials(user, true)
	if err != nil {
		env.Logger.Debug(err)
		code = http.StatusBadRequest
		return
	}
	user.HashedPassword, err = hashPassword(user.Password)
	if err != nil {
		env.Logger.Error(err)
		code = http.StatusInternalServerError
		return
	}
	user.UID, err = env.Users.New(user)
	if err != nil {
		regexDuplicate := regexp.MustCompile(".*Duplicate.*(email|nickname).*")
		duplicate := regexDuplicate.FindStringSubmatch(err.Error())
		if len(duplicate) != 0 {
			env.Logger.Info(err)
			code, err = http.StatusConflict, errors.New(fmt.Sprintf("The %s is already in use", duplicate[1]))
		} else {
			env.Logger.Error(err)
			code, err = http.StatusInternalServerError, errors.WithStack(err)
		}
		return
	}
	data, err := env.Token.Set(w, user)
	if err != nil {
		env.Logger.Error(err)
		code = http.StatusInternalServerError
		return
	}
	code = http.StatusCreated
	sendJSON(w, code, &ResponseModel{Data: data})
	return
}

// Login is a handler that is responsible for logging in user
func (env *Environment) Login(w http.ResponseWriter, r *http.Request) (code int, err error) {
	var user *db.User
	err = json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		env.Logger.Debug(err)
		code, err = http.StatusBadRequest, errors.Wrap(err, "failed to decode the request body")
		return
	}
	err = validateUserCredentials(user, false)
	if err != nil {
		env.Logger.Debug(err)
		code = http.StatusBadRequest
		return
	}
	hashedPassword, err := env.Users.GetHashedPassword(user.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			env.Logger.Debug(err)
			code, err = http.StatusUnauthorized, errors.New("Wrong credentials")
		} else {
			env.Logger.Error(err)
			code = http.StatusInternalServerError
		}
		return
	}
	err = checkPasswordHash(user.Password, hashedPassword)
	if err != nil {
		env.Logger.Debug(err)
		code, err = http.StatusUnauthorized, errors.New("Wrong credentials")
		return
	}
	data, err := env.Token.Set(w, user)
	if err != nil {
		env.Logger.Error(err)
		code = http.StatusInternalServerError
		return
	}
	code = http.StatusOK
	sendJSON(w, code, &ResponseModel{Data: data})
	return
}

// Refresh returns the token pair: access (body) and refresh (httpOnly cookie)
func (env *Environment) Refresh(w http.ResponseWriter, r *http.Request) (code int, err error) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		env.Logger.Debug(err)
		code, err = http.StatusBadRequest, errors.New("failed to find the cookie")
		return
	}
	claims, err := env.Token.Parse(cookie.Value, true)
	if err != nil {
		env.Logger.Debug(err)
		code = http.StatusUnauthorized
		return
	}
	err = env.Token.CheckIfExists(claims.Id)
	if err != nil {
		env.Logger.Debug(err)
		code, err = http.StatusUnauthorized, errors.New("the token has been expired")
		return
	}
	env.Token.Delete(claims.Id)
	user := &db.User{
		UID:      claims.Subject,
		Nickname: claims.Nickname,
		Role:     claims.Role,
	}
	data, err := env.Token.Set(w, user)
	if err != nil {
		env.Logger.Error(err)
		code = http.StatusInternalServerError
		return
	}
	code = http.StatusOK
	sendJSON(w, code, &ResponseModel{Data: data})
	return
}

// Logout is a handler that is responsible for logging out user
func (env *Environment) Logout(w http.ResponseWriter, r *http.Request) (code int, err error) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		env.Logger.Debug(err)
		code, err = http.StatusBadRequest, errors.New("failed to find the cookie")
		return
	}
	claims, err := env.Token.Parse(cookie.Value, true)
	if err != nil {
		env.Logger.Debug(err)
		code = http.StatusUnauthorized
		return
	}
	err = env.Token.Delete(claims.Id)
	if err != nil {
		env.Logger.Error(err)
		err = nil
	}
	code = http.StatusNoContent
	w.WriteHeader(code)
	return
}
