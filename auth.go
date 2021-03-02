package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	"github.com/gxravel/auth/database"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	bcryptCost         = bcrypt.DefaultCost
	accessTokenExpiry  = 15 // Minutes
	refreshTokenExpiry = 7 /* Days */ * 24 * 60
)

var (
	internalError = http.StatusText(http.StatusInternalServerError)
)

// Claims defines JWT token claims
type Claims struct {
	Nickname string `json:"nickname"`
	Role     int8   `json:"role"`
	jwt.StandardClaims
}

// TokenDetails defines structure of a JWT token
type TokenDetails struct {
	String  string
	Expiry  int64
	UUID    string
	Subject string
}

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

func validateUserCredentials(user *database.User, fullCheck bool) (err error) {
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
	reg = regexp.MustCompile(`^[\S]{4,255}$`)
	if !reg.MatchString(user.Password) {
		err = errors.New("Invalid password: minimum length: 4, no spaces")
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

func createToken(user *database.User, expiry time.Duration) (token *TokenDetails, err error) {
	now := time.Now()
	token = &TokenDetails{}
	token.Expiry = now.Add(time.Minute * expiry).Unix()
	claims := &Claims{
		Nickname: user.Nickname,
		Role:     user.Role,
		StandardClaims: jwt.StandardClaims{
			Subject:   user.UID,
			ExpiresAt: token.Expiry,
		},
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	token.String, err = jwtToken.SignedString([]byte(config.JWTRefresh))
	if err != nil {
		err = errors.WithStack(err)
	}
	return
}

func parseToken(tokenString string, key []byte) (claims *Claims, err error) {
	jwtToken, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	if !jwtToken.Valid {
		return nil, errors.New("Invalid token")
	}
	var ok bool
	if *claims, ok = jwtToken.Claims.(Claims); !ok {
		return nil, errors.New("Invalid token claims")
	}
	return
}

func saveToken(ctx context.Context, client *redis.Client, token *TokenDetails) (err error) {
	hashedUUID, err := hashPassword(token.UUID)
	if err != nil {
		return
	}
	expiry := time.Unix(token.Expiry, 0).Sub(time.Now())
	err = errors.WithStack(client.Set(ctx, string(hashedUUID), token.Subject, expiry).Err())
	return
}

func setCookie(w http.ResponseWriter, refreshToken *TokenDetails) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken.String,
		Expires:  time.Unix(refreshTokenExpiry, 0),
		Secure:   true,
		HttpOnly: true,
	})
}

func setTokens(w http.ResponseWriter, user *database.User, redisClient *redis.Client) (data map[string]interface{}, err error) {
	accessToken, err := createToken(user, accessTokenExpiry)
	if err != nil {
		return
	}
	refreshToken, err := createToken(user, refreshTokenExpiry)
	if err != nil {
		return
	}
	refreshToken.Subject = user.UID
	refreshToken.UUID = uuid.NewV4().String()
	ctx := context.Background()
	err = saveToken(ctx, redisClient, refreshToken)
	if err != nil {
		return
	}
	data = map[string]interface{}{
		"access_token":        accessToken.String,
		"access_token_expiry": accessToken.Expiry}
	setCookie(w, refreshToken)
	return
}

func checkIfTokenExists(ctx context.Context, redisClient *redis.Client, tokenUUID string) (err error) {
	hashedUUID, err := hashPassword(tokenUUID)
	if err != nil {
		return
	}
	err = errors.WithStack(redisClient.Get(ctx, string(hashedUUID)).Err())
	return
}

func deleteToken(ctx context.Context, redisClient *redis.Client, tokenUUID string) (err error) {
	hashedUUID, err := hashPassword(tokenUUID)
	if err != nil {
		return
	}
	err = errors.WithStack(redisClient.Del(ctx, string(hashedUUID)).Err())
	return
}

func (env *Environment) signup(w http.ResponseWriter, r *http.Request) (code int, err error) {
	var user *database.User
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
	data, err := setTokens(w, user, env.RedisClient)
	if err != nil {
		env.Logger.Error(err)
		code = http.StatusInternalServerError
		return
	}
	code = http.StatusCreated
	sendJSON(w, code, ResponseModel{Data: data})
	return
}

func (env *Environment) signin(w http.ResponseWriter, r *http.Request) (code int, err error) {
	var user *database.User
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
	data, err := setTokens(w, user, env.RedisClient)
	if err != nil {
		env.Logger.Error(err)
		code = http.StatusInternalServerError
		return
	}
	code = http.StatusOK
	sendJSON(w, code, ResponseModel{Data: data})
	return
}

func (env *Environment) refresh(w http.ResponseWriter, r *http.Request) (code int, err error) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		env.Logger.Debug(err)
		code, err = http.StatusBadRequest, errors.New("failed to find the cookie")
		return
	}
	claims, err := parseToken(cookie.Value, []byte(config.JWTRefresh))
	if err != nil {
		env.Logger.Debug(err)
		code, err = http.StatusUnauthorized, errors.New("the token is not valid")
		return
	}
	ctx := context.Background()
	err = checkIfTokenExists(ctx, env.RedisClient, claims.Id)
	if err != nil {
		env.Logger.Debug(err)
		code, err = http.StatusUnauthorized, errors.New("the token has been expired")
		return
	}
	user := &database.User{
		UID:      claims.Subject,
		Nickname: claims.Nickname,
		Role:     claims.Role,
	}
	data, err := setTokens(w, user, env.RedisClient)
	if err != nil {
		env.Logger.Error(err)
		code = http.StatusInternalServerError
		return
	}
	code = http.StatusOK
	sendJSON(w, code, ResponseModel{Data: data})
	return
}

func (env *Environment) signout(w http.ResponseWriter, r *http.Request) (code int, err error) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		env.Logger.Debug(err)
		code, err = http.StatusBadRequest, errors.New("failed to find the cookie")
		return
	}
	claims, err := parseToken(cookie.Value, []byte(config.JWTRefresh))
	if err != nil {
		env.Logger.Debug(err)
		code, err = http.StatusUnauthorized, errors.New("the token is not valid")
		return
	}
	ctx := context.Background()
	err = deleteToken(ctx, env.RedisClient, claims.Id)
	if err != nil {
		env.Logger.Error(err)
		err = nil
	}
	code = http.StatusNoContent
	w.WriteHeader(code)
	return
}
