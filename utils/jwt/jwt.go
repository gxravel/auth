package jwt

import (
	"context"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"

	"github.com/gxravel/auth/conf"
	"github.com/gxravel/auth/db"
	"github.com/gxravel/auth/utils"
)

const (
	accessTokenExpiry  = time.Minute * 15
	refreshTokenExpiry = time.Hour * 24 * 7
)

// Claims defines JWT token claims
type Claims struct {
	Nickname string `json:"nickname,omitempty"`
	Role     int8   `json:"role,omitempty"`
	Scope    string `json:"scope"`
	jwt.StandardClaims
}

// Details defines structure of a JWT token
type Details struct {
	String  string
	Expiry  int64
	UUID    string
	Subject string
}

type Manager interface {
	Init(client *redis.Client, ctx context.Context, config *conf.JWTConfiguration)
	Parse(tokenString string, isRefresh bool) (claims *Claims, err error)
	save(token *Details) (err error)
	CheckIfExists(tokenUUID string) (err error)
	Delete(tokenUUID string) (err error)
	Set(w http.ResponseWriter, user *db.User) (data map[string]interface{}, err error)
}

type Environment struct {
	client *redis.Client
	ctx    context.Context
	config *conf.JWTConfiguration
}

func (env *Environment) Init(client *redis.Client, ctx context.Context, config *conf.JWTConfiguration) {
	env.client = client
	env.ctx = ctx
	env.config = config
}

// create creates the HS512 jwt token with claims
func create(user *db.User, expiry time.Duration, key string) (token *Details, err error) {
	now := time.Now()
	token = &Details{}
	token.Expiry = now.Add(expiry).Unix()
	claims := &Claims{
		Nickname: user.Nickname,
		Role:     user.Role,
		StandardClaims: jwt.StandardClaims{
			Id:        uuid.NewV4().String(),
			Subject:   user.UID,
			IssuedAt:  now.Unix(),
			ExpiresAt: token.Expiry,
		},
	}
	token.UUID = claims.Id
	token.Subject = user.UID
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	token.String, err = jwtToken.SignedString([]byte(key))
	if err != nil {
		err = errors.WithStack(err)
	}
	return
}

// Parse parses a string token with the key
func (env *Environment) Parse(tokenString string, isRefresh bool) (claims *Claims, err error) {
	var key []byte
	if isRefresh {
		key = []byte(env.config.JWTRefresh)
	} else {
		key = []byte(env.config.JWTAccess)
	}
	jwtToken, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if !jwtToken.Valid {
		var ok bool
		if claims, ok = jwtToken.Claims.(*Claims); !ok {
			return nil, errors.New("Invalid token claims")
		}
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			err = errors.New("That's not a token")
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			err = errors.New("Time expired")
		} else {
			err = errors.New("Couldn't handle this token: " + err.Error())
		}
	} else {
		err = errors.New("Token not provided")
	}
	return
}

// save saves the token to the redis database
func (env *Environment) save(token *Details) (err error) {
	expiry := time.Until(time.Unix(token.Expiry, 0))
	err = errors.WithStack(env.client.Set(env.ctx, token.UUID, token.Subject, expiry).Err())
	return
}

// CheckIfExists checks if token exists in the redis database
func (env *Environment) CheckIfExists(tokenUUID string) (err error) {
	err = errors.WithStack(env.client.Get(env.ctx, tokenUUID).Err())
	return
}

// Delete deletes token from the redis database
func (env *Environment) Delete(tokenUUID string) (err error) {
	err = errors.WithStack(env.client.Del(env.ctx, tokenUUID).Err())
	return
}

func setCookie(w http.ResponseWriter, refreshToken *Details) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken.String,
		Path:     "/api/" + utils.LastVersion + "/",
		Expires:  time.Unix(refreshToken.Expiry, 0),
		SameSite: http.SameSiteStrictMode,
		// Secure:   true,
		HttpOnly: true,
	})
}

// Set returns the access token and sets the refresh token to the http only cookie
func (env *Environment) Set(w http.ResponseWriter, user *db.User) (data map[string]interface{}, err error) {
	accessToken, err := create(user, accessTokenExpiry, env.config.JWTAccess)
	if err != nil {
		return
	}
	refreshToken, err := create(user, refreshTokenExpiry, env.config.JWTAccess)
	if err != nil {
		return
	}
	err = env.save(refreshToken)
	if err != nil {
		return
	}
	data = map[string]interface{}{
		"access_token":        accessToken.String,
		"access_token_expiry": accessToken.Expiry}
	setCookie(w, refreshToken)
	return
}
