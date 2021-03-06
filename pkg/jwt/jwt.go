package jwt

import (
	"context"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	"github.com/gxravel/auth/internal/conf"
	"github.com/gxravel/auth/internal/db/user"
	"github.com/gxravel/auth/pkg/goconst"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

const (
	accessTokenExpiry  = time.Minute * 15
	refreshTokenExpiry = time.Hour * 24 * 7
)

// Claims defines JWT token claims.
type Claims struct {
	Nickname string `json:"nickname,omitempty"`
	Role     int8   `json:"role,omitempty"`
	jwt.StandardClaims
}

// Details defines the structure of a JWT token.
type Details struct {
	String  string
	Expiry  int64
	UUID    string
	Subject string
}

// Manager includes the methods allowed to deal with the token.
type Manager interface {
	save(ctx context.Context, token *Details) (err error)

	Init(client *redis.Client, config *conf.JWTConfiguration)
	Parse(tokenString string, isRefresh bool) (claims *Claims, err error)
	CheckIfExists(ctx context.Context, tokenUUID string) (err error)
	Delete(ctx context.Context, tokenUUID string) (err error)
	Set(ctx context.Context, w http.ResponseWriter, user *user.User) (data map[string]interface{}, err error)
}

// Environment contains the fields which interact with the token.
type Environment struct {
	client *redis.Client
	config *conf.JWTConfiguration
}

// Init initializes the JWT Environment.
func (e *Environment) Init(client *redis.Client, config *conf.JWTConfiguration) {
	e.client = client
	e.config = config
}

// create creates the HS512 JWT token with claims.
func create(user *user.User, expiry time.Duration, key string) (token *Details, err error) {
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

// Parse parses a string token with the key.
func (e *Environment) Parse(tokenString string, isRefresh bool) (claims *Claims, err error) {
	var key []byte
	if isRefresh {
		key = []byte(e.config.JWTRefresh)
	} else {
		key = []byte(e.config.JWTAccess)
	}
	jwtToken, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return key, nil
	})
	var ok bool
	if claims, ok = jwtToken.Claims.(*Claims); !ok || !jwtToken.Valid {
		return nil, errors.New("couldn't handle this token: " + err.Error())
	}
	return
}

// save saves the token to the redis database.
func (e *Environment) save(ctx context.Context, token *Details) (err error) {
	expiry := time.Until(time.Unix(token.Expiry, 0))
	err = errors.WithStack(e.client.Set(ctx, token.UUID, token.Subject, expiry).Err())
	return
}

// CheckIfExists checks if token exists in the redis database.
func (e *Environment) CheckIfExists(ctx context.Context, tokenUUID string) (err error) {
	err = errors.WithStack(e.client.Get(ctx, tokenUUID).Err())
	return
}

// Delete deletes token from the redis database.
func (e *Environment) Delete(ctx context.Context, tokenUUID string) (err error) {
	err = errors.WithStack(e.client.Del(ctx, tokenUUID).Err())
	return
}

func setCookie(w http.ResponseWriter, refreshToken *Details) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken.String,
		Path:     "/api/" + goconst.APIVersion + "/",
		Expires:  time.Unix(refreshToken.Expiry, 0),
		SameSite: http.SameSiteStrictMode,
		// Secure:   true,
		HttpOnly: true,
	})
}

// Set returns the access token and sets the refresh token to the http only cookie.
func (e *Environment) Set(ctx context.Context, w http.ResponseWriter, user *user.User) (data map[string]interface{}, err error) {
	accessToken, err := create(user, accessTokenExpiry, e.config.JWTAccess)
	if err != nil {
		return
	}
	refreshToken, err := create(user, refreshTokenExpiry, e.config.JWTRefresh)
	if err != nil {
		return
	}
	err = e.save(ctx, refreshToken)
	if err != nil {
		return
	}
	data = map[string]interface{}{
		"access_token":        accessToken.String,
		"access_token_expiry": accessToken.Expiry}
	setCookie(w, refreshToken)
	return
}
