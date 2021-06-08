package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/gxravel/auth/internal/conf"
	"github.com/gxravel/auth/internal/db/user"
	"github.com/gxravel/auth/pkg/goconst"
	"github.com/gxravel/auth/pkg/jwt"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockJWTEnvironment struct {
	mock.Mock
}

func (m *MockJWTEnvironment) Parse(token string, isRefresh bool) (*jwt.Claims, error) {
	args := m.Called(token, isRefresh)
	return args.Get(0).(*jwt.Claims), args.Error(1)
}

func (m *MockJWTEnvironment) Init(client *redis.Client, config *conf.JWTConfiguration) {
	m.Called(client, config)
}
func (m *MockJWTEnvironment) CheckIfExists(ctx context.Context, tokenUUID string) (err error) {
	args := m.Called(ctx, tokenUUID)
	return args.Error(0)
}
func (m *MockJWTEnvironment) Delete(ctx context.Context, tokenUUID string) (err error) {
	args := m.Called(ctx, tokenUUID)
	return args.Error(0)
}
func (m *MockJWTEnvironment) Set(ctx context.Context, w http.ResponseWriter, user *user.User) (data map[string]interface{}, err error) {
	args := m.Called(ctx, w, user)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

type MockUsers struct {
	mock.Mock
}

func (m *MockUsers) All() (users []user.User, err error) {
	args := m.Called()
	return args.Get(0).([]user.User), args.Error(1)
}
func (m *MockUsers) New(user *user.User) (uid string, err error) {
	args := m.Called(user)
	return args.String(0), args.Error(1)
}
func (m *MockUsers) GetHashedPassword(uid string) (hashedPassword []byte, err error) {
	args := m.Called(uid)
	return args.Get(0).([]byte), args.Error(1)
}

func TestRefresh(t *testing.T) {
	assert := assert.New(t)
	path := "/api/" + goconst.APIVersion + "/"
	req, err := http.NewRequest("POST", path+"refresh_token", nil)
	assert.NoError(err)

	rr := httptest.NewRecorder()
	http.SetCookie(rr, &http.Cookie{
		Name:     "refresh_token",
		Value:    mock.Anything,
		Path:     path,
		Expires:  time.Now(),
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
	})

	req.AddCookie(rr.Result().Cookies()[0])

	claims := &jwt.Claims{}
	data := map[string]interface{}{
		"access_token":        mock.Anything,
		"access_token_expiry": mock.Anything}
	mockJWT := new(MockJWTEnvironment)
	mockJWT.On("Parse", mock.Anything, true).Return(claims, nil)
	mockJWT.On("CheckIfExists", mock.Anything, mock.Anything).Return(nil)
	mockJWT.On("Delete", mock.Anything, mock.Anything).Return(nil)
	mockJWT.On("Set", mock.Anything, rr, mock.Anything).Return(data, nil)

	e := &environment{token: mockJWT, users: &user.Wrapper{}, log: &logrus.Logger{}}

	code, err := e.refresh(rr, req)
	if assert.NoError(err) {
		assert.Equal(code, http.StatusOK)
	}

	mockJWT.AssertExpectations(t)
}
