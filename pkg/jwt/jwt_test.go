package jwt_test

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	"github.com/gxravel/auth/internal/conf"
	. "github.com/gxravel/auth/pkg/jwt"
	"github.com/stretchr/testify/assert"
)

const JWT_ACCESS = "test-access"
const JWT_REFRESH = "test-refresh"

var config = &conf.JWTConfiguration{JWTAccess: JWT_ACCESS, JWTRefresh: JWT_REFRESH}

func TestParse(t *testing.T) {
	var tests = []struct {
		token     string
		isRefresh bool
		want      *Claims
	}{
		// 0
		{
			token:     "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmlja25hbWUiOiJKb2huIERvZSIsImlhdCI6MTUxNjIzOTAyMn0.a3a58IUnfv84r4ZtmeDh-v79gWbyHKJhf9cFLG1UDNMAHwa9t5goHuqEMS2eHLhM5dTaZgKD0VDRfrIyDGHULA",
			isRefresh: false,
			want:      &Claims{Nickname: "John Doe", StandardClaims: jwt.StandardClaims{Subject: "1234567890", IssuedAt: 1516239022}},
		},
		// 1
		{
			token:     "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMTExIiwiaWF0IjoxNTE2MjM5MDIyfQ.fH7icUwYN4URCT2wSuTZ7sciD_hfp4gM29jzx46OJvupwTinYVqYQYTdF79d4Z3KMH_rsbPiG1w0-TZPtQTYAg",
			isRefresh: true,
			want:      &Claims{StandardClaims: jwt.StandardClaims{Subject: "1111", IssuedAt: 1516239022}},
		},
		// 2
		// wrong header
		{
			token:     "eyJhbGciOiextracharacter5cCI6IkpXVCJ9.eyJzdWIiOiIxMTExIiwiaWF0IjoxNTE2MjM5MDIyfQ.fH7icUwYN4URCT2wSuTZ7sciD_hfp4gM29jzx46OJvupwTinYVqYQYTdF79d4Z3KMH_rsbPiG1w0-TZPtQTYAg",
			isRefresh: true,
			want:      nil,
		},
		// 3
		{
			token:     "pretend-to-be-token",
			isRefresh: true,
			want:      nil,
		},
		// 4
		// wrong payload
		{
			token:     "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMTExIiwiaWF0IjoxNTE2wrOngHerefQ.fH7icUwYN4URCT2wSuTZ7sciD_hfp4gM29jzx46OJvupwTinYVqYQYTdF79d4Z3KMH_rsbPiG1w0-TZPtQTYAg",
			isRefresh: true,
			want:      nil,
		},
		// 5
		// wrong signature
		{
			token:     "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMTExIiwiaWF0IjoxNTE2MjM5MDIyfQ.fH7icUwYN4URCT2wSuTZ7sciD_hfp4gM29jzx46OJQYTdF7wrong_signature9d4Z3KMH_rsbPiG1w0-TZPtQTYAg",
			isRefresh: true,
			want:      nil,
		},
		// 6
		// wrong payload data
		{
			token:     "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMTExIiwicm9sZSI6MSwiaWF0IjoxNTE2MjMzMjEzLCJ3cm9uZyI6ZmFsc2V9.E44kXz_WNq9mWAgI8RXIJsR04Q86_DnQ9Rw1fcXK2n7lzbZdcNqvjFxToNtP3Xxs4y2P-ukPeLLSzhJZ4ODAzw",
			isRefresh: true,
			want:      &Claims{Role: 1, StandardClaims: jwt.StandardClaims{Subject: "1111", IssuedAt: 1516233213}},
		},
		// 7
		// wrong key
		{
			token:     "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMTExIiwicm9sZSI6MSwiaWF0IjoxNTE2MjMzMjEzfQ.9napoA8uEyTPGqdzrUB3nv_tTn9_5wuEpBnb6vuJJWrd__h2MhT4I8Dwlvf7dtIYXDTVnI8-8SyOWtHFllhz7Q",
			isRefresh: false,
			want:      nil,
		},
		// 8
		// secret base64 encoded
		{
			token:     "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMTExIiwicm9sZSI6MCwiaWF0IjoxNTE2MjMzMjEzfQ.CbhwgBWMDgEAiOaErqXnQ1nQOQ_wboYP5uNnBxHm7X7csWJdns8iLimf1GaEI8odCYBnA-6WdxekGTQ7tqxVSA",
			isRefresh: true,
			want:      nil,
		},
		// 9
		{
			token:     "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2ZXJ5LWxvbmctaWQiLCJyb2xlIjoyLCJpYXQiOjE2MTYyMzMyMTMsIm5pY2tuYW1lIjoiZ3hyYXZlbCJ9.gsB-KcnGbFvaPVhibbzGFQgBPpwoIeL1C8QH3UQZSz4RcQA_TEUTxQXNWzOmo45rpYo9vq5_NCci5nKft7sgYw",
			isRefresh: true,
			want:      &Claims{Role: 2, Nickname: "gxravel", StandardClaims: jwt.StandardClaims{Subject: "very-long-id", IssuedAt: 1616233213}},
		},
	}

	var e = &Environment{}
	mr, err := miniredis.Run()
	if err != nil {
		panic(err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	e.Init(client, config)

	for id, test := range tests {
		claims, err := e.Parse(test.token, test.isRefresh)
		if test.want == nil {
			assert.Errorf(t, err, "id: %d, got: %v", id, claims)
		} else {
			if assert.NoError(t, err) {
				assert.Equal(t, test.want, claims)
			}
		}
	}
}
