// Package jwtm provides goji middleware for JSON Web Tokens.
package jwtm

import (
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/zenazn/goji/web"
)

/*
CValue is what gets added to the goji web context env.
*/
type CValue struct {
	Token *jwt.Token
	Error error
}

/*
TokenFunc returns an encoded JTW token
*/
type TokenFunc func(*web.C, *http.Request) string

/*
NewMiddleware creates some goji middleware that loads a JWT token into the
context environment.

keyFunc is responsible for loading loading the correct key.

tokenFunc is responsible for loading the raw JWT token string.

A CValue gets injected into c.Env[envKey]
*/
func NewMiddleware(
	envKey string,
	keyFunc jwt.Keyfunc,
	tokenFunc TokenFunc,
) func(*web.C, http.Handler) http.Handler {
	return func(c *web.C, h http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if c.Env == nil {
					c.Env = make(map[string]interface{})
				}
				v := CValue{}
				t := tokenFunc(c, r)
				if t == "" {
					v.Error = jwt.ErrNoTokenInRequest
				} else {
					v.Token, v.Error = jwt.Parse(tokenFunc(c, r), keyFunc)
				}
				c.Env[envKey] = v
				h.ServeHTTP(w, r)
			},
		)
	}
}

/*
NewAuthorizationHeaderMiddleware creates some goji middleware that loads a JWT
token from the HTTP Authorization headers BEARER value.
*/
func NewAuthorizationHeaderMiddleware(
	envKey string,
	keyFunc jwt.Keyfunc,
) func(*web.C, http.Handler) http.Handler {
	return NewMiddleware(
		envKey,
		keyFunc,
		func(_ *web.C, r *http.Request) string {
			if ah := r.Header.Get("Authorization"); len(ah) > 6 && strings.ToUpper(ah[0:6]) == "BEARER" {
				return ah[7:]
			}
			return ""
		},
	)
}
