goji_jwt
========

[goji framework](https://goji.io) JSON Web Token (JWT) middleware.

example:

```go
package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	jwtm "github.com/williambailey/goji-jwt"
	"github.com/zenazn/goji"
	"github.com/zenazn/goji/web"
)

func main() {

	/*
				Use a jwt handler for every request. The handler will and look
				for a JWT in the authorization header bearer value.

		    A CValue gets injected into goji c.Env["JWT"].
	*/
	goji.Use(jwtm.NewAuthorizationHeaderMiddleware(
		"JWT",
		func(_ *jwt.Token) (interface{}, error) {
			return []byte("secret"), nil
		},
	))

	goji.Get("/", func(c web.C, w http.ResponseWriter, r *http.Request) {
		var cv jwtm.CValue
		if ev, ok := c.Env["JWT"]; ok {
			cv = ev.(jwtm.CValue)
		}
		w.Header().Set("Content-Type", "text/plain")
		if cv.Error != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "JWT Error:\n")
			fmt.Fprint(w, cv.Error.Error())
			return
		}
		if cv.Token == nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "No JWT found.")
			return
		}
		w.WriteHeader(http.StatusOK)
		if cv.Token.Valid {
			fmt.Fprint(w, "Valid")
		} else {
			fmt.Fprint(w, "Invalid")
		}
		fmt.Fprint(w, "JWT found:\n")
		fmt.Fprint(w, cv.Token.Raw)
		fmt.Fprint(w, "\nClaims:\n")
		json.NewEncoder(w).Encode(cv.Token.Claims)
	})

	goji.Serve()
}
```
