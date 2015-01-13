package jwtm

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/zenazn/goji/web"
)

var (
	token  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ.eoaDVGTClRdfxUZXiPs3f8FmJDkDE_VCQFXqKxpLsts"
	claims = make(map[string]interface{})
	secret = []byte("secret")
	envKey = "JWT"
)

func init() {
	claims["sub"] = float64(1234567890) // js numbers are floats
	claims["name"] = "John Doe"
	claims["admin"] = true
}

func getAuthorizationHeaderHandler(c *web.C) http.Handler {
	return NewAuthorizationHeaderMiddleware(
		envKey,
		func(_ *jwt.Token) (interface{}, error) {
			return secret, nil
		},
	)(
		c,
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				// do nothing.
			},
		),
	)
}

func TestAuthorizationMiddlewareWithoutAuthorizationHeader(t *testing.T) {
	rr := httptest.NewRecorder()
	r := &http.Request{
		Method: "GET",
		Header: http.Header{},
	}
	c := &web.C{}
	getAuthorizationHeaderHandler(c).ServeHTTP(rr, r)
	if c.Env == nil {
		t.Fatal("Expecting context env to be not nil")
	}
	ev, ok := c.Env[envKey]
	if !ok {
		t.Fatalf("Expecting context env to have %q item.", envKey)
	}
	cv, ok := ev.(CValue)
	if !ok {
		t.Fatalf("Expecting context env %q item to be a CValue value got %T (%s).", envKey, ev, ev)
	}
	if cv.Token != nil {
		t.Error("Expecting the token to be nil.")
	}
	if cv.Error != jwt.ErrNoTokenInRequest {
		t.Errorf("Expecting error to be jwt.ErrNoTokenInRequest, got %T (%s)", cv.Error, cv.Error)
	}
}

func TestAuthorizationMiddlewareWithAuthorizationHeaderThatIsNotBearer(t *testing.T) {
	rr := httptest.NewRecorder()
	r := &http.Request{
		Method: "GET",
		Header: http.Header{
			"Authorization": []string{
				"foo",
			},
		},
	}
	c := &web.C{}
	getAuthorizationHeaderHandler(c).ServeHTTP(rr, r)
	if c.Env == nil {
		t.Fatal("Expecting context env to be not nil")
	}
	ev, ok := c.Env[envKey]
	if !ok {
		t.Fatalf("Expecting context env to have %q item.", envKey)
	}
	cv, ok := ev.(CValue)
	if !ok {
		t.Fatalf("Expecting context env %q item to be a CValue value got %T (%s).", envKey, ev, ev)
	}
	if cv.Token != nil {
		t.Error("Expecting the token to be nil.")
	}
	if cv.Error != jwt.ErrNoTokenInRequest {
		t.Errorf("Expecting error to be jwt.ErrNoTokenInRequest, got %T (%s)", cv.Error, cv.Error)
	}
}

func TestAuthorizationMiddlewareWithNonJWTBearer(t *testing.T) {
	rr := httptest.NewRecorder()
	r := &http.Request{
		Method: "GET",
		Header: http.Header{
			"Authorization": []string{
				"Bearer 86258651-2385789724-24387623",
			},
		},
	}
	c := &web.C{}
	getAuthorizationHeaderHandler(c).ServeHTTP(rr, r)
	if c.Env == nil {
		t.Fatal("Expecting context env to be not nil")
	}
	ev, ok := c.Env[envKey]
	if !ok {
		t.Fatalf("Expecting context env to have %q item.", envKey)
	}
	cv, ok := ev.(CValue)
	if !ok {
		t.Fatalf("Expecting context env %q item to be a CValue value got %T (%s).", envKey, ev, ev)
	}
	if cv.Token != nil {
		t.Error("Expecting the token to be nil.")
	}
	if ve, ok := cv.Error.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != jwt.ValidationErrorMalformed {
			t.Errorf("Expecting error to contain ValidationErrorMalformed, got %s", ve.Error())
		}
	} else {
		t.Errorf("Expecting error to be jwt.ValidationError, got %T (%s)", cv.Error, cv.Error)
	}
}

func TestAuthorizationMiddlewareWithValidToken(t *testing.T) {
	rr := httptest.NewRecorder()
	r := &http.Request{
		Method: "GET",
		Header: http.Header{
			"Authorization": []string{
				"Bearer " + token,
			},
		},
	}
	c := &web.C{}
	getAuthorizationHeaderHandler(c).ServeHTTP(rr, r)
	if c.Env == nil {
		t.Fatal("Expecting context env to be not nil")
	}
	ev, ok := c.Env[envKey]
	if !ok {
		t.Fatalf("Expecting context env to have %q item.", envKey)
	}
	cv, ok := ev.(CValue)
	if !ok {
		t.Fatalf("Expecting context env %q item to be a CValue value got %T (%s).", envKey, ev, ev)
	}
	if cv.Token == nil {
		t.Error("Expecting the token to not be nil.")
	} else {
		if !cv.Token.Valid {
			t.Error("Expecting the token to be valid.")
		}
		for k, v := range claims {
			if cv.Token.Claims[k] != v {
				t.Errorf("Expecting %q claim to be %q. Got %q.", k, v, cv.Token.Claims[k])
			}
		}
	}
	if cv.Error != nil {
		t.Fatalf("Expecting error to be nil got %T (%s).", cv.Error, cv.Error)
	}
}
