package go_gin_auth

import (
	"context"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/searKing/golib/crypto/auth"
	"github.com/searKing/golib/net/http_/auth/jwt_"
	"net/http"
	"time"
)

// GinJWTMiddleware provides a Json-Web-Token authentication implementation. On failure, a 401 HTTP response
// is returned. On success, the wrapped middleware is called, and the userID is made available as
// c.Get("userID").(string).
// Users can get a token by posting a json request to LoginHandler. The token then needs to be passed in
// the Authentication header. Example: Authorization:Bearer XXX_TOKEN_XXX
type GinJWTMiddleware struct {
	// Realm name to display to the user. Required.
	// https://tools.ietf.org/html/rfc7235#section-2.2
	Realm string `options:"optional" default:""`

	// Whenever the user wants to access a protected route or resource,
	// the user agent should send the JWT,
	// https://jwt.io/introduction/
	Schema string `options:"optional" default:"Bearer"`

	// Duration that a jwt access-token is valid. Optional, defaults to one hour.
	AccessExpireIn time.Duration `options:"optional"`
	// Duration that a jwt refresh-token is valid. Optional, defaults to seven days.
	// This field allows clients to refresh their token until MaxRefresh has passed.
	// Note that clients can refresh their token in the last moment of MaxRefresh.
	// This means that the maximum validity timespan for a token is MaxRefresh + Timeout.
	// Optional, defaults to 0 meaning not refreshable.
	RefreshExpireIn time.Duration `options:"optional"`

	// Callback function that should perform the authentication of the user based on userID and
	// password. Must return true on success, false on failure. Required.
	// Option return user id, if so, user id will be stored in Claim Array.
	AuthenticatorFunc func(c *gin.Context) (appId string, pass bool) `options:"optional"`

	// Callback function that should perform the authorization of the authenticated user. Called
	// only after an authentication success. Must return true on success, false on failure.
	// Optional, default to success.
	AuthorizatorFunc func(c *gin.Context, appId string) bool `options:"optional"`

	// Callback function that will be called during login.
	// Using this function it is possible to add additional payload data to the webtoken.
	// The data is then made available during requests via c.Get("JWT_PAYLOAD").
	// Note that the payload is not encrypted.
	// The attributes mentioned on jwt.io can't be used as keys for the map.
	// Optional, by default no additional data will be set.
	PayloadFunc func(c *gin.Context, appId string) map[string]interface{} `options:"optional"`

	// User can define own UnauthorizedFunc func.
	UnauthorizedFunc func(c *gin.Context, statusCode int) `options:"optional"`

	// Set the identity handler function
	IdentityFunc func(c *gin.Context, claims jwt.Claims) string `options:"optional"`

	// TimeNowFunc provides the current time. You can override it to use another time value.
	// This is useful for testing or if your server uses a different time zone than your tokens.
	TimeNowFunc func(c *gin.Context) time.Time `options:"optional"`

	jwtAuth *jwt_.JWTAuth
}

const (
	KeyGinContext = "GinContext"
)

func NewHS256GinJWTMiddleware(key ...[]byte) *GinJWTMiddleware {
	var signedKey []byte
	if len(key) == 0 {
		signedKey = []byte(auth.ClientKeyWithSize(256))
	} else {
		signedKey = key[0]
	}
	return NewGinJWTMiddleware(jwt_.SigningMethodHS256, signedKey)
}

func NewGinJWTMiddleware(alg string, keys ...[]byte) *GinJWTMiddleware {
	jwtMid := &GinJWTMiddleware{
		jwtAuth: jwt_.NewJWTAuth(alg, keys...),
	}
	jwtMid.BindFuncs()
	return jwtMid
}

func NewGinJWTMiddlewareFromFile(alg string, keyFiles ...string) *GinJWTMiddleware {
	jwtMid := &GinJWTMiddleware{
		jwtAuth: jwt_.NewJWTAuthFromFile(alg, keyFiles...),
	}
	jwtMid.BindFuncs()
	return jwtMid
}

func (mw *GinJWTMiddleware) BindFuncs() {
	mw.jwtAuth.AuthenticatorFunc = func(ctx context.Context, r *http.Request) (appId string, pass bool) {
		c := ctx.Value(KeyGinContext)
		if c == nil {
			return "", false
		}
		ginC, ok := c.(*gin.Context)
		if !ok {
			return "", false
		}
		return mw.Authenticator(ginC)
	}

	mw.jwtAuth.AuthorizatorFunc = func(ctx context.Context, userID string, w http.ResponseWriter) (pass bool) {
		c := ctx.Value(KeyGinContext)
		if c == nil {
			return false
		}
		ginC, ok := c.(*gin.Context)
		if !ok {
			return false
		}
		return mw.Authorizator(ginC, userID)
	}

	mw.jwtAuth.PayloadFunc = func(ctx context.Context, appId string) map[string]interface{} {
		c := ctx.Value(KeyGinContext)
		if c == nil {
			return nil
		}
		ginC, ok := c.(*gin.Context)
		if !ok {
			return nil
		}
		return mw.Payload(ginC, appId)
	}

	mw.jwtAuth.UnauthorizedFunc = func(ctx context.Context, w http.ResponseWriter, status int) {
		c := ctx.Value(KeyGinContext)
		if c == nil {
			return
		}
		ginC, ok := c.(*gin.Context)
		if !ok {
			return
		}
		mw.Unauthorized(ginC, status)
	}

	mw.jwtAuth.IdentityFunc = func(ctx context.Context, claims jwt.Claims) (appId string) {
		c := ctx.Value(KeyGinContext)
		if c == nil {
			return ""
		}
		ginC, ok := c.(*gin.Context)
		if !ok {
			return ""
		}
		return mw.Identity(ginC, claims)
	}

	mw.jwtAuth.TimeNowFunc = func(ctx context.Context) time.Time {
		c := ctx.Value(KeyGinContext)
		if c == nil {
			return time.Now()
		}
		ginC, ok := c.(*gin.Context)
		if !ok {
			return time.Now()
		}
		return mw.TimeNow(ginC)
	}
}

// AuthenticateHandler makes JWTAuth implement the Middleware interface.
func (mw *GinJWTMiddleware) AuthenticateHandler(ctx context.Context) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := context.WithValue(ctx, KeyGinContext, c)
		mw.jwtAuth.AuthenticateHandler(ctx).ServeHTTP(c.Writer, c.Request)
	}
}

// LoginHandler can be used by clients to get a jwt token.
// Payload needs to be json in the form of {"username": "USERNAME", "password": "PASSWORD"}.
// Reply will be of the form {"access_token": "ACCESS_TOKEN", "refresh_token": "REFRESH_TOKEN", "expires_in": "EXPIRES_IN"}.
func (mw *GinJWTMiddleware) LoginHandler(ctx context.Context) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := context.WithValue(ctx, KeyGinContext, c)
		mw.jwtAuth.LoginHandler(ctx).ServeHTTP(c.Writer, c.Request)
	}
}

// RefreshHandler can be used to refresh a token. The token still needs to be valid on refresh.
// Shall be put under an endpoint that is using the JWTAuth.
// Reply will be of the form {"access_token": "ACCESS_TOKEN", "expires_in": "EXPIRES_IN"}.
func (mw *GinJWTMiddleware) RefreshHandler(ctx context.Context) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := context.WithValue(ctx, KeyGinContext, c)
		mw.jwtAuth.RefreshHandler(ctx).ServeHTTP(c.Writer, c.Request)
	}
}

// Callback function that should perform the authentication of the user based on userID and
// password. Must return true on success, false on failure. Required.
// Option return user id, if so, user id will be stored in Claim Array.
func (mw *GinJWTMiddleware) Authenticator(c *gin.Context) (appId string, pass bool) {
	if mw.AuthenticatorFunc != nil {
		return mw.AuthenticatorFunc(c)
	}
	return "", true
}

// Callback function that should perform the authorization of the authenticated user. Called
// only after an authentication success. Must return true on success, false on failure.
// Optional, default to success.
func (mw *GinJWTMiddleware) Authorizator(c *gin.Context, appId string) (pass bool) {
	if mw.AuthorizatorFunc != nil {
		return mw.AuthorizatorFunc(c, appId)
	}
	return true
}

// Callback function that will be called during login.
// Using this function it is possible to add additional payload data to the webtoken.
// The data is then made available during requests via c.Get("JWT_PAYLOAD").
// Note that the payload is not encrypted.
// The attributes mentioned on jwt.io can't be used as keys for the map.
// Optional, by default no additional data will be set.
func (mw *GinJWTMiddleware) Payload(c *gin.Context, appId string) map[string]interface{} {
	if mw.PayloadFunc != nil {
		return mw.PayloadFunc(c, appId)
	}
	return nil
}

// show 401 UnauthorizedFunc error.
func (mw *GinJWTMiddleware) Unauthorized(c *gin.Context, statusCode int) {
	defer c.Abort()
	if mw.UnauthorizedFunc != nil {
		mw.UnauthorizedFunc(c, statusCode)
		return
	}

	auth := jwt_.NewJWTAuthenticate(mw.Realm, mw.Schema)
	auth.WriteHTTPWithStatusCode(c.Writer, statusCode)

	return
}

// Set the identity handler function
func (mw *GinJWTMiddleware) Identity(c *gin.Context, claims jwt.Claims) (appId string) {
	if mw.IdentityFunc != nil {
		return mw.IdentityFunc(c, claims)
	}
	return ""
}

// TimeNowFunc provides the current time. You can override it to use another time value.
// This is useful for testing or if your server uses a different time zone than your tokens.
func (mw *GinJWTMiddleware) TimeNow(c *gin.Context) time.Time {
	if mw.TimeNowFunc != nil {
		return mw.TimeNowFunc(c)
	}
	return time.Now()
}