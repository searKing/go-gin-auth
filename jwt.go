package go_gin_auth

import (
	"context"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/searKing/golib/net/http_/auth/jwt_"
	"github.com/searKing/golib/net/http_/oauth2/endpoints"
	"github.com/searKing/golib/net/http_/oauth2/grant/accesstoken"
	"github.com/searKing/golib/net/http_/oauth2/grant/authorize"
	"github.com/searKing/golib/net/http_/oauth2/grant/implict"
	"io/ioutil"
	"log"
	"sync"
	"time"
)

// GinJWTMiddleware provides a Json-Web-Token authentication implementation. On failure, a 401 HTTP response
// is returned. On success, the wrapped middleware is called, and the clientID is made available as
// c.Get("clientID").(string).
// Users can get a token by posting a json request to AuthorizationEndointHandler. The token then needs to be passed in
// the Authentication header. Example: Authorization:Bearer XXX_TOKEN_XXX
type GinJWTMiddleware struct {
	// If nil, logging is done via the log package's standard logger.
	Logger *log.Logger
	// Duration that a jwt access-token is valid. Optional, defaults to one hour.
	AccessExpireIn time.Duration `options:"optional"`
	// Duration that a jwt refresh-token is valid. Optional, defaults to seven days.
	// This field allows clients to refresh their token until MaxRefresh has passed.
	// Note that clients can refresh their token in the last moment of MaxRefresh.
	// This means that the maximum validity timespan for a token is MaxRefresh + Timeout.
	// Optional, defaults to 0 meaning not refreshable.
	RefreshExpireIn time.Duration `options:"optional"`

	AuthorizationCodeGrantAuthorizationFunc func(ctx context.Context, authReq *endpoints.AuthorizationRequest) (res *endpoints.AuthorizeAuthorizationResult, err authorize.ErrorText)
	ImplicitGrantAuthorizationFunc          func(ctx context.Context, authReq *endpoints.AuthorizationRequest) (res *endpoints.JWTImplicitGrantAuthorizationResult, err implict.ErrorText)

	AuthorizationCodeGrantAccessTokenFunc                func(ctx context.Context, tokenReq *endpoints.AuthorizeAccessTokenRequest) (tokenResp *endpoints.JWTAuthorizeAccessTokenResponse, err accesstoken.ErrorText)
	ResourceOwnerPasswordCredentialsGrantAccessTokenFunc func(ctx context.Context, tokenReq *endpoints.ResourceAccessTokenRequest) (tokenResp *endpoints.JWTAccessTokenResponse, err accesstoken.ErrorText)
	ClientCredentialsGrantAccessTokenFunc                func(ctx context.Context, tokenReq *endpoints.ClientAccessTokenRequest) (tokenResp *endpoints.JWTAccessTokenResponse, err accesstoken.ErrorText)
	RefreshTokenGrantAccessTokenFunc                     func(ctx context.Context, tokenReq *endpoints.JWTRefreshTokenRequest) (tokenResp *endpoints.JWTAccessTokenResponse, err accesstoken.ErrorText)

	AuthorizateFunc func(ctx context.Context, claims jwt.MapClaims) (err accesstoken.ErrorText)
	// TimeNowFunc provides the current time. You can override it to use another time value.
	// This is useful for testing or if your server uses a different time zone than your tokens.
	TimeNowFunc func(ctx context.Context) time.Time

	auth *endpoints.JWTAuthorizationEndpoint
	once sync.Once
}

const (
	KeyGinContext = "GinContext"
)

var DefaultGinJWTMiddleware = func() GinJWTMiddleware {
	auth := func() *endpoints.JWTAuthorizationEndpoint {
		clone := endpoints.DefaultJWTAuthorizationEndpoint
		return &clone
	}()
	return GinJWTMiddleware{
		Logger:          log.New(ioutil.Discard, "oauth2", 0),
		AccessExpireIn:  auth.AccessExpireIn,
		RefreshExpireIn: auth.RefreshExpireIn,
		auth:            auth,
	}
}()

func NewGinJWTMiddleware(key *jwt_.AuthKey) *GinJWTMiddleware {
	return &GinJWTMiddleware{
		auth: endpoints.NewJWTAuthorizationEndpoint(key),
	}
}
func (e *GinJWTMiddleware) logf(format string, v ...interface{}) {
	if e.Logger != nil {
		e.Logger.Printf(format, v...)
	} else {
		log.Printf(format, v...)
	}
}

func (e *GinJWTMiddleware) AuthenticationHandler(ctx context.Context) gin.HandlerFunc {
	return func(c *gin.Context) {
		e.lazyInit()
		ctx := context.WithValue(ctx, KeyGinContext, c)
		e.auth.AuthenticationHandler(ctx).ServeHTTP(c.Writer, c.Request)
	}
}
func (e *GinJWTMiddleware) AccessTokenHandler(ctx context.Context) gin.HandlerFunc {
	return func(c *gin.Context) {
		e.lazyInit()
		ctx := context.WithValue(ctx, KeyGinContext, c)
		e.auth.AccessTokenHandler(ctx).ServeHTTP(c.Writer, c.Request)
	}
}
func (e *GinJWTMiddleware) AuthorizateHandler(ctx context.Context) gin.HandlerFunc {
	return func(c *gin.Context) {
		e.lazyInit()
		ctx := context.WithValue(ctx, KeyGinContext, c)
		e.auth.AuthorizateHandler(ctx).ServeHTTP(c.Writer, c.Request)
	}
}

func (e *GinJWTMiddleware) lazyInit() {
	if e.auth == nil {
		return
	}
	e.once.Do(func() {
		if e.AuthorizationCodeGrantAuthorizationFunc != nil {
			e.auth.AuthorizationCodeGrantAuthorizationFunc =
				func(ctx context.Context, authReq *endpoints.AuthorizationRequest) (res *endpoints.AuthorizeAuthorizationResult, err authorize.ErrorText) {
					c := ctx.Value(KeyGinContext)
					if c == nil {
						e.logf("%s is not missing", KeyGinContext)
						return nil, authorize.ErrorTextInvalidRequest
					}
					ginC, ok := c.(*gin.Context)
					if !ok {
						e.logf("type of %s is not *gin.Context", KeyGinContext)
						return nil, authorize.ErrorTextInvalidRequest
					}
					return e.AuthorizationCodeGrantAuthorizationFunc(ginC, authReq)
				}
		}

		if e.ImplicitGrantAuthorizationFunc != nil {
			e.auth.ImplicitGrantAuthorizationFunc = func(ctx context.Context, authReq *endpoints.AuthorizationRequest) (res *endpoints.JWTImplicitGrantAuthorizationResult, err implict.ErrorText) {
				c := ctx.Value(KeyGinContext)
				if c == nil {
					e.logf("%s is not missing", KeyGinContext)
					return nil, implict.ErrorTextInvalidRequest
				}
				ginC, ok := c.(*gin.Context)
				if !ok {
					e.logf("type of %s is not *gin.Context", KeyGinContext)
					return nil, implict.ErrorTextInvalidRequest
				}
				return e.ImplicitGrantAuthorizationFunc(ginC, authReq)
			}
		}

		if e.AuthorizationCodeGrantAccessTokenFunc != nil {
			e.auth.AuthorizationCodeGrantAccessTokenFunc = func(ctx context.Context, tokenReq *endpoints.AuthorizeAccessTokenRequest) (tokenResp *endpoints.JWTAuthorizeAccessTokenResponse, err accesstoken.ErrorText) {
				c := ctx.Value(KeyGinContext)
				if c == nil {
					e.logf("%s is not missing", KeyGinContext)
					return nil, accesstoken.ErrorTextInvalidRequest
				}
				ginC, ok := c.(*gin.Context)
				if !ok {
					e.logf("type of %s is not *gin.Context", KeyGinContext)
					return nil, accesstoken.ErrorTextInvalidRequest
				}
				return e.AuthorizationCodeGrantAccessTokenFunc(ginC, tokenReq)
			}
		}

		if e.ResourceOwnerPasswordCredentialsGrantAccessTokenFunc != nil {
			e.auth.ResourceOwnerPasswordCredentialsGrantAccessTokenFunc = func(ctx context.Context, tokenReq *endpoints.ResourceAccessTokenRequest) (tokenResp *endpoints.JWTAccessTokenResponse, err accesstoken.ErrorText) {
				c := ctx.Value(KeyGinContext)
				if c == nil {
					e.logf("%s is not missing", KeyGinContext)
					return nil, accesstoken.ErrorTextInvalidRequest
				}
				ginC, ok := c.(*gin.Context)
				if !ok {
					e.logf("type of %s is not *gin.Context", KeyGinContext)
					return nil, accesstoken.ErrorTextInvalidRequest
				}
				return e.ResourceOwnerPasswordCredentialsGrantAccessTokenFunc(ginC, tokenReq)
			}
		}

		if e.ClientCredentialsGrantAccessTokenFunc != nil {
			e.auth.ClientCredentialsGrantAccessTokenFunc = func(ctx context.Context, tokenReq *endpoints.ClientAccessTokenRequest) (tokenResp *endpoints.JWTAccessTokenResponse, err accesstoken.ErrorText) {
				c := ctx.Value(KeyGinContext)
				if c == nil {
					e.logf("%s is not missing", KeyGinContext)
					return nil, accesstoken.ErrorTextInvalidRequest
				}
				ginC, ok := c.(*gin.Context)
				if !ok {
					e.logf("type of %s is not *gin.Context", KeyGinContext)
					return nil, accesstoken.ErrorTextInvalidRequest
				}
				return e.ClientCredentialsGrantAccessTokenFunc(ginC, tokenReq)
			}
		}

		if e.RefreshTokenGrantAccessTokenFunc != nil {
			e.auth.RefreshTokenGrantAccessTokenFunc = func(ctx context.Context, tokenReq *endpoints.JWTRefreshTokenRequest) (tokenResp *endpoints.JWTAccessTokenResponse, err accesstoken.ErrorText) {
				c := ctx.Value(KeyGinContext)
				if c == nil {
					e.logf("%s is not missing", KeyGinContext)
					return nil, accesstoken.ErrorTextInvalidRequest
				}
				ginC, ok := c.(*gin.Context)
				if !ok {
					e.logf("type of %s is not *gin.Context", KeyGinContext)
					return nil, accesstoken.ErrorTextInvalidRequest
				}
				return e.RefreshTokenGrantAccessTokenFunc(ginC, tokenReq)
			}
		}

		if e.AuthorizateFunc != nil {
			e.auth.AuthorizateFunc = func(ctx context.Context, claims jwt.MapClaims) (err accesstoken.ErrorText) {
				c := ctx.Value(KeyGinContext)
				if c == nil {
					e.logf("%s is not missing", KeyGinContext)
					return accesstoken.ErrorTextInvalidRequest
				}
				ginC, ok := c.(*gin.Context)
				if !ok {
					e.logf("type of %s is not *gin.Context", KeyGinContext)
					return accesstoken.ErrorTextInvalidRequest
				}
				return e.AuthorizateFunc(ginC, claims)
			}
		}

		if e.TimeNowFunc != nil {
			e.auth.TimeNowFunc = func(ctx context.Context) time.Time {
				c := ctx.Value(KeyGinContext)
				if c == nil {
					return time.Now()
				}
				ginC, ok := c.(*gin.Context)
				if !ok {
					return time.Now()
				}
				return e.TimeNowFunc(ginC)
			}
		}
		e.auth.AbortFunc = func(ctx context.Context) {
			c := ctx.Value(KeyGinContext)
			if c == nil {
				return
			}
			ginC, ok := c.(*gin.Context)
			if !ok {
				return
			}
			ginC.Abort()
			return
		}
	})
}
