package main

import (
	"context"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/searKing/go-gin-auth"
	"github.com/searKing/golib/net/http_/oauth2/endpoints"
	"github.com/searKing/golib/net/http_/oauth2/grant/accesstoken"
	"net/http"
	"os"
)

func helloWorldHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"text": "Hello World.",
	})
}

func main() {
	port := os.Getenv("HTTP_PORT")
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	if port == "" {
		port = "8080"
	}

	// the jwt middleware
	authMiddleware := &go_gin_auth.DefaultGinJWTMiddleware
	// 认证
	authMiddleware.ClientCredentialsGrantAccessTokenFunc = func(ctx context.Context, tokenReq *endpoints.ClientAccessTokenRequest) (tokenResp *endpoints.JWTAccessTokenResponse, err accesstoken.ErrorText) {
		if tokenReq == nil {
			return nil, accesstoken.ErrorTextInvalidRequest
		}
		if ((tokenReq.UserID == "admin") && (tokenReq.Password == "admin")) ||
			((tokenReq.UserID == "test") && (tokenReq.Password == "test")) {
			return nil, ""
		}
		return &endpoints.JWTAccessTokenResponse{}, ""
	}
	// 授权
	authMiddleware.AuthorizateFunc = func(ctx context.Context, claims jwt.MapClaims) (err accesstoken.ErrorText) {
		if claims == nil {
			return accesstoken.ErrorTextUnauthorizedClient
		}
		return ""

	}
	authMiddleware.RefreshTokenGrantAccessTokenFunc = func(ctx context.Context, tokenReq *endpoints.JWTRefreshTokenRequest) (tokenResp *endpoints.JWTAccessTokenResponse, err accesstoken.ErrorText) {
		if tokenReq == nil {
			return nil, accesstoken.ErrorTextInvalidRequest
		}
		if ((tokenReq.UserID == "admin") && (tokenReq.Password == "admin")) ||
			((tokenReq.UserID == "test") && (tokenReq.Password == "test")) {
			return nil, ""
		}
		return &endpoints.JWTAccessTokenResponse{}, ""
	}

	auth := r.Group("/login/oauth")
	{
		auth.POST("/auth", authMiddleware.AuthorizateHandler(context.Background()))
		auth.POST("/token", authMiddleware.AccessTokenHandler(context.Background()))
	}

	api := r.Group("/api/v1")
	api.Use(authMiddleware.AuthorizateHandler(context.Background()))
	{
		api.GET("/test_api", helloWorldHandler)
	}

	http.ListenAndServe(":"+port, r)
}
