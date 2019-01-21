package main

import (
	"context"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/searKing/go-gin-auth"
	"github.com/searKing/golib/net/http_/auth/jwt_"
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
	authMiddleware, err := go_gin_auth.NewGinJWTMiddlewareFromRandom(jwt_.SigningMethodRS256)
	if err != nil {
		panic(err)
	}
	// authMiddleware.AccessExpireIn = time.Hour //default value
	// authMiddleware.RefreshExpireIn = 7 * 24 * time.Hour  //default value
	// 认证
	authMiddleware.AuthenticatorFunc = func(c *gin.Context, password *jwt_.ClientPassword) (pass bool) {
		if password == nil {
			return false
		}
		if ((password.ClientId == "admin") && (password.ClientSecret == "admin")) ||
			((password.ClientId == "test") && (password.ClientSecret == "test")) {
			return true
		}
		return false
	}

	// 授权
	authMiddleware.AuthorizatorFunc = func(c *gin.Context, claims jwt.MapClaims) bool {
		if claims == nil {
			return false
		}
		return true
	}

	authMiddleware.UnauthorizedFunc = func(c *gin.Context, statusCode int) {
		c.JSON(statusCode, gin.H{
			"code":    statusCode,
			"message": http.StatusText(statusCode),
		})
	}
	auth := r.Group("/login/oauth")
	{
		auth.POST("/access_token", authMiddleware.LoginHandler(context.Background()))
		auth.POST("/refresh_token", authMiddleware.RefreshHandler(context.Background()))
	}

	api := r.Group("/api/v1")
	api.Use(authMiddleware.AuthorizateHandler(context.Background()))
	{
		api.GET("/test_api", helloWorldHandler)
	}

	http.ListenAndServe(":"+port, r)
}
