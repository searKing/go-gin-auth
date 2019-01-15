package main

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/searKing/go-gin-auth"
	"net/http"
	"os"
)

func helloHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"text": "Hello World.",
	})
}

func main() {
	port := os.Getenv("PORT")
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	if port == "" {
		port = "8080"
	}

	// the jwt middleware
	authMiddleware := go_gin_auth.NewHS256GinJWTMiddleware()

	// 认证
	authMiddleware.AuthenticatorFunc = func(c *gin.Context) (appId string, pass bool) {
		appId = c.Query("app_id")
		appSecret := c.Query("app_secret")
		if ((appId == "admin") && (appSecret == "admin")) || ((appId == "test") && (appSecret == "test")) {
			return appId, true
		}

		return appId, false
	}

	// 授权
	authMiddleware.AuthorizatorFunc = func(c *gin.Context, userId string) bool {
		if userId == "admin" {
			return true
		}
		return false
	}

	authMiddleware.UnauthorizedFunc = func(c *gin.Context, statusCode int) {
		c.JSON(statusCode, gin.H{
			"code":    statusCode,
			"message": http.StatusText(statusCode),
		})
	}

	r.POST("/login", authMiddleware.LoginHandler(context.Background()))

	auth := r.Group("/auth")
	auth.Use(authMiddleware.AuthenticateHandler(context.Background()))
	{
		auth.GET("/hello", helloHandler)
		auth.GET("/refresh_token", authMiddleware.RefreshHandler(context.Background()))
	}

	http.ListenAndServe(":"+port, r)
}
