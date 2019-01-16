package main

import (
	"context"
	"fmt"
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
	authMiddleware.AuthenticatorFunc = func(c *gin.Context) (clientId string, pass bool) {
		// case 1
		// curl -X POST \
		//  'http://localhost:8080/login/oauth/access_token?client_id=admin&client_secret=admin'
		clientId = c.Query("client_id")
		clientSecret := c.Query("client_secret")
		if ((clientId == "admin") && (clientSecret == "admin")) || ((clientId == "test") && (clientSecret == "test")) {
			return clientId, true
		}

		// case 2
		// curl -X POST \
		//  'http://localhost:8080/login/oauth/access_token' \
		//  -H 'content-type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW' \
		//  -F client_id=admin \
		//  -F client_secret=admin
		clientId = c.PostForm("client_id")
		clientSecret = c.PostForm("client_secret")
		if ((clientId == "admin") && (clientSecret == "admin")) || ((clientId == "test") && (clientSecret == "test")) {
			return clientId, true
		}

		// case 3
		// curl -X POST \
		//  'http://localhost:8080/login/oauth/access_token' \
		//  -H 'Content-Type: application/json' \
		// -d '{
		//	"client_id": "admin",
		//	"client_secret": "admin"
		//}'
		type ClientInfo struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
		}
		var clientInfo ClientInfo
		data, _ := c.GetRawData()
		fmt.Printf("%s \n", string(data))
		c.BindJSON(&clientInfo)
		clientId = clientInfo.ClientID
		clientSecret = clientInfo.ClientSecret
		if ((clientId == "admin") && (clientSecret == "admin")) || ((clientId == "test") && (clientSecret == "test")) {
			return clientId, true
		}
		return clientId, false
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
