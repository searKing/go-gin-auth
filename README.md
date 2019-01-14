# go-gin-auth
go-gin-auth is an authorization middleware for Gin
[![GitHub tag](https://img.shields.io/github/tag/searKing/go-gin-jwt.svg)](https://github.com/searKing/go-gin-jwt/releases)
[![GoDoc](https://godoc.org/github.com/searKing/go-gin-jwt?status.svg)](https://godoc.org/github.com/searKing/go-gin-jwt)

This is a middleware for [Gin](https://github.com/gin-gonic/gin) framework.

It uses [jwt-go](https://github.com/dgrijalva/jwt-go) and [golib](https://github.com/searKing/golib/net/http_/auth/jwt) to provide a jwt authentication middleware. 
It provides an additional handler functions to provide the `login` api that will generate the access-token&refresh-token;
It provides an additional handler functions to provide the `refresh` api that will refresh the access-token;
It provides an additional handler functions to provide the `authenticate` api that will authenticate the access-token.
