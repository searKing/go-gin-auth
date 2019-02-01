package main

import (
	"context"
	"fmt"
	"golang.org/x/oauth2/clientcredentials"
	"io/ioutil"
)

func main() {

	conf := &clientcredentials.Config{
		ClientID:       "admin",
		ClientSecret:   "admin",
		TokenURL:       "http://localhost:8080/login/oauth/token",
		Scopes:         nil,
		EndpointParams: nil,
	}
	c := conf.Client(context.Background())
	resp, err := c.Get("http://localhost:8080/api/v1/test_api")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Printf("response data: %v", string(data))
}
