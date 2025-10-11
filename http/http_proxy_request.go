package http

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	nxproxy "github.com/maddsua/nx-proxy"
)

var ErrUnauthorized = errors.New("unauthorized")

func proxyRequestCredentials(req *http.Request) (*nxproxy.UserPassword, error) {

	proxyAuth := req.Header.Get("Proxy-Authorization")
	if proxyAuth == "" {
		return nil, ErrUnauthorized
	}

	schema, token, _ := strings.Cut(proxyAuth, " ")
	if strings.ToLower(strings.TrimSpace(schema)) != "basic" {
		return nil, fmt.Errorf("invalid auth schema '%s'", schema)
	}

	userauth, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	username, password, _ := strings.Cut(string(userauth), ":")
	if username == "" {
		return nil, errors.New("username is empty")
	}

	return &nxproxy.UserPassword{
		User:     username,
		Password: password,
	}, nil
}

func proxyRequestHost(req *http.Request) string {

	if req.Method == http.MethodConnect {
		if !strings.Contains(req.RequestURI, "/") {
			return req.RequestURI
		}
		return req.Host
	}

	return req.Host
}
