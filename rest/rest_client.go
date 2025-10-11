package rest

import (
	"net/http"
	"net/url"

	nxproxy "github.com/maddsua/nx-proxy"
	"github.com/maddsua/nx-proxy/rest/model"
)

type Client struct {
	URL   *url.URL
	Token *nxproxy.ServerToken
}

func (client *Client) PostStatus(status *model.Status) error {
	return beacon(client.URL, client.Token, http.MethodPost, "/nxproxy/v1/status", status)
}

func (client *Client) PullConfig() (*model.FullConfig, error) {
	return fetch[model.FullConfig](client.URL, client.Token, http.MethodGet, "/nxproxy/v1/config", nil)
}
