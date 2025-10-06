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

func (client *Client) PostMetrics(metrics *model.Metrics) error {
	return beacon(client.URL, client.Token, http.MethodPost, "/metrics", metrics)
}

func (client *Client) PullTable() (*model.ProxyTable, error) {
	return fetch[model.ProxyTable](client.URL, client.Token, http.MethodGet, "/table", nil)
}
