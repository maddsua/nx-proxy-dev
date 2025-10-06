package rest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	nxproxy "github.com/maddsua/nx-proxy"
)

type Response[T any] struct {
	Data  *T     `json:"data"`
	Error *Error `json:"error"`
}

func decodeResponse[T any](reader io.Reader) (*Response[T], error) {

	var val Response[T]
	if err := json.NewDecoder(reader).Decode(&val); err != nil && err != io.EOF {
		return nil, err
	}

	return &val, nil
}

type Error struct {
	Message string `json:"message"`
}

func beacon(baseUrl *url.URL, token *nxproxy.ServerToken, method string, path string, payload any) error {
	if _, err := fetch[any](baseUrl, token, method, path, payload); err != nil {
		return err
	}
	return nil
}

func fetch[T any](baseUrl *url.URL, token *nxproxy.ServerToken, method string, path string, payload any) (*T, error) {

	if baseUrl == nil {
		return nil, fmt.Errorf("remote url not set")
	}

	reqUrl := url.URL{
		Scheme:   baseUrl.Scheme,
		Host:     baseUrl.Host,
		Path:     strings.TrimRight(baseUrl.Path, "/") + path,
		RawQuery: baseUrl.RawQuery,
	}

	var bodyReader io.Reader
	if payload != nil {
		var buff bytes.Buffer
		if err := json.NewEncoder(&buff).Encode(path); err != nil {
			return nil, fmt.Errorf("marshal: %v", err)
		}
		bodyReader = &buff
	}

	req, err := http.NewRequest(method, reqUrl.String(), bodyReader)
	if err != nil {
		return nil, err
	}

	if token != nil {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.String()))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	req = nil

	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	}

	if strings.Contains(resp.Header.Get("Content-Type"), "json") {

		apiResp, err := decodeResponse[T](resp.Body)
		if err != nil {
			return nil, fmt.Errorf("decode: %v", err)
		}

		if apiResp.Error != nil {
			return nil, fmt.Errorf("api: %v", apiResp.Error.Message)
		}

		return apiResp.Data, nil
	}

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http: %s", resp.Status)
	}

	return nil, fmt.Errorf("no supported data returned (http: %s)", resp.Status)
}
