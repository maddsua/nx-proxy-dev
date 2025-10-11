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
	Data  *T        `json:"data"`
	Error *APIError `json:"error"`
}

func (resp *Response[T]) Write(wrt io.Writer) error {
	return json.NewEncoder(wrt).Encode(resp)
}

func writeResponse[T any](wrt http.ResponseWriter, val *T, err error) {

	wrt.Header().Set("Content-Type", "application/json")

	resp := Response[T]{Data: val}

	if err != nil {

		if apierr, ok := err.(*APIError); ok {
			resp.Error = apierr
		} else {
			resp.Error = &APIError{Message: err.Error()}
		}

		if err, ok := err.(StatusCoder); ok {
			wrt.WriteHeader(err.StatusCode())
		} else {
			wrt.WriteHeader(http.StatusBadRequest)
		}
	}

	resp.Write(wrt)
}

func decodeResponse[T any](reader io.Reader) (*Response[T], error) {

	var val Response[T]
	if err := json.NewDecoder(reader).Decode(&val); err != nil && err != io.EOF {
		return nil, err
	}

	return &val, nil
}

type StatusCoder interface {
	StatusCode() int
}

type APIError struct {
	Message string `json:"message"`
	Status  int    `json:"-"`
}

func (err *APIError) Error() string {
	return "api: " + err.Message
}

func (err *APIError) StatusCode() int {
	if status := err.Status; status >= http.StatusBadRequest {
		return status
	}
	return http.StatusBadRequest
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
		if err := json.NewEncoder(&buff).Encode(payload); err != nil {
			return nil, fmt.Errorf("marshal: %v", err)
		}
		bodyReader = &buff
	}

	req, err := http.NewRequest(method, reqUrl.String(), bodyReader)
	if err != nil {
		return nil, err
	}

	if token != nil {
		bearer := strings.Join([]string{"Bearer", token.String()}, " ")
		req.Header.Set("Authorization", bearer)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {

		if err, ok := err.(*url.Error); ok {
			return nil, err.Err
		}

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
			return nil, apiResp.Error
		} else if apiResp.Data == nil {
			return nil, fmt.Errorf("api: empty data payload")
		}

		return apiResp.Data, nil
	}

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http: %s", resp.Status)
	}

	return nil, fmt.Errorf("no supported data returned (http: %s)", resp.Status)
}
