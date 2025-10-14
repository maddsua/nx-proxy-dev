package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	nxproxy "github.com/maddsua/nx-proxy"
	"github.com/maddsua/nx-proxy/rest/model"
)

type ProcedureHandler struct {
	HandleFullConfig func(ctx context.Context, token *nxproxy.ServerToken) (*model.FullConfig, error)
	HandleStatus     func(ctx context.Context, token *nxproxy.ServerToken, status *model.Status) error
}

func NewHandler(proc ProcedureHandler) http.Handler {

	mux := http.NewServeMux()

	mux.Handle("GET /nxproxy/v1/config", http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {

		if proc.HandleFullConfig == nil {
			panic(fmt.Errorf("nx-proxy.ProcedureHandler.HandleFullConfig not implemented"))
		}

		if token := handleRequestAuth(wrt, req); token != nil {
			result, err := proc.HandleFullConfig(req.Context(), token)
			writeResponse(wrt, result, err)
		}
	}))

	mux.Handle("POST /nxproxy/v1/status", http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {

		if proc.HandleStatus == nil {
			panic(fmt.Errorf("nx-proxy.ProcedureHandler.HandleStatus not implemented"))
		}

		if status := handleRequestBody[model.Status](wrt, req); status != nil {
			if token := handleRequestAuth(wrt, req); token != nil {
				if err := proc.HandleStatus(req.Context(), token, status); err != nil {
					writeResponse[any](wrt, nil, err)
					return
				}
				wrt.WriteHeader(http.StatusNoContent)
			}
		}
	}))

	mux.Handle("GET /nxproxy/v1/ping", http.HandlerFunc(func(wrt http.ResponseWriter, _ *http.Request) {
		wrt.WriteHeader(http.StatusNoContent)
	}))

	return mux
}

func handleRequestBody[T any](wrt http.ResponseWriter, req *http.Request) *T {

	if !strings.Contains(strings.ToLower(req.Header.Get("Content-Type")), "json") {

		writeResponse[any](wrt, nil, &APIError{
			Message: "wrong request content type",
			Status:  http.StatusBadRequest,
		})

		return nil
	}

	var body T

	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {

		writeResponse[any](wrt, nil, &APIError{
			Message: fmt.Sprintf("decoder: %v", err),
			Status:  http.StatusBadRequest,
		})

		return nil
	}

	return &body
}

func handleRequestAuth(wrt http.ResponseWriter, req *http.Request) *nxproxy.ServerToken {

	var unwrapToken = func() (*nxproxy.ServerToken, error) {
		if schema, bearer, _ := strings.Cut(req.Header.Get("Authorization"), " "); strings.ToLower(schema) == "bearer" {
			return nxproxy.ParseServerToken(bearer)
		}
		return nil, nil
	}

	token, err := unwrapToken()
	if err != nil {

		writeResponse[any](wrt, nil, &APIError{
			Message: fmt.Sprintf("invalid token: %v", err),
			Status:  http.StatusBadRequest,
		})
		return nil

	} else if token == nil {

		writeResponse[any](wrt, nil, &APIError{
			Message: "unauthorized",
			Status:  http.StatusUnauthorized,
		})
		return nil
	}

	return token
}
