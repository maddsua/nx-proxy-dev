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

	var panicHandler = func(wrt http.ResponseWriter) {
		if rec := recover(); rec != nil {
			writeResponse[any](wrt, nil, &APIError{
				Message: fmt.Sprintf("handler panicked: %v", rec),
				Status:  http.StatusInternalServerError,
			})
		}
	}

	var handlerNotImplemented = func(wrt http.ResponseWriter) {
		writeResponse[any](wrt, nil, &APIError{
			Message: "procedure not implemented",
			Status:  http.StatusNotImplemented,
		})
	}

	mux := http.NewServeMux()

	mux.Handle("GET /nxproxy/v1/config", http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {

		if proc.HandleFullConfig == nil {
			handlerNotImplemented(wrt)
			return
		}

		defer panicHandler(wrt)

		result, err := proc.HandleFullConfig(req.Context(), requestToken(req))
		writeResponse(wrt, result, err)
	}))

	mux.Handle("POST /nxproxy/v1/status", http.HandlerFunc(func(wrt http.ResponseWriter, req *http.Request) {

		if proc.HandleStatus == nil {
			handlerNotImplemented(wrt)
			return
		}

		defer panicHandler(wrt)

		status, err := requestBody[model.Status](req)
		if err != nil {
			writeResponse[any](wrt, nil, err)
			return
		}

		if err = proc.HandleStatus(req.Context(), requestToken(req), status); err != nil {
			writeResponse[any](wrt, nil, err)
			return
		}

		wrt.WriteHeader(http.StatusNoContent)
	}))

	return mux
}

func requestToken(req *http.Request) *nxproxy.ServerToken {

	if schema, bearer, _ := strings.Cut(req.Header.Get("Authorization"), " "); strings.ToLower(schema) == "bearer" {
		token, _ := nxproxy.ParseServerToken(bearer)
		return token
	}

	return nil
}

func requestBody[T any](req *http.Request) (*T, error) {

	if !strings.Contains(strings.ToLower(req.Header.Get("Content-Type")), "json") {
		return nil, &APIError{
			Message: "wrong request content type",
			Status:  http.StatusBadRequest,
		}
	}

	var body T

	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		return nil, &APIError{
			Message: fmt.Sprintf("decoder: %v", err),
			Status:  http.StatusBadRequest,
		}
	}

	return &body, nil
}
