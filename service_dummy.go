package nxproxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/maddsua/nx-proxy/proxy"
)

type DummyService struct {
	Addr        string
	Auth        proxy.Authenticator
	DisplayType string
	closed      atomic.Bool
	srv         http.Server
	err         error
}

func (svc *DummyService) ListenAndServe() error {

	svc.err = nil

	svc.srv.Addr = svc.Addr
	svc.srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "test service handler; auth: %T; type: %s\n", svc.Auth, svc.DisplayType)
	})

	go func() {
		if err := svc.srv.ListenAndServe(); err != nil {

			if svc.closed.Load() {
				return
			}

			svc.err = err
			slog.Error("DummyService: ListenAndServe",
				slog.String("err", err.Error()))
		}
	}()

	return nil
}

func (svc *DummyService) Error() error {
	return svc.err
}

func (svc *DummyService) Close() error {
	svc.closed.Store(true)
	return svc.srv.Close()
}
