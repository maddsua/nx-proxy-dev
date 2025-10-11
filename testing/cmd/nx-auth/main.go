package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	nxproxy "github.com/maddsua/nx-proxy"
	"github.com/maddsua/nx-proxy/rest"
	"github.com/maddsua/nx-proxy/rest/model"
)

func main() {

	slog.SetLogLoggerLevel(slog.LevelDebug)

	cfg, err := LoadConfig("")
	if err != nil {
		slog.Error("Load config",
			slog.String("err", err.Error()))
		os.Exit(1)
	}

	handler := rest.ProcedureHandler{

		HandleFullConfig: func(ctx context.Context, token *nxproxy.ServerToken) (*model.FullConfig, error) {

			if token == nil {
				return nil, fmt.Errorf("unauthorized")
			}

			slog.Info("Sending config",
				slog.String("token_id", token.ID.String()))

			if val, err := LoadConfig(cfg.location); err != nil {
				slog.Error("Reload config",
					slog.String("loc", cfg.location),
					slog.String("err", err.Error()))
			} else {
				cfg.Proxy = val.Proxy
			}

			var services []nxproxy.ServiceOptions
			for _, entry := range cfg.Proxy.Services {

				var peers []nxproxy.PeerOptions

				for _, entry := range entry.Peers {
					peers = append(peers, nxproxy.PeerOptions{
						ID: entry.ID,
						PasswordAuth: &nxproxy.UserPassword{
							User:     entry.UserName,
							Password: entry.Password,
						},
						MaxConnections: entry.MaxConnections,
						FramedIP:       entry.FramedIP,
						Bandwidth: nxproxy.PeerBandwidth{
							Rx: entry.RxRate,
							Tx: entry.TxRate,
						},
					})
				}

				services = append(services, nxproxy.ServiceOptions{
					Peers: peers,
					SlotOptions: nxproxy.SlotOptions{
						ID:       entry.ID,
						Proto:    nxproxy.ProxyProto(entry.Proto),
						BindAddr: entry.BindAddr,
					},
				})
			}

			return &model.FullConfig{
				Services: services,
				DNS:      cfg.Proxy.Dns,
			}, nil
		},

		HandleStatus: func(ctx context.Context, token *nxproxy.ServerToken, status *model.Status) error {

			if token == nil {
				return fmt.Errorf("unauthorized")
			}

			data, _ := json.MarshalIndent(status, "", "  ")
			slog.Info("Dumping status",
				slog.String("token_id", token.ID.String()))
			fmt.Print(string(data))

			return nil
		},
	}

	srv := http.Server{
		Addr:    cfg.ListenAddr,
		Handler: rest.NewHandler(handler),
	}

	errCh := make(chan error, 1)
	exitCh := make(chan os.Signal, 1)
	signal.Notify(exitCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			errCh <- err
		}
	}()

	slog.Info("Listening",
		slog.String("addr", srv.Addr))

	select {
	case <-exitCh:
		srv.Close()
	case err := <-errCh:
		slog.Error("Serve",
			slog.String("err", err.Error()))
		os.Exit(1)
	}
}
