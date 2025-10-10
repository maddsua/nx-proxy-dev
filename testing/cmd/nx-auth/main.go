package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	nxproxy "github.com/maddsua/nx-proxy"
	"github.com/maddsua/nx-proxy/rest/model"
)

func main() {

	fmt.Printf("\n----- WARNING -----\n\n")

	fmt.Println("THIS PROGRAM IS INTENDED FOR DEVELOPMENT PURPOSES")
	fmt.Println("AND UNDER ANY CIRCUMSTANCES SHOULD NOT BE EXPOSED")
	fmt.Println("TO THE PUBLIC INTERNET IN ANY CAPACITY")

	fmt.Printf("\n ----- \n\n")

	slog.SetLogLoggerLevel(slog.LevelDebug)

	cfg, err := LoadConfig("")
	if err != nil {
		slog.Error("Load config",
			slog.String("err", err.Error()))
		os.Exit(1)
	}

	mux := http.NewServeMux()

	mux.Handle("GET /config", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if val, err := LoadConfig(cfg.location); err != nil {
			slog.Error("Reload config",
				slog.String("loc", cfg.location),
				slog.String("err", err.Error()))
		} else {
			cfg.Proxy = val.Proxy
		}

		w.Header().Set("Content-Type", "application/json")

		var services []nxproxy.ServiceOptions
		for _, entry := range cfg.Proxy.Services {

			var peers []nxproxy.PeerOptions

			for _, entry := range entry.Peers {
				peers = append(peers, nxproxy.PeerOptions{
					ID: entry.ID,
					PasswordAuth: &nxproxy.PeerPasswordAuth{
						UserName: entry.UserName,
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

		json.NewEncoder(w).Encode(map[string]any{
			"data": model.FullConfig{
				Services: services,
				DNS:      cfg.Proxy.Dns,
			},
		})
	}))

	mux.Handle("POST /metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		defer w.WriteHeader(http.StatusNoContent)

		var metrics model.Metrics

		if err := json.NewDecoder(r.Body).Decode(&metrics); err != nil {
			slog.Error("Decode metrics",
				slog.String("err", err.Error()))
			return
		}

		slog.Info("Uptime",
			slog.String("run_id", metrics.Service.RunID.String()),
			slog.Duration("t", time.Duration(metrics.Service.Uptime)*time.Second))

		for _, delta := range metrics.Deltas {
			slog.Info("Delta",
				slog.String("peer", delta.PeerID.String()),
				slog.Int("rx", int(delta.Rx)),
				slog.Int("tx", int(delta.Tx)))
		}
	}))

	srv := http.Server{
		Addr:    cfg.ListenAddr,
		Handler: mux,
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
