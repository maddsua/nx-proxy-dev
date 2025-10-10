package main

import (
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	nxproxy "github.com/maddsua/nx-proxy"
	"github.com/maddsua/nx-proxy/rest"
	"github.com/maddsua/nx-proxy/rest/model"
)

func main() {

	configFileEntries := LoadConfigFile()
	if configFileEntries == nil {
		slog.Warn("No config files found")
	}

	if val, _ := GetConfigOpt(configFileEntries, "DEBUG"); strings.ToLower(val) == "true" {
		slog.SetLogLoggerLevel(slog.LevelDebug)
		slog.Debug("ENABLED")
	}

	var client rest.Client

	if val, ok := GetConfigOpt(configFileEntries, "SECRET_TOKEN"); ok {
		token, err := nxproxy.ParseServerToken(val)
		if err != nil {
			slog.Error("STARTUP: Parse secret token",
				slog.String("err", err.Error()))
			os.Exit(1)
		}
		client.Token = token
	} else {
		slog.Warn("STARTUP: Secret token not provided")
	}

	if val, ok := GetConfigOpt(configFileEntries, "AUTH_URL"); ok {

		url, err := url.Parse(val)
		if err != nil {
			slog.Error("STARTUP: Parse auth server url",
				slog.String("err", err.Error()))
			os.Exit(1)
		}
		client.URL = url

	} else {
		slog.Error("STARTUP: Auth server url not provided")
		os.Exit(1)
	}

	var hub ServiceHub
	var wg sync.WaitGroup

	runID := uuid.New()
	runAt := time.Now()
	doneCh := make(chan struct{})

	wg.Add(2)

	go func() {

		var retryQueue []nxproxy.SlotDelta

		defer wg.Done()

		var doUpdate = func() {

			metrics := model.Metrics{
				Deltas: append(retryQueue, hub.Deltas()...),
				Service: model.ServiceInfo{
					RunID:  runID,
					Uptime: int64(time.Since(runAt).Seconds()),
				},
			}

			if err := client.PostMetrics(&metrics); err != nil {
				slog.Error("API: PostMetrics",
					slog.String("err", err.Error()))
				retryQueue = metrics.Deltas
				return
			}

			retryQueue = nil

			slog.Debug("API: Metrics sent",
				slog.String("remote", client.URL.Host),
				slog.Int("deltas", len(metrics.Deltas)))
		}

		ticker := time.NewTicker(30 * time.Second)

		for {
			select {
			case <-ticker.C:
				doUpdate()
			case <-doneCh:
				doUpdate()
				return
			}
		}
	}()

	go func() {

		defer wg.Done()

		var pullConfig = func() {

			cfg, err := client.PullConfig()
			if err != nil {
				slog.Error("API: Pulling config",
					slog.String("err", err.Error()),
					slog.String("remote", client.URL.Host))
				return
			}

			slog.Debug("API: Updating config",
				slog.String("remote", client.URL.Host))

			hub.SetConfig(cfg)

			slog.Debug("API: Config updated")
		}

		ticker := time.NewTicker(15 * time.Second)

		for {

			pullConfig()

			select {
			case <-ticker.C:
				continue
			case <-doneCh:
				return
			}
		}
	}()

	exitCh := make(chan os.Signal, 1)
	signal.Notify(exitCh, os.Interrupt, syscall.SIGTERM)

	exitSignal := <-exitCh
	slog.Warn("Received an exit signal",
		slog.String("type", exitSignal.String()))

	close(doneCh)
	hub.CloseSlots()

	slog.Debug("Routine: Waiting for tasks to finish")
	wg.Wait()

	slog.Warn("Service stopped. Bye-Bye...")
}

type dnsProvider struct {
	resolver *net.Resolver
	addr     string
}

func (prov *dnsProvider) Addr() string {
	return prov.addr
}

func (prov *dnsProvider) Resolver() *net.Resolver {
	return prov.resolver
}
