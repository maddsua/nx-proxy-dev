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

	lock, err := NewInstanceLock()
	if err != nil {
		slog.Error("Another running instance detected. Aborting")
		os.Exit(1)
	}

	defer lock.Unlock()

	cfgEntries, cfgLocation := LoadConfigFile()
	if cfgEntries == nil {
		slog.Warn("No config files found")
	} else {
		slog.Info("Loaded config",
			slog.String("loc", cfgLocation))
	}

	if val, _ := GetConfigOpt(cfgEntries, "DEBUG"); strings.ToLower(val) == "true" {
		slog.SetLogLoggerLevel(slog.LevelDebug)
		slog.Debug("ENABLED")
	}

	var client rest.Client

	if val, ok := GetConfigOpt(cfgEntries, "SECRET_TOKEN"); ok {
		token, err := nxproxy.ParseServerToken(val)
		if err != nil {
			slog.Error("Parse secret token",
				slog.String("err", err.Error()))
			os.Exit(1)
		}
		client.Token = token
	} else {
		slog.Warn("Secret token not provided")
	}

	if val, ok := GetConfigOpt(cfgEntries, "AUTH_URL"); ok {

		url, err := url.Parse(val)
		if err != nil {
			slog.Error("Parse auth server url",
				slog.String("err", err.Error()))
			os.Exit(1)
		}
		client.URL = url

	} else {
		slog.Error("Auth server url not provided")
		os.Exit(1)
	}

	var hub ServiceHub
	var wg sync.WaitGroup

	runID := uuid.New()
	runAt := time.Now()
	doneCh := make(chan struct{})

	var doConfigPull = func() {

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

	deltasQueue := make([]nxproxy.SlotDelta, 0)

	var doStatusPush = func() {

		newDeltas := hub.Deltas()

		metrics := model.Status{
			Deltas: append(deltasQueue, newDeltas...),
			Slots:  hub.SlotInfo(),
			Service: model.ServiceInfo{
				RunID:  runID,
				Uptime: int64(time.Since(runAt).Seconds()),
			},
		}

		if err := client.PostStatus(&metrics); err != nil {
			slog.Error("API: PostMetrics",
				slog.String("err", err.Error()))
			deltasQueue = append(deltasQueue, newDeltas...)
			return
		}

		deltasQueue = make([]nxproxy.SlotDelta, 0)

		slog.Debug("API: Metrics sent",
			slog.String("remote", client.URL.Host),
			slog.Int("deltas", len(metrics.Deltas)))
	}

	doConfigPull()
	doStatusPush()

	wg.Add(2)

	go func() {

		defer wg.Done()

		ticker := time.NewTicker(15 * time.Second)

		for {

			select {
			case <-ticker.C:
				doConfigPull()
			case <-doneCh:
				return
			}
		}
	}()

	go func() {

		defer wg.Done()

		ticker := time.NewTicker(10 * time.Second)

		for {
			select {
			case <-ticker.C:
				doStatusPush()
			case <-doneCh:
				doStatusPush()
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
