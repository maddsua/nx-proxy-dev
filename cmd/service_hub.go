package main

import (
	"log/slog"
	"sync"

	nxproxy "github.com/maddsua/nx-proxy"

	http_proxy "github.com/maddsua/nx-proxy/http"
	"github.com/maddsua/nx-proxy/rest/model"
	socks5_proxy "github.com/maddsua/nx-proxy/socks5"
)

type ServiceHub struct {
	dns       dnsProvider
	bindMap   map[string]nxproxy.SlotService
	mtx       sync.Mutex
	oldDeltas []nxproxy.PeerDelta
	errSlots  []nxproxy.SlotInfo
}

func (hub *ServiceHub) SetConfig(cfg *model.FullConfig) {
	hub.SetDns(cfg.DNS)
	hub.SetServices(cfg.Services)
}

func (hub *ServiceHub) SetDns(addr string) {

	if addr == "" {
		hub.dns.resolver = nil
		hub.dns.addr = ""
		return
	}

	resolver, err := nxproxy.NewDnsResolver(addr)
	if err != nil {
		slog.Error("SetDns: NewDnsResolver",
			slog.String("addr", addr),
			slog.String("err", err.Error()))
		return
	}

	hub.dns.resolver = resolver
	hub.dns.addr = addr
}

func (hub *ServiceHub) SetServices(entries []nxproxy.ServiceOptions) {

	hub.mtx.Lock()
	defer hub.mtx.Unlock()

	if hub.bindMap == nil {
		hub.bindMap = map[string]nxproxy.SlotService{}
	}

	//	reset list of failed slots
	hub.errSlots = nil

	newBindMap := map[string]nxproxy.SlotService{}

	for _, entry := range entries {

		bindAddr, err := nxproxy.ServiceBindAddr(entry.BindAddr, entry.Proto)
		if err != nil {
			slog.Error("ServiceBindAddr invalid",
				slog.String("val", entry.BindAddr),
				slog.String("err", err.Error()))
			continue
		}

		if slot, has := hub.bindMap[bindAddr]; has {

			if err := slot.SetOptions(entry.SlotOptions); err == nil {

				slot.SetPeers(entry.Peers)

				//	remove from the old bind map
				newBindMap[bindAddr] = slot
				delete(hub.bindMap, bindAddr)

				info := slot.Info()

				slog.Debug("Update slot",
					slog.String("proto", string(info.Proto)),
					slog.String("addr", info.BindAddr))

				continue
			}

			if err := slot.Close(); err != nil {
				info := slot.Info()
				slog.Error("Replace slot: Close outdated slot",
					slog.String("addr", info.BindAddr),
					slog.String("err", err.Error()))
				continue
			}

			hub.oldDeltas = append(hub.oldDeltas, slot.Deltas()...)
		}

		var storeSlotErr = func(err error) {
			hub.errSlots = append(hub.errSlots, nxproxy.SlotInfo{
				Proto:    entry.Proto,
				BindAddr: entry.BindAddr,
				Up:       false,
				Error:    err.Error(),
			})
		}

		var slot nxproxy.SlotService
		switch entry.Proto {
		case nxproxy.ProxyProtoSocks:
			slot, err = socks5_proxy.NewService(entry.SlotOptions, &hub.dns)
		case nxproxy.ProxyProtoHttp:
			slot, err = http_proxy.NewService(entry.SlotOptions, &hub.dns)
		default:
			err = nxproxy.ErrUnsupportedProto
		}

		if err != nil {
			slog.Error("Unable to create slot",
				slog.String("proto", string(entry.Proto)),
				slog.String("bind_addr", entry.BindAddr),
				slog.String("err", err.Error()))
			storeSlotErr(err)
			continue
		}

		slot.SetPeers(entry.Peers)

		info := slot.Info()

		if _, has := hub.bindMap[bindAddr]; has {
			slog.Info("Replace slot",
				slog.String("type", string(info.Proto)),
				slog.String("addr", info.BindAddr))
		} else {
			slog.Info("Create slot",
				slog.String("type", string(info.Proto)),
				slog.String("addr", info.BindAddr))
		}

		newBindMap[bindAddr] = slot
	}

	//	remove slot entries that weren't updated
	for key, svc := range hub.bindMap {

		info := svc.Info()
		err := svc.Close()

		if newSvc, has := newBindMap[key]; has {

			newInfo := newSvc.Info()

			if err != nil {

				slog.Error("Slot failed to terminate; Unable to overwrite a newer slot entry",
					slog.String("type", string(info.Proto)),
					slog.String("addr", info.BindAddr),
					slog.String("err", err.Error()))

				slog.Warn("Possible service binding conflict",
					slog.String("addr", info.BindAddr))

				continue
			}

			slog.Info("Replace slot",
				slog.String("type", string(info.Proto)),
				slog.String("addr", info.BindAddr),
				slog.String("new_type", string(newInfo.Proto)))

			continue
		}

		if err != nil {
			slog.Error("Slot failed to terminate; Keeping and retrying again",
				slog.String("addr", info.BindAddr),
				slog.String("err", err.Error()))
			newBindMap[key] = svc
			continue
		}

		slog.Info("Remove slot",
			slog.String("type", string(info.Proto)),
			slog.String("addr", info.BindAddr))

		hub.oldDeltas = append(hub.oldDeltas, svc.Deltas()...)

		delete(hub.bindMap, key)
	}

	hub.bindMap = newBindMap
}

func (hub *ServiceHub) Deltas() []nxproxy.PeerDelta {

	hub.mtx.Lock()
	defer hub.mtx.Unlock()

	entries := append([]nxproxy.PeerDelta{}, hub.oldDeltas...)
	hub.oldDeltas = nil

	for _, slot := range hub.bindMap {
		entries = append(entries, slot.Deltas()...)
	}

	return entries
}

func (hub *ServiceHub) SlotInfo() []nxproxy.SlotInfo {

	hub.mtx.Lock()
	defer hub.mtx.Unlock()

	entries := append([]nxproxy.SlotInfo{}, hub.errSlots...)
	hub.errSlots = nil

	for _, slot := range hub.bindMap {
		entries = append(entries, slot.Info())
	}

	return entries
}

func (hub *ServiceHub) CloseSlots() {

	hub.mtx.Lock()
	defer hub.mtx.Unlock()

	hub.errSlots = nil

	for key, slot := range hub.bindMap {

		info := slot.Info()

		if err := slot.Close(); err != nil {
			slog.Error("Slot failed to terminate",
				slog.String("proto", string(info.Proto)),
				slog.String("addr", info.BindAddr),
				slog.String("err", err.Error()))
		} else {
			slog.Info("Terminate slot",
				slog.String("proto", string(info.Proto)),
				slog.String("addr", info.BindAddr))
		}

		hub.oldDeltas = append(hub.oldDeltas, slot.Deltas()...)

		delete(hub.bindMap, key)
	}
}
