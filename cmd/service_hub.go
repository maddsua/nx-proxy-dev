package main

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/google/uuid"
	nxproxy "github.com/maddsua/nx-proxy"

	http_proxy "github.com/maddsua/nx-proxy/http"
	"github.com/maddsua/nx-proxy/rest/model"
	socks5_proxy "github.com/maddsua/nx-proxy/socks5"
)

type ServiceHub struct {
	dns       dnsProvider
	bindMap   map[string]nxproxy.SlotService
	mtx       sync.Mutex
	oldDeltas []nxproxy.SlotDelta
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
		slog.Error("ServiceHub: SetDns: NewDnsResolver",
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

	importedSlotIDSet := map[uuid.UUID]struct{}{}

	var slotOptsValid = func(slot *nxproxy.SlotOptions) error {

		if slot.ID == uuid.Nil {
			return fmt.Errorf("slot id is null")
		}

		if _, has := importedSlotIDSet[slot.ID]; has {
			return fmt.Errorf("slot id not unique: %v", slot.ID)
		} else {
			importedSlotIDSet[slot.ID] = struct{}{}
		}

		if !slot.Proto.Valid() {
			return fmt.Errorf("slot service value invalid: %v", slot.Proto)
		}

		return nil
	}

	newBindMap := map[string]nxproxy.SlotService{}

	for _, entry := range entries {

		if err := slotOptsValid(&entry.SlotOptions); err != nil {
			slog.Warn("Service: Import slot: Entry invalid; Skipped",
				slog.String("slot_id", entry.ID.String()),
				slog.String("err", err.Error()))
			continue
		}

		bindAddr, err := nxproxy.ServiceBindAddr(entry.BindAddr, entry.Proto)
		if err != nil {
			slog.Error("ServiceHub: ServiceBindAddr invalid",
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

				slog.Debug("ServiceHub: Update slot",
					slog.String("id", info.ID.String()),
					slog.String("proto", string(info.Proto)),
					slog.String("addr", info.BindAddr))

				continue
			}

			if err := slot.Close(); err != nil {
				slog.Error("ServiceHub: Replace slot: Close outdated slot",
					slog.String("id", slot.Info().ID.String()),
					slog.String("err", err.Error()))
				continue
			}

			hub.oldDeltas = append(hub.oldDeltas, slot.Deltas()...)
		}

		var storeSlotErr = func(err error) {
			hub.errSlots = append(hub.errSlots, nxproxy.SlotInfo{
				ID:       entry.ID,
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
			slog.Error("ServiceHub: Unable to create slot",
				slog.String("id", entry.ID.String()),
				slog.String("proto", string(entry.Proto)),
				slog.String("proto", string(entry.Proto)))
			storeSlotErr(err)
			continue
		}

		slot.SetPeers(entry.Peers)

		info := slot.Info()

		if _, has := hub.bindMap[bindAddr]; has {
			slog.Info("ServiceHub: Replace slot",
				slog.String("id", info.ID.String()),
				slog.String("type", string(info.Proto)),
				slog.String("addr", info.BindAddr))
		} else {
			slog.Info("ServiceHub: Create slot",
				slog.String("id", info.ID.String()),
				slog.String("type", string(info.Proto)),
				slog.String("addr", info.BindAddr))
		}

		newBindMap[bindAddr] = slot
	}

	//	remove slot entries that weren't updated
	for key, slot := range hub.bindMap {

		info := slot.Info()

		if err := slot.Close(); err != nil {

			if newSlot, has := newBindMap[key]; has {

				newInfo := newSlot.Info()

				slog.Error("ServiceHub: Slot failed to terminate; Unable to overwrite a newer slot entry",
					slog.String("old_id", info.ID.String()),
					slog.String("new_id", newInfo.ID.String()),
					slog.String("type", string(info.Proto)),
					slog.String("addr", info.BindAddr),
					slog.String("err", err.Error()))
				slog.Warn("ServiceHub: Possible service binding conflict")

			} else {
				slog.Error("ServiceHub: Slot failed to terminate; Keeping and retrying again",
					slog.String("id", info.ID.String()),
					slog.String("err", err.Error()))
				newBindMap[key] = slot
			}

		} else {
			slog.Info("ServiceHub: Remove slot",
				slog.String("id", info.ID.String()),
				slog.String("type", string(info.Proto)),
				slog.String("addr", info.BindAddr))
		}

		hub.oldDeltas = append(hub.oldDeltas, slot.Deltas()...)

		delete(hub.bindMap, key)
	}

	hub.bindMap = newBindMap
}

func (hub *ServiceHub) Deltas() []nxproxy.SlotDelta {

	hub.mtx.Lock()
	defer hub.mtx.Unlock()

	entries := append([]nxproxy.SlotDelta{}, hub.oldDeltas...)
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
			slog.Error("ServiceHub: Slot failed to terminate",
				slog.String("id", info.ID.String()),
				slog.String("proto", string(info.Proto)),
				slog.String("addr", info.BindAddr),
				slog.String("err", err.Error()))
		} else {
			slog.Info("ServiceHub: Terminate slot",
				slog.String("id", info.ID.String()),
				slog.String("proto", string(info.Proto)),
				slog.String("addr", info.BindAddr))
		}

		hub.oldDeltas = append(hub.oldDeltas, slot.Deltas()...)

		delete(hub.bindMap, key)
	}
}
