package main

import (
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/google/uuid"
	nxproxy "github.com/maddsua/nx-proxy"

	"github.com/maddsua/nx-proxy/rest/model"
	socksv5 "github.com/maddsua/nx-proxy/socks5"
)

type ServiceHub struct {
	dns            dnsProvider
	bindMap        map[string]nxproxy.SlotService
	mtx            sync.Mutex
	deferredDeltas []nxproxy.SlotDelta
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

				slog.Debug("ServiceHub: Update slot",
					slog.String("id", slot.ID().String()),
					slog.String("proto", string(slot.Proto())),
					slog.String("addr", slot.BindAddr()))

				continue
			}

			if err := slot.Close(); err != nil {
				slog.Error("ServiceHub: Replace slot: Close outdated slot",
					slog.String("id", slot.ID().String()),
					slog.String("err", err.Error()))
				continue
			}

			hub.deferredDeltas = append(hub.deferredDeltas, slot.Deltas()...)
		}

		var slot nxproxy.SlotService

		switch entry.Proto {
		case nxproxy.ProxyProtoSocks:
			if slot, err = socksv5.NewService(entry.SlotOptions, &hub.dns); err != nil {
				slog.Error("ServiceHub: Create slot: Socks5",
					slog.String("id", slot.ID().String()),
					slog.String("err", err.Error()))
				continue
			}
		default:
			slog.Error("ServiceHub: Create slot: Unsupported service protocol",
				slog.String("id", entry.ID.String()),
				slog.String("proto", string(entry.Proto)))
			continue
		}

		slot.SetPeers(entry.Peers)

		if _, has := hub.bindMap[bindAddr]; has {
			slog.Info("ServiceHub: Replace slot",
				slog.String("id", slot.ID().String()),
				slog.String("type", string(slot.Proto())),
				slog.String("addr", slot.BindAddr()))
		} else {
			slog.Info("ServiceHub: Create slot",
				slog.String("id", slot.ID().String()),
				slog.String("type", string(slot.Proto())),
				slog.String("addr", slot.BindAddr()))
		}

		newBindMap[bindAddr] = slot
	}

	//	remove slot entries that weren't updated
	for key, slot := range hub.bindMap {

		if err := slot.Close(); err != nil {

			if newSlot, has := newBindMap[key]; has {
				slog.Error("ServiceHub: Slot failed to terminate; Keeping and retrying again",
					slog.String("old_id", slot.ID().String()),
					slog.String("new_id", newSlot.ID().String()),
					slog.String("err", err.Error()))
				newBindMap[key] = slot
			} else {
				slog.Error("ServiceHub: Slot failed to terminate; Unable to overwrite a newer slot entry",
					slog.String("old_id", slot.ID().String()),
					slog.String("new_id", newSlot.ID().String()),
					slog.String("type", string(slot.Proto())),
					slog.String("addr", slot.BindAddr()),
					slog.String("err", err.Error()))
				slog.Warn("ServiceHub: Possible service binding conflict")
			}

		} else {
			slog.Info("ServiceHub: Remove slot",
				slog.String("id", slot.ID().String()),
				slog.String("type", string(slot.Proto())),
				slog.String("addr", slot.BindAddr()))
		}

		hub.deferredDeltas = append(hub.deferredDeltas, slot.Deltas()...)

		delete(hub.bindMap, key)
	}

	hub.bindMap = newBindMap
}

func (hub *ServiceHub) Deltas() []nxproxy.SlotDelta {

	hub.mtx.Lock()
	defer hub.mtx.Unlock()

	entries := slices.Clone(hub.deferredDeltas)
	hub.deferredDeltas = nil

	for _, slot := range hub.bindMap {
		entries = append(entries, slot.Deltas()...)
	}

	return entries
}

func (hub *ServiceHub) CloseSlots() {

	hub.mtx.Lock()
	defer hub.mtx.Unlock()

	for key, slot := range hub.bindMap {

		if err := slot.Close(); err != nil {
			slog.Error("ServiceHub: Slot failed to terminate",
				slog.String("id", slot.ID().String()),
				slog.String("proto", string(slot.Proto())),
				slog.String("addr", slot.BindAddr()),
				slog.String("err", err.Error()))
		} else {
			slog.Info("ServiceHub: Terminate slot",
				slog.String("id", slot.ID().String()),
				slog.String("proto", string(slot.Proto())),
				slog.String("addr", slot.BindAddr()))
		}

		hub.deferredDeltas = append(hub.deferredDeltas, slot.Deltas()...)

		delete(hub.bindMap, key)
	}
}
