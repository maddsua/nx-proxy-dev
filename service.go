package nxproxy

import (
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"sync"

	"github.com/google/uuid"
	socksv5 "github.com/maddsua/nx-proxy/socks_v5"
)

type Authenticator interface {
	LookupWithPassword(username, password string) (*Peer, error)
}

type ServiceHub struct {
	bindMap        map[string]*Slot
	mtx            sync.Mutex
	deferredDeltas []SlotDelta
}

func (hub *ServiceHub) ImportServices(entries []ServiceOptions) {

	hub.mtx.Lock()
	defer hub.mtx.Unlock()

	if hub.bindMap == nil {
		hub.bindMap = map[string]*Slot{}
	}

	importedSlotIDSet := map[uuid.UUID]struct{}{}

	var slotServiceOk = func(slot *Slot) bool {
		return slot.Server != nil && slot.Server.Error() == nil
	}

	var isSameSlotService = func(slot *Slot, opt *ServiceOptions) bool {
		return slot.SlotOptions.Proto == opt.Slot.Proto
	}

	var slotOptsValid = func(slot *SlotOptions) error {

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

	newBindMap := map[string]*Slot{}

	for _, entry := range entries {

		if err := slotOptsValid(&entry.Slot); err != nil {
			slog.Warn("Service: Import slot: Entry invalid; Skipped",
				slog.String("slot_id", entry.Slot.ID.String()),
				slog.String("err", err.Error()))
			continue
		}

		bindAddr, err := ServiceBindAddr(entry.Slot.BindAddr, entry.Slot.Proto)
		if err != nil {
			slog.Error("ServiceHub: ServiceBindAddr invalid",
				slog.String("val", entry.Slot.BindAddr),
				slog.String("err", err.Error()))
			continue
		}

		if slot, has := hub.bindMap[bindAddr]; has {

			if isSameSlotService(slot, &entry) && slotServiceOk(slot) {

				//	update options and peer list
				slot.SlotOptions = entry.Slot
				slot.ImportPeerList(entry.Peers)

				//	remove from the old bind map
				newBindMap[bindAddr] = slot
				delete(hub.bindMap, bindAddr)

				slog.Debug("ServiceHub: Update slot",
					slog.String("id", slot.ID.String()),
					slog.String("type", string(slot.SlotOptions.Proto)),
					slog.String("addr", slot.SlotOptions.BindAddr))

				continue
			}

			if err := slot.Close(); err != nil {
				slog.Error("ServiceHub: Replace slot: Close old slot",
					slog.String("id", slot.ID.String()),
					slog.String("err", err.Error()))
				continue
			}

			hub.deferredDeltas = append(hub.deferredDeltas, slot.Deltas()...)
		}

		slot := Slot{SlotOptions: entry.Slot}
		slot.ImportPeerList(entry.Peers)

		switch slot.SlotOptions.Proto {
		case ServiceTypeSocks:
			slot.Server = &socksv5.Server{Addr: bindAddr, Auth: &slot}
		default:
			//	todo: replace with a http impl
			slot.Server = &DummyService{Addr: slot.BindAddr, Auth: &slot, DisplayType: string(entry.Slot.Proto)}
		}

		if err := slot.Server.ListenAndServe(); err != nil {
			slog.Error("ServiceHub: Create slot: Start service",
				slog.String("id", slot.ID.String()),
				slog.String("type", string(slot.SlotOptions.Proto)),
				slog.String("err", err.Error()))
			continue
		}

		if _, has := hub.bindMap[bindAddr]; has {
			slog.Info("ServiceHub: Replace slot",
				slog.String("id", slot.ID.String()),
				slog.String("type", string(slot.SlotOptions.Proto)),
				slog.String("addr", slot.SlotOptions.BindAddr))
		} else {
			slog.Info("ServiceHub: Create slot",
				slog.String("id", slot.ID.String()),
				slog.String("type", string(slot.SlotOptions.Proto)),
				slog.String("addr", slot.SlotOptions.BindAddr))
		}

		newBindMap[bindAddr] = &slot
	}

	//	remove slot entries that weren't updated
	for key, slot := range hub.bindMap {

		if err := slot.Close(); err != nil {

			if newSlot, has := newBindMap[key]; has {
				slog.Error("ServiceHub: Slot failed to terminate; Keeping and retrying again",
					slog.String("old_id", slot.ID.String()),
					slog.String("new_id", newSlot.ID.String()),
					slog.String("err", err.Error()))
				newBindMap[key] = slot
			} else {
				slog.Error("ServiceHub: Slot failed to terminate; Unable to overwrite a newer slot entry",
					slog.String("old_id", slot.ID.String()),
					slog.String("new_id", newSlot.ID.String()),
					slog.String("type", string(slot.SlotOptions.Proto)),
					slog.String("addr", slot.SlotOptions.BindAddr),
					slog.String("err", err.Error()))
				slog.Warn("ServiceHub: Possible service binding conflict")
			}

		} else {
			slog.Info("ServiceHub: Remove outdated slot",
				slog.String("id", slot.ID.String()),
				slog.String("type", string(slot.SlotOptions.Proto)),
				slog.String("addr", slot.SlotOptions.BindAddr))
		}

		hub.deferredDeltas = append(hub.deferredDeltas, slot.Deltas()...)

		delete(hub.bindMap, key)
	}

	hub.bindMap = newBindMap
}

func (hub *ServiceHub) Deltas() []SlotDelta {

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
				slog.String("id", slot.ID.String()),
				slog.String("type", string(slot.SlotOptions.Proto)),
				slog.String("addr", slot.SlotOptions.BindAddr),
				slog.String("err", err.Error()))
		} else {
			slog.Info("ServiceHub: Terminate slot",
				slog.String("id", slot.ID.String()),
				slog.String("type", string(slot.SlotOptions.Proto)),
				slog.String("addr", slot.SlotOptions.BindAddr))
		}

		hub.deferredDeltas = append(hub.deferredDeltas, slot.Deltas()...)

		delete(hub.bindMap, key)
	}
}

type ServiceOptions struct {
	Slot  SlotOptions   `json:"slot"`
	Peers []PeerOptions `json:"peers"`
}

func ServiceBindAddr(addr string, service ProxyProto) (string, error) {

	prefix, suffix, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("split addr: %v", err)
	}

	if ip := net.ParseIP(prefix); ip == nil {
		return "", fmt.Errorf("parse host: not an ip address")
	}

	port, err := strconv.Atoi(suffix)
	if err != nil {
		return "", fmt.Errorf("parse port: %v", err)
	}

	var networkSuffix string
	switch service {
	case ServiceTypeHttp, ServiceTypeSocks:
		networkSuffix = "/tcp"
		//	udp support can be added here in the future
	}

	return net.JoinHostPort(prefix, strconv.Itoa(port)) + networkSuffix, nil
}
