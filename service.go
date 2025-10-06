package nxproxy

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
)

//	todo: check if "prefix" is assigned to this machine

type Authenticator interface {
	LookupWithPassword(username, password string) (*Peer, error)
}

type ServiceHub struct {
	bindMap map[string]*Slot
	mtx     sync.Mutex
}

func (hub *ServiceHub) ImportServices(entries []ServiceOptions) {

	hub.mtx.Lock()
	defer hub.mtx.Unlock()

	if hub.bindMap == nil {
		hub.bindMap = map[string]*Slot{}
	}

	for _, service := range entries {

		bindAddr, err := ServiceBindAddr(service.Slot.BindAddr, service.Slot.Service)
		if err != nil {
			slog.Error("ServiceHub: ServiceBindAddr invalid",
				slog.String("val", service.Slot.BindAddr),
				slog.String("err", err.Error()))
			continue
		}

	}

	//	todo: import and diff
}

type ServiceOptions struct {
	Slot  SlotOptions   `json:"slot"`
	Peers []PeerOptions `json:"peers"`
}

func ServiceBindAddr(addr string, service ServiceType) (string, error) {

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
