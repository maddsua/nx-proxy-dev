package nxproxy

import (
	"fmt"
	"net"
	"strconv"
)

type PasswordAuthenticator interface {
	LookupWithPassword(username, password string) (*Peer, error)
}

type SlotServer interface {
	ListenAndServe() error
	Error() error
	Close() error
}

type ProxyProto string

func (val ProxyProto) Valid() bool {
	return val == ProxyProtoHttp || val == ProxyProtoSocks
}

const (
	ProxyProtoSocks = ProxyProto("socks")
	ProxyProtoHttp  = ProxyProto("http")
)

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
	case ProxyProtoHttp, ProxyProtoSocks:
		networkSuffix = "/tcp"
		//	udp support can be added here in the future
	}

	return net.JoinHostPort(prefix, strconv.Itoa(port)) + networkSuffix, nil
}
