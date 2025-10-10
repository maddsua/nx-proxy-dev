package nxproxy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func GetAddrPort(addr net.Addr) (net.IP, int) {

	if addr, ok := addr.(*net.TCPAddr); ok {
		return addr.IP, addr.Port
	}

	if addr, ok := addr.(*net.UDPAddr); ok {
		return addr.IP, addr.Port
	}

	return nil, 0
}

func IsLocalAddress(addr string) bool {

	ipAddr, _ := net.ResolveIPAddr("ip", addr)
	if ipAddr == nil {
		return false
	}

	return ipAddr.IP.IsLoopback() || ipAddr.IP.IsPrivate() || ipAddr.IP.IsUnspecified()
}

func SplitAddrNet(addr string) (string, string, bool) {

	if val, ok := strings.CutSuffix(addr, "/tcp"); ok {
		return val, "tcp", true
	}

	if val, ok := strings.CutSuffix(addr, "/udp"); ok {
		return val, "udp", true
	}

	return addr, "tcp", false
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

func ParseFramedIP(addr string) (net.IP, error) {

	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("invalid addr: %s", addr)
	}

	if assigned, err := AddrAssigned(ip); err != nil {
		return nil, fmt.Errorf("check ip tables: %v", err)
	} else if !assigned {
		return nil, fmt.Errorf("addr not assigned: %s", addr)
	}

	return ip, nil
}

func TcpDialAddr(addr net.IP) net.Addr {
	if addr != nil && !addr.IsLoopback() {
		return &net.TCPAddr{IP: addr}
	}
	return nil
}

type AddrContainer interface {
	Contains(val net.IP) bool
}

func AddrAssigned(addr net.IP) (bool, error) {

	table, err := net.InterfaceAddrs()
	if err != nil {
		return false, err
	}

	for _, val := range table {
		if val, ok := val.(AddrContainer); ok {
			if val.Contains(addr) {
				return true, nil
			}
		}
	}

	return false, nil
}
