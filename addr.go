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

func SplitNetworkType(addr string) (string, string, bool) {

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
