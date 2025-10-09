package nxproxy

import "net"

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
