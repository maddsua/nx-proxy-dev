package nxproxy

import (
	"context"
	"fmt"
	"net"
	"time"
)

type DnsProvider interface {
	Resolver() *net.Resolver
}

func NewDnsResolver(addr string) (*net.Resolver, error) {

	const defaultTimeout = 10 * time.Second

	//	set default DNS udp port
	var hostname string
	if host, _, err := net.SplitHostPort(addr); err != nil {
		hostname = addr
		addr = fmt.Sprintf("%s:%d", addr, 53)
	} else {
		hostname = host
	}

	//	check that hostname is correct
	if addr, _ := net.ResolveIPAddr("ip", hostname); addr == nil {
		return nil, fmt.Errorf("dns resolver: server unknown: %s", hostname)
	}

	//	make sure the server is actually up and running
	if err := ProbeDnsServer(addr); err != nil {
		return nil, fmt.Errorf("dns resolver: couldn't connect to the server at %s: %v", hostname, err)
	}

	dialer := net.Dialer{Timeout: defaultTimeout}

	var dialOverride = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	return &net.Resolver{
		PreferGo: true,
		Dial:     dialOverride,
	}, nil
}
