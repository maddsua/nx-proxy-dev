package model

import (
	"github.com/google/uuid"
	nxproxy "github.com/maddsua/nx-proxy"
	"github.com/maddsua/nx-proxy/proxy"
)

type ProxyTable struct {
	Services []nxproxy.ServiceOptions `json:"services"`
}

type Metrics struct {
	Service ServiceInfo       `json:"service"`
	Deltas  []proxy.SlotDelta `json:"deltas"`
}

type ServiceInfo struct {
	RunID  uuid.UUID `json:"run_id"`
	Uptime int64     `json:"uptime"`
}
