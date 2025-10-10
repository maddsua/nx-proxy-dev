package model

import (
	"github.com/google/uuid"
	nxproxy "github.com/maddsua/nx-proxy"
)

type FullConfig struct {
	Services []nxproxy.ServiceOptions `json:"services"`
	DNS      string                   `json:"dns"`
}

type Metrics struct {
	Service ServiceInfo         `json:"service"`
	Deltas  []nxproxy.SlotDelta `json:"deltas"`
}

type ServiceInfo struct {
	RunID  uuid.UUID `json:"run_id"`
	Uptime int64     `json:"uptime"`
}
