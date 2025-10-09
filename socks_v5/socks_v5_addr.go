package socksv5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strconv"
)

const (
	AddrIPv4   = byte(0x01)
	AddrDomain = byte(0x03)
	AddrIPv6   = byte(0x04)
)

type Addr string

func (addr Addr) MarshallBinary() ([]byte, error) {

	if addr == "" {
		return nil, nil
	}

	var buff bytes.Buffer

	hostStr, portStr, err := net.SplitHostPort(string(addr))
	if err != nil {
		return nil, fmt.Errorf("invalid 'addr:port': %v", err)
	}

	hostAddr := net.ParseIP(hostStr)

	switch {
	case len(hostAddr) == net.IPv4len:
		buff.WriteByte(AddrIPv4)
		buff.Write(hostAddr)
	case len(hostAddr) == net.IPv6len:
		buff.WriteByte(AddrIPv6)
		buff.Write(hostAddr)
	default:
		buff.WriteByte(AddrDomain)
		buff.WriteString(hostStr)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port number: %v", err)
	}

	buff.Write(binary.BigEndian.AppendUint16(nil, uint16(port)))

	if buff.Len() > math.MaxUint8 {
		return nil, fmt.Errorf("address too large")
	}

	return buff.Bytes(), nil
}
