package socksv5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"

	nxproxy "github.com/maddsua/nx-proxy"
)

const (
	AddrIPv4       = byte(0x01)
	AddrDomainName = byte(0x03)
	AddrIPv6       = byte(0x04)
)

type Addr struct {
	Host string
	Port uint16
}

func (val Addr) String() string {
	return net.JoinHostPort(val.Host, strconv.Itoa(int(val.Port)))
}

func (val *Addr) MarshallBinary() ([]byte, error) {

	if val == nil {
		return nil, nil
	}

	var buff bytes.Buffer

	if ip := net.ParseIP(val.Host); ip != nil {

		if ip4 := ip.To4(); ip4 != nil {
			buff.WriteByte(AddrIPv4)
			buff.Write(ip4)
		} else {
			buff.WriteByte(AddrIPv6)
			buff.Write(ip)
		}

	} else {
		buff.WriteByte(AddrDomainName)
		buff.WriteString(val.Host)
	}

	buff.Write(binary.BigEndian.AppendUint16(nil, uint16(val.Port)))

	if buff.Len() > math.MaxUint8 {
		return nil, fmt.Errorf("address too large")
	}

	return buff.Bytes(), nil
}

func readAddr(reader io.Reader) (*Addr, error) {

	addrType, err := nxproxy.ReadByte(reader)
	if err != nil {
		return nil, err
	}

	addr := Addr{}

	switch addrType {

	case AddrIPv4:

		buff, err := nxproxy.ReadN(reader, net.IPv4len)
		if err != nil {
			return nil, err
		}

		addr.Host = net.IP(buff).String()

	case AddrIPv6:

		buff, err := nxproxy.ReadN(reader, net.IPv6len)
		if err != nil {
			return nil, err
		}

		addr.Host = net.IP(buff).String()

	case AddrDomainName:

		domainLen, err := nxproxy.ReadByte(reader)
		if err != nil {
			return nil, err
		} else if domainLen <= 0 {
			return nil, fmt.Errorf("invalid domain name length")
		}

		domain, err := nxproxy.ReadN(reader, int(domainLen))
		if err != nil {
			return nil, err
		}

		addr.Host = string(domain)

	default:
		return nil, fmt.Errorf("invalid addr type: %x", addrType)
	}

	portBuff, err := nxproxy.ReadN(reader, 2)
	if err != nil {
		return nil, err
	}

	addr.Port = binary.BigEndian.Uint16(portBuff)

	return &addr, nil
}
