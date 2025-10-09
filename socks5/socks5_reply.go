package socks5

import (
	"bytes"
	"net"
)

const ProtoVersionByte = byte(0x05)
const ProtoReserved = byte(0x00)

type Reply byte

const (
	ReplyOk = Reply(iota)
	ReplyErrGeneric
	ReplyErrConnNotAllowedByRuleset
	ReplyErrNetUnreachable
	ReplyErrHostUnreachable
	ReplyErrConnRefused
	ReplyErrTtlExpired
	ReplyErrCmdNotSupported
	ReplyErrAddrTypeNotSupported
)

func reply(conn net.Conn, val Reply, addr *Addr) (err error) {

	var buff bytes.Buffer

	buff.Write([]byte{ProtoVersionByte, byte(val)})

	if addr != nil {

		bytes, err := addr.MarshallBinary()
		if err != nil {
			return err
		}

		buff.WriteByte(ProtoReserved)
		buff.Write(bytes)
	}

	_, err = conn.Write(buff.Bytes())
	return err
}
