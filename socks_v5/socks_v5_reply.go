package socksv5

import (
	"bytes"
	"net"
)

const Version = byte(0x05)

type Reply byte

const (
	ReplyOk         = Reply(0x00)
	ReplyErrGeneric = Reply(0x01)
	//	ReplyErrConnNotAllowedByRuleset = socksV5Reply(0x02)
	ReplyErrNetUnreachable       = Reply(0x03)
	ReplyErrHostUnreachable      = Reply(0x04)
	ReplyErrConnRefused          = Reply(0x05)
	ReplyErrTtlExpired           = Reply(0x06)
	ReplyErrCmdNotSupported      = Reply(0x07)
	ReplyErrAddrTypeNotSupported = Reply(0x08)
)

func reply(conn net.Conn, val byte, addr *Addr) (err error) {

	var buff bytes.Buffer

	buff.Write([]byte{Version, byte(val)})

	if addr != nil {

		bytes, err := addr.MarshallBinary()
		if err != nil {
			return err
		}

		buff.WriteByte(0x00)
		buff.Write(bytes)
	}

	_, err = conn.Write(buff.Bytes())
	return err
}
