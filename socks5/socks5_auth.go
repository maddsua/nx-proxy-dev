package socks5

import (
	"fmt"
	"io"
	"net"

	nxproxy "github.com/maddsua/nx-proxy"
)

type AuthMethod byte

// Reference: https://www.iana.org/assignments/socks-methods/socks-methods.xhtml
const (
	AuthMethodNone               = AuthMethod(0x00)
	AuthMethodGSSAPI             = AuthMethod(0x01)
	AuthMethodPassword           = AuthMethod(0x02)
	AuthMethodChallengeHandshake = AuthMethod(0x03)
	AuthMethodChallengeResponse  = AuthMethod(0x05)
	AuthMethodSSL                = AuthMethod(0x06)
	AuthMethodNDSAuth            = AuthMethod(0x07)
	AuthMethodMultiAuthFramework = AuthMethod(0x08)
	AuthMethodJSON               = AuthMethod(0x09)
	AuthMethodUnacceptable       = AuthMethod(0xff)
)

func (val AuthMethod) Valid() bool {
	return val == AuthMethodNone ||
		val == AuthMethodGSSAPI ||
		val == AuthMethodPassword ||
		val == AuthMethodChallengeHandshake ||
		val == AuthMethodChallengeResponse ||
		val == AuthMethodSSL ||
		val == AuthMethodNDSAuth ||
		val == AuthMethodMultiAuthFramework ||
		val == AuthMethodJSON ||
		val == AuthMethodUnacceptable
}

func (val AuthMethod) String() string {
	switch val {
	case AuthMethodNone:
		return "none"
	case AuthMethodGSSAPI:
		return "gssapi"
	case AuthMethodPassword:
		return "password"
	case AuthMethodChallengeHandshake:
		return "challenge_handshake"
	case AuthMethodChallengeResponse:
		return "challenge_response"
	case AuthMethodSSL:
		return "ssl"
	case AuthMethodNDSAuth:
		return "nds_auth"
	case AuthMethodMultiAuthFramework:
		return "multi_auth_framework"
	case AuthMethodJSON:
		return "json"
	case AuthMethodUnacceptable:
		return "unacceptable"
	default:
		return fmt.Sprintf("<%d>", val)
	}
}

func readAuthMethods(reader io.Reader) (map[AuthMethod]bool, error) {

	header, err := nxproxy.ReadN(reader, 2)
	if err != nil {
		return nil, err
	} else if header[0] != ProtoVersionByte {
		return nil, fmt.Errorf("unsupported protocol version: %x", header[0])
	}

	nmethods := int(header[1])
	if nmethods == 0 {
		return nil, fmt.Errorf("handshake suggests no auth methods")
	}

	methodBuff, err := nxproxy.ReadN(reader, nmethods)
	if err != nil {
		return nil, fmt.Errorf("failed to read 'methods': %v", err)
	}

	methodMap := make(map[AuthMethod]bool)
	for _, val := range methodBuff {
		if method := AuthMethod(val); method.Valid() {
			methodMap[method] = true
		}
	}

	return methodMap, nil
}

type PasswordAuthStatus byte

const (
	PasswordAuthVersion = byte(0x01)
	PasswordAuthOk      = PasswordAuthStatus(0x00)
	PasswordAuthFail    = PasswordAuthStatus(0x01)
)

func replyAuth(conn net.Conn, val AuthMethod) error {
	return reply(conn, Reply(val), nil)
}

// In accordance to https://datatracker.ietf.org/doc/html/rfc1929
func connPasswordAuth(conn net.Conn, slot *nxproxy.Slot) (*nxproxy.Peer, error) {

	if err := replyAuth(conn, AuthMethodPassword); err != nil {
		return nil, fmt.Errorf("auth method ack: %v", err)
	}

	var reply = func(val PasswordAuthStatus) error {
		_, err := conn.Write([]byte{PasswordAuthVersion, byte(val)})
		return err
	}

	var readCredentials = func() (*nxproxy.UserPassword, error) {

		buff, err := nxproxy.ReadN(conn, 2)
		if err != nil {
			return nil, err
		}

		if ver := buff[0]; ver != PasswordAuthVersion {
			return nil, fmt.Errorf("unexpected negotiation version: %v", ver)
		}

		ulen := int(buff[1])

		if buff, err = nxproxy.ReadN(conn, ulen+1); err != nil {
			return nil, err
		}

		username := buff[:len(buff)-1]
		plen := int(buff[len(buff)-1])

		password, err := nxproxy.ReadN(conn, plen)
		if err != nil {
			return nil, err
		}

		return &nxproxy.UserPassword{
			User:     string(username),
			Password: string(password),
		}, nil
	}

	creds, err := readCredentials()
	if err != nil {
		_ = reply(PasswordAuthFail)
		return nil, fmt.Errorf("failed to read credentials: %v", err)
	}

	//	ensure that username isn't empty
	if creds.User == "" {
		_ = reply(PasswordAuthFail)
		return nil, fmt.Errorf("invalid credentials: empty user name")
	}

	remoteIp, _ := nxproxy.GetAddrPort(conn.RemoteAddr())

	peer, err := slot.LookupWithPassword(remoteIp, creds.User, creds.Password)
	if err != nil {
		_ = reply(PasswordAuthFail)
		return nil, err
	}

	if err := reply(PasswordAuthOk); err != nil {
		return nil, fmt.Errorf("send ack: %v", err)
	}

	return peer, nil
}
