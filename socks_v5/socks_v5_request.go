package socksv5

import (
	"fmt"
	"io"

	nxproxy "github.com/maddsua/nx-proxy"
)

const (
	cmdEnum = Command(iota)
	CmdConnect
	CmdBind
	CmdAssociate
)

type Command byte

func (val Command) Valid() bool {
	return val == CmdConnect || val == CmdBind || val == CmdAssociate
}

func (val Command) String() string {
	switch val {
	case CmdConnect:
		return "connect"
	case CmdBind:
		return "bind"
	case CmdAssociate:
		return "associate"
	default:
		return fmt.Sprintf("<%d>", val)
	}
}

func readCommand(reader io.Reader) (Command, error) {

	buff, err := nxproxy.ReadN(reader, 3)
	if err != nil {
		return cmdEnum, fmt.Errorf("read command: %v", err)
	}

	if buff[0] != ProtoVersionByte {
		return cmdEnum, fmt.Errorf("unexpected negotiation version: %v", buff[0])
	} else if buff[2] != ProtoReserved {
		return cmdEnum, fmt.Errorf("trail data after command byte")
	}

	return Command(buff[1]), nil
}

type Request struct {
	Cmd  Command
	Addr *Addr
}

func readRequest(reader io.Reader) (*Request, error) {

	cmd, err := readCommand(reader)
	if err != nil {
		return nil, fmt.Errorf("read cmd: %v", err)
	}

	addr, err := readAddr(reader)
	if err != nil {
		return nil, fmt.Errorf("read addr: %v", err)
	}

	return &Request{Cmd: cmd, Addr: addr}, nil
}
