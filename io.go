package nxproxy

import (
	"io"
)

func ReadN(reader io.Reader, n int) ([]byte, error) {

	if n <= 0 {
		return nil, nil
	}

	buff := make([]byte, n)
	bytesRead, err := reader.Read(buff)
	if bytesRead == len(buff) {
		return buff, nil
	} else if err == nil && bytesRead != len(buff) {
		return nil, io.EOF
	}

	return buff, err
}

func ReadByte(reader io.Reader) (byte, error) {
	buff, err := ReadN(reader, 1)
	return buff[0], err
}
