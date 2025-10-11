package http

import (
	"bufio"
	"net/http"
	"time"
)

func writeAck(writer *bufio.Writer, headers http.Header) error {

	resp := http.Response{
		StatusCode: http.StatusOK,
		Status:     "Connection established",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}

	if headers != nil {
		resp.Header = headers
	} else {
		resp.Header = http.Header{}
	}

	resp.Header.Set("Date", time.Now().In(time.UTC).Format(time.RFC1123))
	resp.Header.Set("Proxy-Connection", "Keep-Alive")

	if err := resp.Write(writer); err != nil {
		return err
	}

	if err := writer.Flush(); err != nil {
		return err
	}

	return nil
}
