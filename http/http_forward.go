package http

import (
	"io"
	"net/http"
)

func forwardRequest(req *http.Request) (*http.Request, error) {

	fwreq, err := http.NewRequest(req.Method, req.URL.String(), req.Body)
	if err != nil {
		return nil, err
	}

	fwreq.Header = req.Header.Clone()

	fwreq.Header.Set("Host", fwreq.Host)
	fwreq.Header.Del("Connection")
	fwreq.Header.Del("Upgrade")

	return fwreq, nil
}

func writeForwarded(resp *http.Response, wrt http.ResponseWriter) error {

	headers := resp.Header.Clone()

	headers.Del("TE")
	headers.Del("Transfer-Encoding")

	for header, entries := range headers {
		for _, val := range entries {
			wrt.Header().Add(header, val)
		}
	}

	wrt.WriteHeader(resp.StatusCode)

	return streamBody(resp.Body, wrt)
}

func streamBody(body io.Reader, wrt http.ResponseWriter) error {

	buff := make([]byte, 32*1024)

	for {

		readBytes, err := body.Read(buff)

		if readBytes > 0 {

			if _, err := wrt.Write(buff[:readBytes]); err != nil {
				return err
			}

			if flusher, ok := wrt.(http.Flusher); ok {
				flusher.Flush()
			}
		}

		if err != nil {

			if err == io.EOF {
				return nil
			}

			return err
		}
	}
}
