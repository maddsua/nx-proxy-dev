package http

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"

	nxproxy "github.com/maddsua/nx-proxy"
)

type PeeredConn struct {
	net.Conn
	*nxproxy.PeerConnection
}

func (conn *PeeredConn) Read(buff []byte) (int, error) {

	if bandwidth, limited := conn.BandwidthRx(); limited {

		chunkSize := min(bandwidth, len(buff))
		chunk := make([]byte, chunkSize)
		started := time.Now()

		read, err := conn.Conn.Read(chunk)
		if read == 0 {
			return read, err
		}

		conn.AccountRx(read)

		copy(buff, chunk[:read])

		nxproxy.WaitTCIO(bandwidth, read, started)

		return read, err
	}

	bytesRead, err := conn.Conn.Read(buff)

	conn.AccountRx(bytesRead)

	return bytesRead, err
}

func (conn *PeeredConn) Write(buff []byte) (int, error) {

	if len(buff) == 0 {
		return 0, nil
	}

	if bandwidth, limited := conn.BandwidthTx(); limited {

		var total int
		buffSize := len(buff)

		for total < buffSize {

			chunkSize := min(bandwidth, buffSize-total)
			chunk := buff[total : total+chunkSize]

			started := time.Now()
			written, err := conn.Conn.Write(chunk)

			conn.AccountTx(written)

			total += written

			if err != nil {
				return total, err
			} else if written < chunkSize {
				return total, io.ErrShortWrite
			}

			nxproxy.WaitTCIO(bandwidth, written, started)
		}

		return total, nil
	}

	written, err := conn.Conn.Write(buff)

	conn.AccountTx(written)

	return written, err
}

func (conn *PeeredConn) Close() error {
	conn.PeerConnection.Close()
	return conn.Conn.Close()
}

type PeerDialer struct {
	*nxproxy.Peer
}

func (peer *PeerDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {

	connCtl, err := peer.Connection()
	if err != nil {
		return nil, err
	}

	baseConn, err := peer.Dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	return &PeeredConn{
		Conn:           baseConn,
		PeerConnection: connCtl,
	}, nil
}

func NewPeerClient(peer *nxproxy.Peer) *http.Client {

	dialer := PeerDialer{Peer: peer}

	return &http.Client{
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          10,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 5 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
