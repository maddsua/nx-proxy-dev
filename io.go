package nxproxy

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
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

// Bridges two connections together to create a proxy
func ProxyBridge(ctl *PeerConnection, clientConn net.Conn, remoteConn net.Conn) (err error) {

	ctx := ctl.Context()

	txCtx, cancelTx := context.WithCancel(ctx)
	rxCtx, cancelRx := context.WithCancel(ctx)

	doneCh := make(chan error, 2)
	defer close(doneCh)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		doneCh <- SpliceConn(txCtx, remoteConn, clientConn, ctl.BandwidthTx, ctl.AccountTx)
	}()

	go func() {
		defer wg.Done()
		doneCh <- SpliceConn(rxCtx, clientConn, remoteConn, ctl.BandwidthRx, ctl.AccountRx)
	}()

	select {
	case err = <-doneCh:
	case <-ctx.Done():
	}

	cancelRx()
	cancelTx()

	_ = remoteConn.SetReadDeadline(time.Unix(1, 0))
	_ = clientConn.SetReadDeadline(time.Unix(1, 0))

	wg.Wait()
	return
}

// Implementations of BandwidthFn must return the data volume in bytes that a connection may copy in one second at most
type BandwidthFn func() (int, bool)

type AccountFn func(delta int)

// Forwards data from src to dst while limiting data rate and accounting for traffic volume
func SpliceConn(ctx context.Context, dst io.Writer, src io.Reader, bw BandwidthFn, acct AccountFn) error {

	const defaultChunkSize = 32 * 1024

	var copyLimit = func(bandwidth int) error {

		chunk := make([]byte, bandwidth)
		started := time.Now()

		read, err := src.Read(chunk)

		if read > 0 {

			written, err := dst.Write(chunk[:read])

			if acct != nil {
				acct(written)
			}

			if err != nil {
				return err
			} else if written < read {
				return io.ErrShortWrite
			}

			WaitTCIO(bandwidth, min(written, read), started)
		}

		return err
	}

	var copyDirect = func() error {

		written, err := io.CopyN(dst, src, defaultChunkSize)

		if acct != nil {
			acct(int(written))
		}

		return err
	}

	for ctx.Err() == nil {

		var bandwidth int
		if bw != nil {
			bandwidth, _ = bw()
		}

		var err error
		if bandwidth > 0 {
			err = copyLimit(bandwidth)
		} else {
			err = copyDirect()
		}

		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
	}

	return nil
}

// Creates a fake delay that can be used to limit data transfer rate
func WaitTCIO(bandwidth int, size int, started time.Time) {
	elapsed := time.Since(started)
	time.Sleep(DurationTCIO(bandwidth, size) - elapsed)
}

// Returns the amount of time it's expected for an IO operation to take. Bandwidth in bps, size in bytes
func DurationTCIO(bandwidth int, size int) time.Duration {
	return time.Duration(int64(time.Second) * int64(size) / int64(bandwidth))
}
