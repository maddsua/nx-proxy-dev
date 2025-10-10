package nxproxy

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

type PeerConnection struct {
	id uint64

	deltaRx atomic.Uint64
	deltaTx atomic.Uint64

	bandRx atomic.Uint32
	bandTx atomic.Uint32

	mtx      sync.Mutex
	ctx      context.Context
	cancelFn context.CancelFunc
	updated  time.Time
}

func (conn *PeerConnection) Context() context.Context {

	conn.mtx.Lock()
	defer conn.mtx.Unlock()

	if conn.ctx == nil {
		conn.ctx, conn.cancelFn = context.WithCancel(context.Background())
	}
	return conn.ctx
}

func (conn *PeerConnection) BandwidthRx() (int, bool) {
	val := conn.bandRx.Load()
	return int(val), val > 0
}

func (conn *PeerConnection) BandwidthTx() (int, bool) {
	val := conn.bandTx.Load()
	return int(val), val > 0
}

func (conn *PeerConnection) AccountRx(delta int) {
	if delta > 0 {
		conn.deltaRx.Add(uint64(delta))
	}
}

func (conn *PeerConnection) AccountTx(delta int) {
	if delta > 0 {
		conn.deltaTx.Add(uint64(delta))
	}
}

func (conn *PeerConnection) Close() {

	conn.mtx.Lock()
	defer conn.mtx.Unlock()

	if conn.cancelFn != nil {
		conn.cancelFn()
	}
}
