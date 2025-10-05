package nxproxy

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

var ErrTooManyConnections = errors.New("too many connections")

type Peer struct {
	ID             uuid.UUID
	PasswordAuth   *PeerPasswordAuth
	MaxConnections uint
	Bandwidth      PeerBandwidth

	DataReceived atomic.Uint64
	DataSent     atomic.Uint64

	nextConnID uint64
	connMap    map[uint64]*PeerConnection
	mtx        sync.Mutex
}

func (peer *Peer) AuthKey() string {

	if auth := peer.PasswordAuth; auth != nil {
		return fmt.Sprintf("pass:%s:%s", auth.UserName, auth.Password)
	}

	return "<nil>"
}

type PeerPasswordAuth struct {
	UserName string
	Password string
}

func (peer *Peer) Connection() (*PeerConnection, error) {

	peer.mtx.Lock()
	defer peer.mtx.Unlock()

	if peer.connMap == nil {
		peer.connMap = map[uint64]*PeerConnection{}
	}

	if peer.MaxConnections > 0 && len(peer.connMap) > int(peer.MaxConnections) {
		return nil, ErrTooManyConnections
	}

	var pickNextId = func() (uint64, error) {

		if peer.nextConnID < math.MaxInt64 {
			peer.nextConnID++
			return peer.nextConnID, nil
		}

		for idx := range math.MaxInt64 {
			if _, has := peer.connMap[uint64(idx)]; !has {
				return uint64(idx), nil
			}
		}

		return 0, ErrTooManyConnections
	}

	nextID, err := pickNextId()
	if err != nil {
		return nil, err
	}

	conn := PeerConnection{ID: nextID}
	conn.wg.Add(1)

	peer.connMap[nextID] = &conn

	return &conn, nil
}

func (peer *Peer) RefreshState() {

	peer.mtx.Lock()
	defer peer.mtx.Unlock()

	for key, conn := range peer.connMap {

		if conn.closed.Load() {

			conn.wg.Wait()

			//	copy data volume back to the peer
			peer.DataReceived.Add(conn.DataReceived.Load())
			peer.DataSent.Add(conn.DataSent.Load())

			//	and nuke the connection entirely
			delete(peer.connMap, key)
			continue
		}
	}

	//	recalculate bandwidth for each connection
	bandwidth := peer.Bandwidth

	var getBaseBandwidth = func(val uint32, minVal uint32) uint32 {
		return max(val/uint32(len(peer.connMap)), minVal)
	}

	var equivalentBandwidth = func(base uint32, updatedAt time.Time) uint64 {

		if !updatedAt.IsZero() {
			if elapsed := time.Since(updatedAt); elapsed > time.Second {
				return uint64(elapsed.Seconds() * float64(base))
			}
		}

		return uint64(base)
	}

	baseRx := getBaseBandwidth(bandwidth.Rx, bandwidth.MinRx)
	baseTx := getBaseBandwidth(bandwidth.Tx, bandwidth.MinTx)

	var unusedRx uint32
	var unusedTx uint32

	now := time.Now()

	var getMargin = func(val uint64) uint64 {
		return val / 10
	}

	satMarginRx := getMargin(uint64(baseRx))
	satMarginTx := getMargin(uint64(baseTx))

	var nsatRx, nsatTx int

	//	calculate unused bandwidth
	for _, conn := range peer.connMap {

		equivRx := equivalentBandwidth(baseRx, conn.updated)
		equivTx := equivalentBandwidth(baseTx, conn.updated)

		volRx := conn.DataReceived.Load()
		volTx := conn.DataSent.Load()

		if volRx >= satMarginRx {
			nsatRx++
		} else if delta := equivRx - volRx; delta > 0 {
			unusedRx += uint32(delta)
		}

		if volTx >= satMarginTx {
			nsatTx++
		} else if delta := equivTx - volTx; delta > 0 {
			unusedTx += uint32(delta)
		}

		conn.updated = now
	}

	//	redistribute extra bandwidth and take data volume stats
	for _, conn := range peer.connMap {

		volRx := conn.DataReceived.Swap(0)
		volTx := conn.DataSent.Swap(0)

		var extraRx, extraTx uint32

		if nsatRx > 0 && volRx >= satMarginRx {
			extraRx = max(unusedRx / uint32(nsatRx))
		}

		if nsatTx > 0 && volTx >= satMarginTx {
			extraTx = max(unusedTx / uint32(nsatTx))
		}

		conn.DataRateDown.Store(min(baseRx+extraRx, bandwidth.Rx))
		conn.DataRateUp.Store(min(baseTx+extraTx, bandwidth.Tx))

		peer.DataReceived.Add(volRx)
		peer.DataSent.Add(volTx)
	}
}

type PeerConnection struct {
	ID uint64

	DataReceived atomic.Uint64
	DataSent     atomic.Uint64

	DataRateDown atomic.Uint32
	DataRateUp   atomic.Uint32

	closed   atomic.Bool
	ctx      context.Context
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
	updated  time.Time
}

func (conn *PeerConnection) Context() context.Context {
	if conn.ctx == nil {
		return context.Background()
	}
	return conn.ctx
}

func (conn *PeerConnection) Close() {

	if conn.cancelFn != nil {
		conn.cancelFn()
	}

	if conn.closed.CompareAndSwap(false, true) {
		conn.wg.Done()
	}
}

type PeerBandwidth struct {
	Rx    uint32
	Tx    uint32
	MinRx uint32
	MinTx uint32
}
