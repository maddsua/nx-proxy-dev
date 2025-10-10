package nxproxy

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

var ErrTooManyConnections = errors.New("too many connections")
var ErrPeerClosed = errors.New("peer closed")

type PeerOptions struct {
	ID             uuid.UUID         `json:"id"`
	PasswordAuth   *PeerPasswordAuth `json:"password_auth"`
	MaxConnections uint              `json:"max_connections"`
	Bandwidth      PeerBandwidth     `json:"bandwidth"`
	FramedIP       string            `json:"framed_ip"`
}

func (peer *PeerOptions) Fingerprint() string {

	if auth := peer.PasswordAuth; auth != nil {
		return fmt.Sprintf("%v:pass:%s", peer.ID, auth.UserName)
	}

	return "<nil>"
}

func (peer *PeerOptions) CmpCredentials(other PeerOptions) bool {

	if auth := peer.PasswordAuth; auth != nil && other.PasswordAuth != nil {
		return auth.UserName == other.PasswordAuth.UserName &&
			auth.Password == other.PasswordAuth.Password
	}

	return false
}

func (peer *PeerOptions) DisplayName() string {

	if auth := peer.PasswordAuth; auth != nil {
		return auth.UserName
	}

	return peer.ID.String()
}

type PeerPasswordAuth struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}

type PeerBandwidth struct {
	Rx    uint32 `json:"rx"`
	Tx    uint32 `json:"tx"`
	MinRx uint32 `json:"min_rx"`
	MinTx uint32 `json:"min_tx"`
}

type Peer struct {
	PeerOptions

	BaseContext context.Context
	Dialer      net.Dialer

	DataReceived atomic.Uint64
	DataSent     atomic.Uint64

	nextConnID    uint64
	connMap       map[uint64]*PeerConnection
	mtx           sync.Mutex
	closed        atomic.Bool
	refreshActive atomic.Bool
}

func (peer *Peer) Connection() (*PeerConnection, error) {

	if peer.closed.Load() {
		return nil, ErrPeerClosed
	}

	peer.mtx.Lock()
	defer peer.mtx.Unlock()

	if peer.connMap == nil {
		peer.connMap = map[uint64]*PeerConnection{}
	}

	if peer.refreshActive.CompareAndSwap(false, true) {
		go peer.refreshRoutine()
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

	bandwidth := peer.Bandwidth

	var baseBandwidth = func(base uint32, min uint32) (val atomic.Uint32) {

		var distributed = func() uint32 {

			if n := len(peer.connMap); n > 1 {
				return base / uint32(n)
			}

			return base
		}

		val.Store(max(distributed(), min))

		return
	}

	conn := PeerConnection{
		id:      nextID,
		bandwRx: baseBandwidth(bandwidth.Rx, bandwidth.MinRx),
		bandwTx: baseBandwidth(bandwidth.Tx, bandwidth.MinTx),
	}

	baseCtx := peer.BaseContext
	if baseCtx == nil {
		baseCtx = context.Background()
	}

	conn.ctx, conn.cancelFn = context.WithCancel(baseCtx)

	peer.connMap[nextID] = &conn

	return &conn, nil
}

func (peer *Peer) refreshRoutine() {

	ticker := time.NewTicker(time.Second)

	defer func() {
		ticker.Stop()
		peer.refreshActive.Store(false)
	}()

	//	should prevent early exits in some conditions
	var lastNconn int

	for peer.refreshActive.Load() {

		<-ticker.C
		peer.RefreshState()

		nconn := len(peer.connMap)
		if max(nconn, lastNconn) < 1 {
			return
		}

		lastNconn = nconn
	}
}

func (peer *Peer) RefreshState() {

	if peer.closed.Load() {
		return
	}

	peer.mtx.Lock()
	defer peer.mtx.Unlock()

	for key, conn := range peer.connMap {

		if conn.ctx.Err() != nil {

			//	copy data volume back to the peer
			peer.DataReceived.Add(conn.bytesRx.Load())
			peer.DataSent.Add(conn.bytesTx.Load())

			//	and nuke the connection entirely
			delete(peer.connMap, key)
			continue
		}
	}

	//	recalculate bandwidth for each connection
	bandwidth := peer.Bandwidth

	var getBaseBandwidth = func(val uint32) uint32 {

		if n := len(peer.connMap); n > 1 {
			return val / uint32(n)
		}

		return val
	}

	var equivalentBandwidth = func(base uint32, updatedAt time.Time) uint64 {

		if !updatedAt.IsZero() {
			if elapsed := time.Since(updatedAt); elapsed > time.Second {
				return uint64(elapsed.Seconds() * float64(base))
			}
		}

		return uint64(base)
	}

	baseRx := getBaseBandwidth(bandwidth.Rx)
	baseTx := getBaseBandwidth(bandwidth.Tx)

	var unusedRx uint32
	var unusedTx uint32

	now := time.Now()

	var saturationThreshold = func(val uint64) uint64 {
		return val - (val / 10)
	}

	satThresholdRx := saturationThreshold(uint64(baseRx))
	satThresholdTx := saturationThreshold(uint64(baseTx))

	var nsatRx, nsatTx int

	//	calculate unused bandwidth
	for _, conn := range peer.connMap {

		equivRx := equivalentBandwidth(baseRx, conn.updated)
		equivTx := equivalentBandwidth(baseTx, conn.updated)

		volRx := conn.bytesRx.Load()
		volTx := conn.bytesTx.Load()

		if volRx >= satThresholdRx {
			nsatRx++
		} else if delta := equivRx - volRx; delta > 0 {
			unusedRx += uint32(delta)
		}

		if volTx >= satThresholdTx {
			nsatTx++
		} else if delta := equivTx - volTx; delta > 0 {
			unusedTx += uint32(delta)
		}

		conn.updated = now
	}

	//	redistribute extra bandwidth and take data volume stats
	for _, conn := range peer.connMap {

		volRx := conn.bytesRx.Swap(0)
		volTx := conn.bytesTx.Swap(0)

		var extraRx, extraTx uint32

		if nsatRx > 0 && volRx >= satThresholdRx {
			extraRx = unusedRx / uint32(nsatRx)
		}

		if nsatTx > 0 && volTx >= satThresholdTx {
			extraTx = unusedTx / uint32(nsatTx)
		}

		conn.bandwRx.Store(max(baseRx+extraRx, bandwidth.MinRx))
		conn.bandwTx.Store(max(baseTx+extraTx, bandwidth.MinTx))

		peer.DataReceived.Add(volRx)
		peer.DataSent.Add(volTx)
	}
}

func (peer *Peer) CloseConnections() {

	peer.mtx.Lock()
	defer peer.mtx.Unlock()

	for key, conn := range peer.connMap {

		conn.Close()

		peer.DataReceived.Add(conn.bytesRx.Load())
		peer.DataSent.Add(conn.bytesTx.Load())

		delete(peer.connMap, key)
	}
}

// todo: nuke
func (peer *Peer) Close() {

	if !peer.closed.CompareAndSwap(false, true) {
		return
	}

	peer.CloseConnections()
	peer.refreshActive.Store(false)
}

func (peer *Peer) Deltas() (PeerDelta, bool) {

	rx := peer.DataReceived.Swap(0)
	tx := peer.DataSent.Swap(0)

	if rx > 0 || tx > 0 {
		return PeerDelta{
			PeerID: peer.ID,

			Rx: rx,
			Tx: tx,
		}, true
	}

	return PeerDelta{}, false
}

type PeerDelta struct {
	PeerID uuid.UUID `json:"peer"`
	Rx     uint64    `json:"rx"`
	Tx     uint64    `json:"tx"`
}

type PeerConnection struct {
	id uint64

	bytesRx atomic.Uint64
	bytesTx atomic.Uint64

	bandwRx atomic.Uint32
	bandwTx atomic.Uint32

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
	val := conn.bandwRx.Load()
	return int(val), val > 0
}

func (conn *PeerConnection) BandwidthTx() (int, bool) {
	val := conn.bandwTx.Load()
	return int(val), val > 0
}

func (conn *PeerConnection) AccountRx(delta int) {
	if delta > 0 {
		conn.bytesRx.Add(uint64(delta))
	}
}

func (conn *PeerConnection) AccountTx(delta int) {
	if delta > 0 {
		conn.bytesTx.Add(uint64(delta))
	}
}

func (conn *PeerConnection) Close() {

	conn.mtx.Lock()
	defer conn.mtx.Unlock()

	if conn.cancelFn != nil {
		conn.cancelFn()
	}
}
