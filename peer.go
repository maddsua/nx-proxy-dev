package nxproxy

import (
	"context"
	"errors"
	"math"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

var ErrTooManyConnections = errors.New("too many connections")

type PeerOptions struct {

	//	unique peer ID used for accounting identification
	ID uuid.UUID `json:"id"`

	//	optional (not so) paasword auth data
	PasswordAuth *UserPassword `json:"password_auth"`

	//	maximal number of open connections
	MaxConnections uint `json:"max_connections"`

	//	connection speed limits
	Bandwidth PeerBandwidth `json:"bandwidth"`

	//	public ip to use for outbound connections, optional
	FramedIP string `json:"framed_ip,omitempty"`

	//	used to disable a peer without completely removing it
	Disabled bool `json:"disabled"`
}

type UserPassword struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

type PeerBandwidth struct {

	//	total connection bandwidth for up/down streams
	Rx uint32 `json:"rx"`
	Tx uint32 `json:"tx"`

	//	respective minimal speed per connection
	MinRx uint32 `json:"min_rx"`
	MinTx uint32 `json:"min_tx"`
}

type PeerDelta struct {

	//	unique peer ID
	PeerID uuid.UUID `json:"peer"`

	//	data transferred
	Rx uint64 `json:"rx"`
	Tx uint64 `json:"tx"`
}

func (peer *PeerOptions) CmpCredentials(other PeerOptions) bool {

	if peer.ID != other.ID {
		return false
	}

	if auth := peer.PasswordAuth; auth != nil && other.PasswordAuth != nil {
		return auth.User == other.PasswordAuth.User &&
			auth.Password == other.PasswordAuth.Password
	}

	return false
}

func (peer *PeerOptions) DisplayName() string {

	if auth := peer.PasswordAuth; auth != nil {
		return auth.User
	}

	return peer.ID.String()
}

type Peer struct {
	PeerOptions

	BaseContext context.Context
	Dialer      net.Dialer
	HttpClient  *http.Client

	DeltaRx atomic.Uint64
	DeltaTx atomic.Uint64

	nextConnID    uint64
	connMap       map[uint64]*PeerConnection
	mtx           sync.Mutex
	refreshActive atomic.Bool
}

func (peer *Peer) Connection() (*PeerConnection, error) {

	peer.mtx.Lock()
	defer peer.mtx.Unlock()

	if peer.connMap == nil {
		peer.connMap = map[uint64]*PeerConnection{}
	}

	if peer.refreshActive.CompareAndSwap(false, true) {
		go peer.refresh()
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
		id:     nextID,
		bandRx: baseBandwidth(bandwidth.Rx, bandwidth.MinRx),
		bandTx: baseBandwidth(bandwidth.Tx, bandwidth.MinTx),
	}

	baseCtx := peer.BaseContext
	if baseCtx == nil {
		baseCtx = context.Background()
	}

	conn.ctx, conn.cancelFn = context.WithCancel(baseCtx)

	peer.connMap[nextID] = &conn

	return &conn, nil
}

func (peer *Peer) refresh() {

	ticker := time.NewTicker(time.Second)

	defer func() {
		ticker.Stop()
		peer.refreshActive.Store(false)
	}()

	//	removes all closed connections and returns a list of remaining ones
	var connCleanup = func() []*PeerConnection {

		peer.mtx.Lock()
		defer peer.mtx.Unlock()

		var entries []*PeerConnection

		for key, conn := range peer.connMap {

			if conn.ctx.Err() != nil {

				//	copy data volume back to the peer
				peer.DeltaRx.Add(conn.deltaRx.Load())
				peer.DeltaTx.Add(conn.deltaTx.Load())

				//	and nuke the connection entirely
				delete(peer.connMap, key)
				continue
			}

			entries = append(entries, conn)
		}

		return entries
	}

	var slurpDeltas = func(entries []*PeerConnection) {
		for _, conn := range entries {
			peer.DeltaRx.Add(conn.deltaRx.Swap(0))
			peer.DeltaTx.Add(conn.deltaTx.Swap(0))
		}
	}

	//	should prevent early exits in some conditions
	var lastNconn int

	for peer.refreshActive.Load() {

		<-ticker.C

		conns := connCleanup()
		RedistributePeerBandwidth(conns, peer.Bandwidth)
		slurpDeltas(conns)

		//	check if have any other connections left, and if not - exit routine
		if max(len(conns), lastNconn) < 1 {
			return
		}

		lastNconn = len(conns)
	}
}

func (peer *Peer) ConnectionList() []*PeerConnection {

	peer.mtx.Lock()
	defer peer.mtx.Unlock()

	var entries []*PeerConnection
	for _, conn := range peer.connMap {
		entries = append(entries, conn)
	}

	return entries
}

func (peer *Peer) CloseConnections() {

	peer.mtx.Lock()
	defer peer.mtx.Unlock()

	//	todo: triage
	if peer.HttpClient != nil {
		peer.HttpClient.CloseIdleConnections()
	}

	for key, conn := range peer.connMap {

		conn.Close()

		peer.DeltaRx.Add(conn.deltaRx.Load())
		peer.DeltaTx.Add(conn.deltaTx.Load())

		delete(peer.connMap, key)
	}
}

func (peer *Peer) Delta() (PeerDelta, bool) {

	rx := peer.DeltaRx.Swap(0)
	tx := peer.DeltaTx.Swap(0)

	if rx > 0 || tx > 0 {
		return PeerDelta{
			PeerID: peer.ID,

			Rx: rx,
			Tx: tx,
		}, true
	}

	return PeerDelta{}, false
}
