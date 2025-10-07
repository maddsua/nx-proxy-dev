package socksv5

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
)

//	todo: resolve the conandrum of importing interfaces

type Authenticator interface {
	LookupWithPassword(username, password string) (Peer, error)
}

type Peer interface {
	Connection() (Connection, error)
}

type Connection interface {
	Context() context.Context
	IoAdd()
	IoDone()
	BandwidthRx() (int, bool)
	BandwidthTx() (int, bool)
	AccountRx(delta int)
	AccountTx(delta int)
	Close()
}

type Server struct {
	Addr string
	Auth Authenticator

	mtx       sync.Mutex
	init      atomic.Bool
	listener  net.Listener
	ctx       context.Context
	cancelCtx context.CancelFunc
	err       error
}

func (svc *Server) ListenAndServe() error {

	svc.mtx.Lock()
	defer svc.mtx.Unlock()

	if svc.init.Load() {
		if err := svc.Close(); err != nil {
			return fmt.Errorf("restart: %v", err)
		}
	}

	svc.init.Store(true)

	svc.ctx, svc.cancelCtx = context.WithCancel(context.Background())

	svc.listener, svc.err = net.Listen("tcp", svc.Addr)
	if svc.err != nil {
		return svc.err
	}

	go svc.acceptConns()

	return nil
}

func (svc *Server) Error() error {
	return svc.err
}

func (svc *Server) Close() error {

	svc.mtx.Lock()
	defer svc.mtx.Unlock()

	if !svc.init.CompareAndSwap(true, false) {
		return nil
	}

	svc.err = svc.listener.Close()
	svc.cancelCtx()

	return svc.err
}

func (svc *Server) acceptConns() {

	for svc.ctx.Err() == nil {

		next, err := svc.listener.Accept()
		if err != nil {
			slog.Warn("SOCKS5: Accept connection",
				slog.String("err", err.Error()))
			continue
		}

		go svc.handleConn(next)
	}
}

func (svc *Server) handleConn(conn net.Conn) {

	defer func() {

		conn.Close()

		if rec := recover(); rec != nil {
			slog.Error("SOCKS5: Handler panic recovered",
				slog.String("err", fmt.Sprint(rec)))
			fmt.Println("Panic stack:", string(debug.Stack()))
		}
	}()

	//	todo: implement
}
