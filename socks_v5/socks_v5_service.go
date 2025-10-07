package socksv5

import (
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"

	"github.com/maddsua/nx-proxy/proxy"
)

type Server struct {
	Addr string
	Auth proxy.Authenticator

	mtx      sync.Mutex
	active   atomic.Bool
	listener net.Listener
	wg       sync.WaitGroup
	err      error
}

func (svc *Server) ListenAndServe() error {

	svc.mtx.Lock()
	defer svc.mtx.Unlock()

	if svc.active.Load() {
		if err := svc.Close(); err != nil {
			return fmt.Errorf("restart: %v", err)
		}
	}

	svc.listener, svc.err = net.Listen("tcp", svc.Addr)
	if svc.err != nil {
		return svc.err
	}

	svc.active.Store(true)

	go svc.acceptConns()

	return nil
}

func (svc *Server) Error() error {
	return svc.err
}

func (svc *Server) Close() error {

	svc.mtx.Lock()
	defer svc.mtx.Unlock()

	if !svc.active.Load() {
		return nil
	}

	svc.active.Store(false)
	svc.err = svc.listener.Close()
	svc.wg.Wait()

	return svc.err
}

func (svc *Server) acceptConns() {

	for svc.active.Load() {

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
