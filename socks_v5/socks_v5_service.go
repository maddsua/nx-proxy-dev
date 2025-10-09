package socksv5

import (
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	nxproxy "github.com/maddsua/nx-proxy"
)

type Server struct {
	Addr string
	Auth nxproxy.PasswordAuthenticator

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

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	methods, err := readAuthMethods(conn)
	if err != nil {
		_ = reply(conn, byte(ReplyErrGeneric), nil)
		return
	}

	var peer *nxproxy.Peer

	if _, has := methods[AuthMethodPassword]; has {
		if peer, err = connPasswordAuth(conn, svc.Auth); err != nil {
			slog.Warn("SOCKS5: Password auth: Failed",
				//	todo: log source and bind ips
				slog.String("err", err.Error()))
			return
		}
	} else {
		_ = reply(conn, byte(AuthMethodUnacceptable), nil)
		return
	}

	//	todo: implement other
}
