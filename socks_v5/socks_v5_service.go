package socksv5

import (
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"strconv"
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
		_ = reply(conn, ReplyErrGeneric, nil)
		return
	}

	var peer *nxproxy.Peer

	if _, has := methods[AuthMethodPassword]; has {

		if peer, err = connPasswordAuth(conn, svc.Auth); err != nil {

			client_ip, _ := nxproxy.GetAddrPort(conn.RemoteAddr())
			host_ip, host_port := nxproxy.GetAddrPort(conn.LocalAddr())

			slog.Warn("SOCKS5: Password auth: Failed",
				slog.String("client_ip", client_ip.String()),
				slog.String("proxy_addr", net.JoinHostPort(host_ip.String(), strconv.Itoa(host_port))),
				slog.String("err", err.Error()))
			return
		}

	} else {
		_ = replyAuth(conn, AuthMethodUnacceptable)
		return
	}

	req, err := readRequest(conn)
	if err != nil {

		client_ip, _ := nxproxy.GetAddrPort(conn.RemoteAddr())
		host_ip, host_port := nxproxy.GetAddrPort(conn.LocalAddr())

		slog.Warn("SOCKS5: Invalid request",
			slog.String("client_ip", client_ip.String()),
			slog.String("proxy_addr", net.JoinHostPort(host_ip.String(), strconv.Itoa(host_port))),
			slog.String("err", err.Error()))

		_ = reply(conn, ReplyErrGeneric, nil)

		return
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {

		client_ip, _ := nxproxy.GetAddrPort(conn.RemoteAddr())
		host_ip, host_port := nxproxy.GetAddrPort(conn.LocalAddr())

		slog.Warn("SOCKS5: Reset io timeouts",
			slog.String("client_ip", client_ip.String()),
			slog.String("proxy_addr", net.JoinHostPort(host_ip.String(), strconv.Itoa(host_port))),
			slog.String("err", err.Error()))

		_ = reply(conn, ReplyErrGeneric, nil)

		return
	}

	if nxproxy.IsLocalAddress(req.Addr.Host) {

		client_ip, _ := nxproxy.GetAddrPort(conn.RemoteAddr())
		host_ip, host_port := nxproxy.GetAddrPort(conn.LocalAddr())

		slog.Warn("SOCKS5: Dest addr not allowed",
			slog.String("client_ip", client_ip.String()),
			slog.String("proxy_addr", net.JoinHostPort(host_ip.String(), strconv.Itoa(host_port))),
			slog.String("dst", req.Addr.String()))

		_ = reply(conn, ReplyErrConnNotAllowedByRuleset, nil)
	}

	switch req.Cmd {
	case CmdConnect:
		svc.handleCmdConnect(conn, peer, req.Addr)
	default:

		client_ip, _ := nxproxy.GetAddrPort(conn.RemoteAddr())
		host_ip, host_port := nxproxy.GetAddrPort(conn.LocalAddr())

		slog.Debug("SOCKS5: Command not supported",
			slog.String("client_ip", client_ip.String()),
			slog.String("proxy_addr", net.JoinHostPort(host_ip.String(), strconv.Itoa(host_port))),
			slog.String("cmd", req.Cmd.String()))

		_ = reply(conn, ReplyErrCmdNotSupported, nil)
	}
}

func (svc *Server) handleCmdConnect(conn net.Conn, peer *nxproxy.Peer, remoteAddr *Addr) {

	connCtl, err := peer.Connection()
	if err != nil {

		client_ip, _ := nxproxy.GetAddrPort(conn.RemoteAddr())
		host_ip, host_port := nxproxy.GetAddrPort(conn.LocalAddr())

		slog.Debug("SOCKS5: Connect: Peer connection rejected",
			slog.String("client_ip", client_ip.String()),
			slog.String("proxy_addr", net.JoinHostPort(host_ip.String(), strconv.Itoa(host_port))),
			slog.String("peer", peer.DisplayName()),
			slog.String("err", err.Error()))

		if err == nxproxy.ErrTooManyConnections {
			_ = reply(conn, ReplyErrConnNotAllowedByRuleset, remoteAddr)
		} else {
			_ = reply(conn, ReplyErrGeneric, remoteAddr)
		}

		return
	}

	defer connCtl.Close()

	//	todo: insert framed ip and dns
	dialer := nxproxy.NewTcpDialer(nil, nil)

	dstConn, err := dialer.DialContext(connCtl.Context(), "tcp", remoteAddr.String())
	if err != nil {

		client_ip, _ := nxproxy.GetAddrPort(conn.RemoteAddr())
		host_ip, host_port := nxproxy.GetAddrPort(conn.LocalAddr())

		slog.Debug("SOCKSv5: Connect: Unable to dial destination",
			slog.String("client_ip", client_ip.String()),
			slog.String("proxy_addr", net.JoinHostPort(host_ip.String(), strconv.Itoa(host_port))),
			slog.String("peer", peer.DisplayName()),
			slog.String("remote", remoteAddr.Host),
			slog.String("err", err.Error()))

		_ = reply(conn, ReplyErrHostUnreachable, remoteAddr)

		return
	}

	defer dstConn.Close()

	if err := reply(conn, ReplyOk, remoteAddr); err != nil {

		client_ip, _ := nxproxy.GetAddrPort(conn.RemoteAddr())
		host_ip, host_port := nxproxy.GetAddrPort(conn.LocalAddr())

		slog.Debug("SOCKSv5: Connect: Ack failed",
			slog.String("client_ip", client_ip.String()),
			slog.String("proxy_addr", net.JoinHostPort(host_ip.String(), strconv.Itoa(host_port))),
			slog.String("peer", peer.DisplayName()),
			slog.String("remote", remoteAddr.Host),
			slog.String("err", err.Error()))

		return
	}

	//	todo: pipe and wait
}
