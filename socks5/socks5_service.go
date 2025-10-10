package socks5

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"time"

	"github.com/google/uuid"
	nxproxy "github.com/maddsua/nx-proxy"
)

func NewService(opts nxproxy.SlotOptions, dns nxproxy.DnsProvider) (nxproxy.SlotService, error) {

	svc := service{
		Slot: nxproxy.Slot{
			SlotOptions: opts,
			Rl: &nxproxy.RateLimiter{
				RateLimiterOptions: nxproxy.DefaultRatelimiter,
			},
			DNS: dns,
		},
	}

	var err error

	addr, proto, _ := nxproxy.SplitAddrNet(opts.BindAddr)

	if svc.listener, err = net.Listen(proto, addr); err != nil {
		return nil, fmt.Errorf("listen: %v", err)
	}

	svc.ctx, svc.cancelFn = context.WithCancel(context.Background())

	svc.BaseContext = svc.ctx

	go svc.acceptConns()

	return &svc, nil
}

type service struct {
	nxproxy.Slot

	ctx      context.Context
	cancelFn context.CancelFunc
	listener net.Listener
}

func (svc *service) ID() uuid.UUID {
	return svc.SlotOptions.ID
}

func (svc *service) Proto() nxproxy.ProxyProto {
	return svc.SlotOptions.Proto
}

func (svc *service) BindAddr() string {
	return svc.SlotOptions.BindAddr
}

func (svc *service) SetOptions(opts nxproxy.SlotOptions) error {

	if svc.SlotOptions.Fingerprint() != opts.Fingerprint() {
		return nxproxy.ErrSlotOptionsIncompatible
	}

	svc.SlotOptions = opts

	return nil
}

func (svc *service) Close() error {

	if svc.ctx.Err() != nil {
		return nil
	}

	svc.cancelFn()
	err := svc.listener.Close()

	return err
}

func (svc *service) acceptConns() {

	for svc.ctx.Err() == nil {

		if next, err := svc.listener.Accept(); err != nil {

			if svc.ctx.Err() != nil {
				return
			}

			slog.Warn("SOCKS5: Accept connection",
				slog.String("err", err.Error()))

			continue

		} else {
			go svc.serveConn(next)
		}
	}
}

func (svc *service) serveConn(conn net.Conn) {

	defer func() {

		conn.Close()

		if rec := recover(); rec != nil {
			slog.Error("SOCKS5: Handler panic recovered",
				slog.String("err", fmt.Sprint(rec)))
			fmt.Println("Panic stack:", string(debug.Stack()))
		}
	}()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	clientIP, _ := nxproxy.GetAddrPort(conn.RemoteAddr())

	methods, err := readAuthMethods(conn)
	if err != nil {
		slog.Debug("SOCKS5: Handshake error",
			slog.String("client_ip", clientIP.String()),
			slog.String("proxy_addr", svc.SlotOptions.BindAddr),
			slog.String("err", err.Error()))
		_ = reply(conn, ReplyErrGeneric, nil)
		return
	}

	var peer *nxproxy.Peer

	if _, has := methods[AuthMethodPassword]; has {

		if peer, err = connPasswordAuth(conn, &svc.Slot); err != nil {
			slog.Debug("SOCKS5: Password auth: Failed",
				slog.String("client_ip", clientIP.String()),
				slog.String("proxy_addr", svc.SlotOptions.BindAddr),
				slog.String("err", err.Error()))
			return
		}

	} else {
		_ = replyAuth(conn, AuthMethodUnacceptable)
		return
	}

	req, err := readRequest(conn)
	if err != nil {
		slog.Debug("SOCKS5: Invalid request",
			slog.String("client_ip", clientIP.String()),
			slog.String("proxy_addr", svc.SlotOptions.BindAddr),
			slog.String("err", err.Error()))
		_ = reply(conn, ReplyErrGeneric, nil)
		return
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		slog.Debug("SOCKS5: Reset io timeouts",
			slog.String("client_ip", clientIP.String()),
			slog.String("proxy_addr", svc.SlotOptions.BindAddr),
			slog.String("err", err.Error()))
		_ = reply(conn, ReplyErrGeneric, nil)
		return
	}

	if nxproxy.IsLocalAddress(req.Addr.Host) {
		slog.Warn("SOCKS5: Dest addr not allowed",
			slog.String("client_ip", clientIP.String()),
			slog.String("proxy_addr", svc.SlotOptions.BindAddr),
			slog.String("dst", req.Addr.String()))
		_ = reply(conn, ReplyErrConnNotAllowedByRuleset, nil)
		return
	}

	switch req.Cmd {
	case CmdConnect:
		svc.cmdConnect(conn, peer, req.Addr)
	default:
		slog.Debug("SOCKS5: Command not supported",
			slog.String("client_ip", clientIP.String()),
			slog.String("proxy_addr", svc.SlotOptions.BindAddr),
			slog.String("cmd", req.Cmd.String()))
		_ = reply(conn, ReplyErrCmdNotSupported, nil)
	}
}

func (svc *service) cmdConnect(conn net.Conn, peer *nxproxy.Peer, remoteAddr *Addr) {

	clientIP, _ := nxproxy.GetAddrPort(conn.RemoteAddr())

	connCtl, err := peer.Connection()
	if err != nil {

		slog.Debug("SOCKS5: Connect: Peer connection rejected",
			slog.String("client_ip", clientIP.String()),
			slog.String("proxy_addr", svc.SlotOptions.BindAddr),
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

	dstConn, err := peer.Dialer.DialContext(connCtl.Context(), "tcp", remoteAddr.String())
	if err != nil {
		slog.Debug("SOCKSv5: Connect: Unable to dial destination",
			slog.String("client_ip", clientIP.String()),
			slog.String("proxy_addr", svc.SlotOptions.BindAddr),
			slog.String("peer", peer.DisplayName()),
			slog.String("remote", remoteAddr.Host),
			slog.String("err", err.Error()))
		_ = reply(conn, ReplyErrHostUnreachable, remoteAddr)
		return
	}

	defer dstConn.Close()

	if err := reply(conn, ReplyOk, remoteAddr); err != nil {
		slog.Debug("SOCKSv5: Connect: Ack failed",
			slog.String("client_ip", clientIP.String()),
			slog.String("proxy_addr", svc.SlotOptions.BindAddr),
			slog.String("peer", peer.DisplayName()),
			slog.String("remote", remoteAddr.Host),
			slog.String("err", err.Error()))
		return
	}

	slog.Debug("SOCKSv5: Connect",
		slog.String("client_ip", clientIP.String()),
		slog.String("proxy_addr", svc.SlotOptions.BindAddr),
		slog.String("peer", peer.DisplayName()),
		slog.String("remote", remoteAddr.Host))

	if err := nxproxy.ProxyBridge(connCtl, conn, dstConn); err != nil {
		slog.Debug("SOCKSv5: Connect: Broken pipe",
			slog.String("client_ip", clientIP.String()),
			slog.String("proxy_addr", svc.SlotOptions.BindAddr),
			slog.String("peer", peer.DisplayName()),
			slog.String("remote", remoteAddr.Host),
			slog.String("err", err.Error()))
	}
}
