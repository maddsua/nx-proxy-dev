package http

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"

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

	addr, proto, _ := nxproxy.SplitAddrNet(opts.BindAddr)

	listener, err := net.Listen(proto, addr)
	if err != nil {
		return nil, err
	}

	svc.srv.Addr = addr
	svc.srv.Handler = http.HandlerFunc(svc.ServeHTTP)

	go svc.srv.Serve(listener)

	return &svc, nil
}

type service struct {
	nxproxy.Slot

	srv http.Server
}

func (svc *service) SetOptions(opts nxproxy.SlotOptions) error {

	if !svc.SlotOptions.Compatible(&opts) {
		return nxproxy.ErrSlotOptionsIncompatible
	}

	svc.SlotOptions = opts

	return nil
}

func (svc *service) Close() error {
	err := svc.srv.Close()
	svc.Slot.ClosePeerConnections()
	return err
}

func (svc *service) ServeHTTP(wrt http.ResponseWriter, req *http.Request) {

	clientIP, _, _ := net.SplitHostPort(req.RemoteAddr)
	host := proxyRequestHost(req)

	wrt.Header().Set("Via", "nx-proxy")
	wrt.Header().Set("X-Forwarded", fmt.Sprintf("to=%s", host))

	creds, err := proxyRequestCredentials(req)
	if err != nil {

		slog.Debug("HTTP: Request auth invalid",
			slog.String("client_ip", clientIP),
			slog.String("proxy_addr", svc.srv.Addr),
			slog.String("err", err.Error()))

		wrt.Header().Set("Proxy-Authenticate", "Basic")
		wrt.WriteHeader(http.StatusUnauthorized)
		return
	}

	peer, err := svc.Slot.LookupWithPassword(net.ParseIP(clientIP), creds.User, creds.Password)
	if err != nil {

		wrt.Header().Set("Proxy-Connection", "Close")

		switch err := err.(type) {

		case *nxproxy.RateLimitError:
			wrt.Header().Set("Retry-After", err.Expires.String())
			wrt.WriteHeader(http.StatusTooManyRequests)

		case *nxproxy.CredentialsError:
			slog.Debug("HTTP: Invalid credentials",
				slog.String("client_ip", clientIP),
				slog.String("proxy_addr", svc.SlotOptions.BindAddr),
				slog.String("err", err.Error()))
			wrt.WriteHeader(http.StatusForbidden)

		default:
			slog.Debug("HTTP: Password auth rejected",
				slog.String("client_ip", clientIP),
				slog.String("proxy_addr", svc.SlotOptions.BindAddr),
				slog.String("err", err.Error()))
			wrt.WriteHeader(http.StatusForbidden)
		}

		return
	}

	if peer.Disabled {
		slog.Debug("HTTP: Request cancelled; Peer disabled",
			slog.String("client_ip", clientIP),
			slog.String("proxy_addr", svc.SlotOptions.BindAddr),
			slog.String("peer", peer.DisplayName()),
			slog.String("host", host))
		wrt.WriteHeader(http.StatusPaymentRequired)
		return
	}

	if nxproxy.IsLocalAddress(host) {
		slog.Warn("HTTP: Dest addr not allowed",
			slog.String("client_ip", clientIP),
			slog.String("proxy_addr", svc.SlotOptions.BindAddr),
			slog.String("host", host))
		wrt.Header().Set("Proxy-Connection", "Close")
		wrt.WriteHeader(http.StatusBadGateway)
		return
	}

	if req.Method != http.MethodConnect {

		if peer.HttpClient == nil {
			peer.HttpClient = NewPeerClient(peer)
		}

		fwreq, err := forwardRequest(req)
		if err != nil {
			slog.Debug("HTTP: Forward: Unable to create forward request",
				slog.String("client_ip", clientIP),
				slog.String("proxy_addr", svc.SlotOptions.BindAddr),
				slog.String("peer", peer.DisplayName()),
				slog.String("host", host),
				slog.String("err", err.Error()))
			wrt.WriteHeader(http.StatusBadRequest)
			return
		}

		fwresp, err := peer.HttpClient.Do(fwreq)
		if err != nil {
			slog.Debug("HTTP: Forward: Request",
				slog.String("client_ip", clientIP),
				slog.String("proxy_addr", svc.SlotOptions.BindAddr),
				slog.String("peer", peer.DisplayName()),
				slog.String("host", host),
				slog.String("err", err.Error()))
			wrt.WriteHeader(http.StatusBadGateway)
			return
		}

		defer fwresp.Body.Close()

		if err := writeForwarded(fwresp, wrt); err != nil {
			slog.Debug("HTTP: Forward: Write",
				slog.String("client_ip", clientIP),
				slog.String("proxy_addr", svc.SlotOptions.BindAddr),
				slog.String("peer", peer.DisplayName()),
				slog.String("host", host),
				slog.String("err", err.Error()))
			return
		}

		slog.Debug("HTTP: Forward",
			slog.String("client_ip", clientIP),
			slog.String("proxy_addr", svc.SlotOptions.BindAddr),
			slog.String("peer", peer.DisplayName()),
			slog.String("host", host))
		return
	}

	connCtl, err := peer.Connection()
	if err != nil {

		slog.Debug("HTTP: Connect: Peer connection rejected",
			slog.String("client_ip", clientIP),
			slog.String("proxy_addr", svc.SlotOptions.BindAddr),
			slog.String("peer", peer.DisplayName()),
			slog.String("host", host),
			slog.String("err", err.Error()))

		wrt.Header().Set("Proxy-Connection", "Close")

		if err == nxproxy.ErrTooManyConnections {
			wrt.WriteHeader(http.StatusTooManyRequests)
		} else {
			wrt.WriteHeader(http.StatusInternalServerError)
		}

		return
	}

	defer connCtl.Close()

	dstConn, err := peer.Dialer.DialContext(connCtl.Context(), "tcp", host)
	if err != nil {

		slog.Debug("HTTP: Dial destination",
			slog.String("client_ip", clientIP),
			slog.String("proxy_addr", svc.SlotOptions.BindAddr),
			slog.String("peer", peer.DisplayName()),
			slog.String("host", host),
			slog.String("err", err.Error()))

		wrt.Header().Set("Proxy-Connection", "Close")
		wrt.WriteHeader(http.StatusBadGateway)
		return
	}

	defer dstConn.Close()

	conn, rw, err := wrt.(http.Hijacker).Hijack()
	if err != nil {
		slog.Error("HTTP: Connection hijack failed",
			slog.String("client_ip", clientIP),
			slog.String("proxy_addr", svc.SlotOptions.BindAddr),
			slog.String("host", host),
			slog.String("err", err.Error()))
		wrt.WriteHeader(http.StatusNotImplemented)
		return
	}

	defer conn.Close()

	if err := writeAck(rw.Writer, wrt.Header().Clone()); err != nil {
		slog.Debug("HTTP: Tunnel: Failed to write ack",
			slog.String("client_ip", clientIP),
			slog.String("proxy_addr", svc.SlotOptions.BindAddr),
			slog.String("host", host),
			slog.String("err", err.Error()))
		return
	}

	if trailLen := rw.Reader.Buffered(); trailLen > 0 {

		trailer, err := rw.Reader.Peek(trailLen)
		if err != nil {
			slog.Debug("HTTP: Tunnel: Failed to read trailer",
				slog.String("client_ip", clientIP),
				slog.String("proxy_addr", svc.SlotOptions.BindAddr),
				slog.String("host", host),
				slog.String("err", err.Error()))
			return
		}

		written, err := dstConn.Write(trailer)
		if err != nil {
			slog.Debug("HTTP: Tunnel: Failed to write trailer",
				slog.String("client_ip", clientIP),
				slog.String("proxy_addr", svc.SlotOptions.BindAddr),
				slog.String("host", host),
				slog.String("err", err.Error()))
			return
		}

		connCtl.AccountTx(written)
	}

	slog.Debug("HTTP: Connect",
		slog.String("client_ip", clientIP),
		slog.String("proxy_addr", svc.SlotOptions.BindAddr),
		slog.String("peer", peer.DisplayName()),
		slog.String("remote", host))

	if err := nxproxy.ProxyBridge(connCtl, conn, dstConn); err != nil {
		slog.Debug("HTTP: Connect: Broken pipe",
			slog.String("client_ip", clientIP),
			slog.String("proxy_addr", svc.SlotOptions.BindAddr),
			slog.String("peer", peer.DisplayName()),
			slog.String("remote", host),
			slog.String("err", err.Error()))
	}
}
