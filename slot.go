package nxproxy

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
)

var ErrSlotOptionsIncompatible = errors.New("slot options incompatible")
var ErrUnsupportedProto = errors.New("unsupported protocol")

type SlotService interface {
	Info() SlotInfo
	Deltas() []PeerDelta
	SetPeers(entries []PeerOptions)
	SetOptions(opts SlotOptions) error
	Close() error
}

type ProxyProto string

func (val ProxyProto) Valid() bool {
	return val == ProxyProtoHttp || val == ProxyProtoSocks
}

const (
	ProxyProtoSocks = ProxyProto("socks")
	ProxyProtoHttp  = ProxyProto("http")
)

type ServiceOptions struct {
	SlotOptions
	Peers []PeerOptions `json:"peers"`
}

type SlotOptions struct {
	Proto    ProxyProto `json:"proto"`
	BindAddr string     `json:"bind_addr"`
}

func (opts *SlotOptions) Compatible(other *SlotOptions) bool {

	if other == nil || opts == nil {
		return false
	}

	return opts.Proto == other.Proto &&
		opts.BindAddr == other.BindAddr
}

type SlotInfo struct {
	Up              bool       `json:"up"`
	Proto           ProxyProto `json:"proto"`
	BindAddr        string     `json:"bind_addr"`
	RegisteredPeers int        `json:"registered_peers"`
	Error           string     `json:"error,omitempty"`
}

type Slot struct {
	SlotOptions

	BaseContext context.Context
	Rl          *RateLimiter
	DNS         DnsProvider

	oldDeltas []PeerDelta

	peerMap     map[uuid.UUID]*Peer
	userNameMap map[string]*Peer
	mtx         sync.Mutex
}

func (slot *Slot) Info() SlotInfo {
	return SlotInfo{
		Up:              true,
		Proto:           slot.Proto,
		BindAddr:        slot.BindAddr,
		RegisteredPeers: len(slot.peerMap),
	}
}

func (slot *Slot) Deltas() []PeerDelta {

	slot.mtx.Lock()
	defer slot.mtx.Unlock()

	deltaList := slices.Clone(slot.oldDeltas)
	slot.oldDeltas = nil

	for _, peer := range slot.peerMap {
		if delta, has := peer.Delta(); has {
			deltaList = append(deltaList, delta)
		}
	}

	peerMap := map[uuid.UUID]*PeerDelta{}

	for _, delta := range deltaList {

		entry := peerMap[delta.ID]
		if entry == nil {
			entry = &delta
			peerMap[delta.ID] = entry
		} else {
			entry.Rx += delta.Rx
			entry.Tx += delta.Tx
		}
	}

	var entries []PeerDelta
	for _, val := range peerMap {
		entries = append(entries, *val)
	}

	return entries
}

func (slot *Slot) SetPeers(entries []PeerOptions) {

	slot.mtx.Lock()
	defer slot.mtx.Unlock()

	importedPeerIdSet := map[uuid.UUID]struct{}{}
	importedUsernameSet := map[string]struct{}{}

	var peerOptsValid = func(peer *PeerOptions) error {

		if peer.ID == uuid.Nil {
			return fmt.Errorf("id is null")
		}

		if _, has := importedPeerIdSet[peer.ID]; has {
			return fmt.Errorf("id not unique: %v", peer.ID)
		} else {
			importedPeerIdSet[peer.ID] = struct{}{}
		}

		if peer.PasswordAuth == nil {
			return fmt.Errorf("no auth properties are set")
		}

		if _, has := importedUsernameSet[peer.PasswordAuth.User]; has {
			return fmt.Errorf("password auth: user name not unique: %s", peer.PasswordAuth.User)
		} else {
			importedUsernameSet[peer.PasswordAuth.User] = struct{}{}
		}

		return nil
	}

	var storePeerDelta = func(peer *Peer) {
		if delta, has := peer.Delta(); has {
			slot.oldDeltas = append(slot.oldDeltas, delta)
		}
	}

	newPeerMap := map[uuid.UUID]*Peer{}

	//	update peers
	for _, entry := range entries {

		if err := peerOptsValid(&entry); err != nil {
			slog.Warn("Update peers: Peer option invalid; Skipped",
				slog.String("peer_id", entry.ID.String()),
				slog.String("name", entry.DisplayName()),
				slog.String("err", err.Error()))
			continue
		}

		framedIP, err := ParseFramedIP(entry.FramedIP)
		if err != nil {
			slog.Warn("Update peers: Framed IP unavailable",
				slog.String("id", entry.ID.String()),
				slog.String("addr", entry.FramedIP),
				slog.String("name", entry.DisplayName()),
				slog.String("err", err.Error()))
		}

		if peer, ok := slot.peerMap[entry.ID]; ok {

			slog.Debug("Update peer",
				slog.String("id", peer.ID.String()),
				slog.String("name", peer.DisplayName()))

			//	check if we have state changes
			mustReauth := !peer.PeerOptions.CmpCredentials(entry)
			disabledFlagChanged := peer.Disabled != entry.Disabled

			//	update peer props
			peer.PeerOptions = entry
			peer.Dialer.LocalAddr = TcpDialAddr(framedIP)

			//	drop connections if peer has to be disabled
			if peer.Disabled {
				peer.CloseConnections()
				storePeerDelta(peer)
			}

			if disabledFlagChanged {
				if peer.Disabled {
					slog.Info("Peer disabled",
						slog.String("id", peer.ID.String()),
						slog.String("name", peer.DisplayName()))
				} else {
					slog.Info("Peer enabled",
						slog.String("id", peer.ID.String()),
						slog.String("name", peer.DisplayName()))
				}
			}

			//	also drop connections has to reauth
			if mustReauth {

				slog.Info("Peer credentials changed; Must reauthenticate",
					slog.String("id", peer.ID.String()),
					slog.String("name", peer.DisplayName()))

				peer.CloseConnections()
				storePeerDelta(peer)
			}

			//	update maps
			newPeerMap[peer.ID] = peer
			delete(slot.peerMap, entry.ID)

			continue
		}

		peer := Peer{
			PeerOptions: entry,
			BaseContext: slot.BaseContext,
			Dialer: net.Dialer{
				Resolver:  slot.DNS.Resolver(),
				LocalAddr: TcpDialAddr(framedIP),
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			},
		}

		slog.Info("Create peer",
			slog.String("id", peer.ID.String()),
			slog.String("name", peer.DisplayName()))

		newPeerMap[entry.ID] = &peer
	}

	//	remove old peers
	for key, peer := range slot.peerMap {
		if _, has := newPeerMap[key]; !has {

			slog.Info("Remove peer",
				slog.String("id", peer.ID.String()),
				slog.String("name", peer.DisplayName()))

			peer.CloseConnections()
			storePeerDelta(peer)
		}
	}

	slot.peerMap = newPeerMap

	//	remap by username
	newUserNameMap := map[string]*Peer{}
	for _, peer := range newPeerMap {
		if auth := peer.PeerOptions.PasswordAuth; auth != nil {
			newUserNameMap[auth.User] = peer
		}
	}

	slot.userNameMap = newUserNameMap
}

func (slot *Slot) ClosePeerConnections() {

	slot.mtx.Lock()
	defer slot.mtx.Unlock()

	for _, peer := range slot.peerMap {

		peer.CloseConnections()

		if delta, has := peer.Delta(); has {
			slot.oldDeltas = append(slot.oldDeltas, delta)
		}
	}
}

func (slot *Slot) LookupWithPassword(ip net.IP, username, password string) (*Peer, error) {

	slot.mtx.Lock()
	defer slot.mtx.Unlock()

	var rlc *RlCounter
	if slot.Rl != nil {

		rlc = slot.Rl.Get("pw:" + ip.String())

		if err := rlc.Use(); err != nil {
			return nil, err
		}
	}

	if slot.peerMap == nil {
		slot.peerMap = map[uuid.UUID]*Peer{}
	}

	peer := slot.userNameMap[username]
	if peer == nil {
		return nil, &CredentialsError{}
	}

	var comparePasswords = func(want, have string) bool {
		return subtle.ConstantTimeCompare([]byte(want), []byte(have)) == 1
	}

	if pa := peer.PasswordAuth; pa == nil {
		return nil, &CredentialsError{}
	} else if !comparePasswords(pa.Password, password) {
		return nil, &CredentialsError{Username: &username}
	}

	if rlc != nil {
		rlc.Reset()
	}

	return peer, nil
}

type CredentialsError struct {
	Username *string
}

func (err *CredentialsError) Error() string {

	if err.Username != nil {
		return fmt.Sprintf("invalid password for %s", *err.Username)
	}

	return "username not found"
}
