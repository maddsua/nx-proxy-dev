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

var ErrUserNotFound = errors.New("user not found")
var ErrPasswordInvalid = errors.New("password invalid")
var ErrSlotOptionsIncompatible = errors.New("slot options incompatible")

type SlotService interface {
	ID() uuid.UUID
	Proto() ProxyProto
	BindAddr() string
	Deltas() []SlotDelta
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
	ID       uuid.UUID  `json:"id"`
	Proto    ProxyProto `json:"proto"`
	BindAddr string     `json:"bind_addr"`
}

func (opts *SlotOptions) Fingerprint() string {
	return fmt.Sprintf("%s:%s", opts.Proto, opts.BindAddr)
}

type Slot struct {
	SlotOptions

	BaseContext context.Context
	Rl          *RateLimiter
	DNS         DnsProvider

	deferredDeltas []PeerDelta

	peerMap     map[uuid.UUID]*Peer
	userNameMap map[string]*Peer
	mtx         sync.Mutex
}

func (slot *Slot) Deltas() []SlotDelta {

	slot.mtx.Lock()
	defer slot.mtx.Unlock()

	deltaList := slices.Clone(slot.deferredDeltas)
	slot.deferredDeltas = nil

	for _, peer := range slot.peerMap {
		if delta, has := peer.Deltas(); has {
			deltaList = append(deltaList, delta)
		}
	}

	peerMap := map[uuid.UUID]*PeerDelta{}

	for _, delta := range deltaList {

		entry := peerMap[delta.PeerID]
		if entry == nil {
			entry = &delta
			peerMap[delta.PeerID] = entry
		} else {
			entry.Rx += delta.Rx
			entry.Tx += delta.Tx
		}
	}

	var entries []SlotDelta
	for _, val := range peerMap {
		entries = append(entries, SlotDelta{
			SlotID:    slot.ID,
			PeerDelta: *val,
		})
	}

	return entries
}

func (slot *Slot) deferPeerDelta(peer *Peer) {
	if delta, has := peer.Deltas(); has {
		slot.deferredDeltas = append(slot.deferredDeltas, delta)
	}
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

		if _, has := importedUsernameSet[peer.PasswordAuth.UserName]; has {
			return fmt.Errorf("password auth: user name not unique: %s", peer.PasswordAuth.UserName)
		} else {
			importedUsernameSet[peer.PasswordAuth.UserName] = struct{}{}
		}

		return nil
	}

	newPeerMap := map[uuid.UUID]*Peer{}

	//	update peers
	for _, entry := range entries {

		if err := peerOptsValid(&entry); err != nil {
			slog.Warn("Update peers: Peer option invalid; Skipped",
				slog.String("slot_id", slot.ID.String()),
				slog.String("peer_id", entry.ID.String()),
				slog.String("name", entry.DisplayName()),
				slog.String("err", err.Error()))
			continue
		}

		framedIP, err := ParseFramedIP(entry.FramedIP)
		if err != nil {
			slog.Warn("Update peers: Framed IP unavailable",
				slog.String("slot_id", slot.ID.String()),
				slog.String("id", entry.ID.String()),
				slog.String("addr", entry.FramedIP),
				slog.String("name", entry.DisplayName()),
				slog.String("err", err.Error()))
		}

		if peer, ok := slot.peerMap[entry.ID]; ok {

			if peer.PeerOptions.Fingerprint() == entry.Fingerprint() {

				//	check if we have to reauthenticate
				mustReauth := !peer.PeerOptions.CmpCredentials(entry)

				//	update peer props
				peer.PeerOptions = entry
				peer.Dialer.LocalAddr = TcpDialAddr(framedIP)

				if mustReauth {
					slog.Debug("Peer credentials changed; Must reauthenticate",
						slog.String("slot_id", slot.ID.String()),
						slog.String("id", peer.ID.String()),
						slog.String("name", peer.DisplayName()))

					peer.CloseConnections()
				}

				//	update maps
				newPeerMap[peer.ID] = peer
				delete(slot.peerMap, entry.ID)

				slog.Debug("Update peer",
					slog.String("slot_id", slot.ID.String()),
					slog.String("id", peer.ID.String()),
					slog.String("name", peer.DisplayName()))

				continue
			}

			peer.Close()
			slot.deferPeerDelta(peer)
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

		if _, has := newPeerMap[entry.ID]; has {
			slog.Debug("Replace peer",
				slog.String("slot_id", slot.ID.String()),
				slog.String("id", peer.ID.String()),
				slog.String("name", peer.DisplayName()))
		} else {
			slog.Info("Create peer",
				slog.String("slot_id", slot.ID.String()),
				slog.String("id", peer.ID.String()),
				slog.String("name", peer.DisplayName()))
		}

		newPeerMap[entry.ID] = &peer
	}

	//	remove old peers
	for key, peer := range slot.peerMap {
		if _, has := newPeerMap[key]; !has {

			slog.Info("Remove peer",
				slog.String("slot_id", slot.ID.String()),
				slog.String("id", peer.ID.String()),
				slog.String("name", peer.DisplayName()))

			peer.Close()
			slot.deferPeerDelta(peer)
		}
	}

	slot.peerMap = newPeerMap

	//	remap by username
	newUserNameMap := map[string]*Peer{}
	for _, peer := range newPeerMap {
		if auth := peer.PeerOptions.PasswordAuth; auth != nil {
			newUserNameMap[auth.UserName] = peer
		}
	}

	slot.userNameMap = newUserNameMap
}

func (slot *Slot) Close() (err error) {

	slot.mtx.Lock()
	defer slot.mtx.Unlock()

	for key, peer := range slot.peerMap {
		peer.Close()
		slot.deferPeerDelta(peer)
		delete(slot.peerMap, key)
	}

	return
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
		return nil, ErrUserNotFound
	}

	var comparePasswords = func(want, have string) bool {
		return subtle.ConstantTimeCompare([]byte(want), []byte(have)) == 1
	}

	if pa := peer.PasswordAuth; pa == nil {
		return nil, ErrPasswordInvalid
	} else if !comparePasswords(pa.Password, password) {
		return nil, ErrPasswordInvalid
	}

	if rlc != nil {
		rlc.Reset()
	}

	return peer, nil
}

type SlotDelta struct {
	SlotID uuid.UUID `json:"slot"`
	PeerDelta
}
