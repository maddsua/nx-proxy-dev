package nxproxy

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/google/uuid"
)

//	todo: add some sort of rate limiting

var ErrUserNotFound = errors.New("user not found")
var ErrPasswordInvalid = errors.New("password invalid")
var ErrSlotOptionsIncompatible = errors.New("slot options incompatible")

type PasswordAuthenticator interface {
	LookupWithPassword(username, password string) (*Peer, error)
}

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
	Slot  SlotOptions   `json:"slot"`
	Peers []PeerOptions `json:"peers"`
}

type SlotOptions struct {
	ID       uuid.UUID  `json:"id"`
	Proto    ProxyProto `json:"proto"`
	BindAddr string     `json:"bind_addr"`
}

type Slot struct {
	SlotOptions
	Server SlotService

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
			entry.DataReceived += delta.DataReceived
			entry.DataSent += delta.DataSent
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
			slog.Warn("Slot: Import peer: Entry invalid; Skipped",
				slog.String("slot_id", slot.ID.String()),
				slog.String("peer_id", entry.ID.String()),
				slog.String("err", err.Error()))
			continue
		}

		if peer, ok := slot.peerMap[entry.ID]; ok {

			if peer.PeerOptions.Fingerprint() == entry.Fingerprint() {
				peer.PeerOptions = entry
				newPeerMap[peer.ID] = peer
				delete(slot.peerMap, entry.ID)
				continue
			}

			peer.Close()
			slot.deferPeerDelta(peer)
		}

		newPeerMap[entry.ID] = &Peer{PeerOptions: entry}
	}

	//	remove old peers
	for key, peer := range slot.peerMap {
		if _, has := newPeerMap[key]; !has {
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

	if slot.Server != nil {
		err = slot.Server.Close()
	}

	for key, peer := range slot.peerMap {
		peer.Close()
		slot.deferPeerDelta(peer)
		delete(slot.peerMap, key)
	}

	return
}

func (slot *Slot) LookupWithPassword(username, password string) (*Peer, error) {

	slot.mtx.Lock()
	defer slot.mtx.Unlock()

	if slot.peerMap == nil {
		slot.peerMap = map[uuid.UUID]*Peer{}
	}

	peer := slot.userNameMap[username]
	if peer == nil {
		return nil, ErrUserNotFound
	}

	var comparePasswords = func(want, have []byte) bool {

		if len(want) != len(have) {
			return false
		}

		var fail bool

		for idx, val := range want {
			if have[idx] != val {
				fail = true
			}
		}

		return !fail
	}

	if pa := peer.PasswordAuth; pa == nil {
		return nil, ErrPasswordInvalid
	} else if !comparePasswords([]byte(pa.Password), []byte(password)) {
		return nil, ErrPasswordInvalid
	}

	return peer, nil
}

type SlotDelta struct {
	SlotID uuid.UUID `json:"slot_id"`
	PeerDelta
}
