package nxproxy

import (
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
)

var ErrUserNotFound = errors.New("user not found")
var ErrPasswordInvalid = errors.New("password invalid")

type SlotService interface {
	Error() error
	Close() error
}

type ServiceType string

func (val ServiceType) Valid() bool {
	return val == ServiceTypeHttp || val == ServiceTypeSocks
}

const (
	ServiceTypeSocks = "socks"
	ServiceTypeHttp  = "http"
)

type SlotOptions struct {
	ID          uuid.UUID   `json:"id"`
	ServiceType ServiceType `json:"service_type"`
	BindAddr    string      `json:"bind_addr"`
}

type Slot struct {
	SlotOptions
	Service SlotService

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

func (slot *Slot) ImportPeerList(entries []PeerOptions) {

	slot.mtx.Lock()
	defer slot.mtx.Unlock()

	newPeerMap := map[uuid.UUID]*Peer{}

	for _, entry := range entries {

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

	newUserNameMap := map[string]*Peer{}

	for _, peer := range newPeerMap {
		if auth := peer.PeerOptions.PasswordAuth; auth != nil {
			newUserNameMap[auth.UserName] = peer
		}
	}

	for key, peer := range slot.peerMap {
		if _, has := newPeerMap[key]; !has {
			peer.Close()
			slot.deferPeerDelta(peer)
		}
	}

	slot.peerMap = newPeerMap
	slot.userNameMap = newUserNameMap
}

func (slot *Slot) Close() {

	slot.mtx.Lock()
	defer slot.mtx.Unlock()

	for key, peer := range slot.peerMap {
		peer.Close()
		slot.deferPeerDelta(peer)
		delete(slot.peerMap, key)
	}
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
		//	a small fake delay to hinder password cracking attempts without having to use a full blown rate limiter
		time.Sleep(5 * time.Second)
		return nil, ErrPasswordInvalid
	}

	return peer, nil
}

type SlotDelta struct {
	SlotID uuid.UUID `json:"slot_id"`
	PeerDelta
}
