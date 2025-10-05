package nxproxy

import (
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

var ErrUserNotFound = errors.New("user not found")
var ErrPasswordInvalid = errors.New("password invalid")

//	todo: implement stats export
//	todo: implement peer import
//	todo: implement service interface

type Slot struct {
	peerMap     map[uuid.UUID]*Peer
	userNameMap map[string]*Peer
	mtx         sync.Mutex
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
