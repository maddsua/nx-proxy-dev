package nxproxy

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var ErrRateLimited = errors.New("rate limited")

type RlCounter struct {
	init    int64
	quota   atomic.Int64
	expires time.Time
	mod     atomic.Bool
}

func (rlc *RlCounter) Reset() {
	rlc.quota.Store(rlc.init)
}

func (rlc *RlCounter) resetTo(val int64) {
	rlc.init = val
	rlc.quota.Store(val)
}

func (rlc *RlCounter) Use() error {

	if rlc.init <= 0 {
		return nil
	}

	if rlc.quota.Add(-1) < 0 {
		return ErrRateLimited
	}
	return nil
}

type RateLimiter struct {
	Quota  int64
	Window time.Duration

	entries          map[string]*RlCounter
	mtx              sync.Mutex
	cleanupScheduled atomic.Bool
}

func (rl *RateLimiter) Get(key string) *RlCounter {

	rl.mtx.Lock()
	defer rl.mtx.Unlock()

	if rl.entries == nil {
		rl.entries = map[string]*RlCounter{}
	}

	if rl.cleanupScheduled.CompareAndSwap(false, true) {
		time.AfterFunc(time.Minute, rl.cleanup)
	}

	ctr := rl.entries[key]
	if ctr == nil {
		ctr = &RlCounter{init: rl.Quota}
		rl.entries[key] = ctr
	}

	now := time.Now()

	if ctr.expires.Before(now) {
		ctr.resetTo(rl.Quota)
	}

	ctr.expires = now.Add(rl.Window)
	ctr.mod.Store(true)

	return ctr
}

func (rl *RateLimiter) cleanup() {

	rl.mtx.Lock()
	defer rl.mtx.Unlock()

	defer rl.cleanupScheduled.Store(false)

	now := time.Now()

	for key, entry := range rl.entries {

		if entry.expires.Before(now) {

			if entry.mod.Load() {
				entry.resetTo(rl.Quota)
				entry.mod.Store(false)
				continue
			}

			delete(rl.entries, key)
		}
	}
}
