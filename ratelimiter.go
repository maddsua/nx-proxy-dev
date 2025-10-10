package nxproxy

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type RateLimitError struct {
	Expires time.Time
}

func (val *RateLimitError) Error() string {
	return fmt.Sprintf("rate limited until %v", val.Expires)
}

var DefaultRatelimiter = RateLimiterOptions{
	Quota:  50,
	Window: 5 * time.Minute,
}

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
		return &RateLimitError{Expires: rlc.expires}
	}

	return nil
}

type RateLimiterOptions struct {
	Quota  int64
	Window time.Duration
}

type RateLimiter struct {
	RateLimiterOptions

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
