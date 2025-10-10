package nxproxy

import "time"

func RedistributePeerBandwidth(conns []*PeerConnection, bandwidth PeerBandwidth) {

	var getBaseBandwidth = func(val uint32) uint32 {

		if n := len(conns); n > 1 {
			return val / uint32(n)
		}

		return val
	}

	var equivalentBandwidth = func(base uint32, updatedAt time.Time) uint64 {

		if !updatedAt.IsZero() {
			if elapsed := time.Since(updatedAt); elapsed > time.Second {
				return uint64(elapsed.Seconds() * float64(base))
			}
		}

		return uint64(base)
	}

	baseRx := getBaseBandwidth(bandwidth.Rx)
	baseTx := getBaseBandwidth(bandwidth.Tx)

	var unusedRx uint32
	var unusedTx uint32

	now := time.Now()

	var saturationThreshold = func(val uint64) uint64 {
		return val - (val / 10)
	}

	satThresholdRx := saturationThreshold(uint64(baseRx))
	satThresholdTx := saturationThreshold(uint64(baseTx))

	var nsatRx, nsatTx int

	//	calculate unused bandwidth
	for _, conn := range conns {

		equivRx := equivalentBandwidth(baseRx, conn.updated)
		equivTx := equivalentBandwidth(baseTx, conn.updated)

		volRx := conn.deltaRx.Load()
		volTx := conn.deltaTx.Load()

		if volRx >= satThresholdRx {
			nsatRx++
		} else if delta := equivRx - volRx; delta > 0 {
			unusedRx += uint32(delta)
		}

		if volTx >= satThresholdTx {
			nsatTx++
		} else if delta := equivTx - volTx; delta > 0 {
			unusedTx += uint32(delta)
		}

		conn.updated = now
	}

	//	redistribute extra bandwidth and take data volume stats
	for _, conn := range conns {

		var extraRx, extraTx uint32

		if nsatRx > 0 && conn.deltaRx.Load() >= satThresholdRx {
			extraRx = unusedRx / uint32(nsatRx)
		}

		if nsatTx > 0 && conn.deltaTx.Load() >= satThresholdTx {
			extraTx = unusedTx / uint32(nsatTx)
		}

		conn.bandRx.Store(max(baseRx+extraRx, bandwidth.MinRx))
		conn.bandTx.Store(max(baseTx+extraTx, bandwidth.MinTx))
	}
}
