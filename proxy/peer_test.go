package proxy_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/maddsua/nx-proxy/proxy"
)

func TestPeer_ConnLimit(t *testing.T) {

	peer := proxy.Peer{
		PeerOptions: proxy.PeerOptions{
			ID:             uuid.New(),
			MaxConnections: 10,
		},
	}

	for idx := range 20 {

		_, err := peer.Connection()
		if idx < int(peer.MaxConnections) && err != nil {
			t.Errorf("unexpected err: %v at idx %d", err, idx)
		} else if idx > int(peer.MaxConnections) && err != proxy.ErrTooManyConnections {
			t.Errorf("unexpected absense of ErrTooManyConnections at idx %d", idx)
		}
	}
}

func TestPeer_Bandwidth_1(t *testing.T) {

	peer := proxy.Peer{
		PeerOptions: proxy.PeerOptions{
			ID:             uuid.New(),
			MaxConnections: 10,
		},
	}

	for range 5 {

		conn, err := peer.Connection()
		if err != nil {
			t.Errorf("unexpected err: %v", err)
		}

		defer conn.Close()
	}

	conn, err := peer.Connection()
	if err != nil {
		t.Errorf("unexpected err: %v", err)
	}

	conn.AccountRx(200_000)
	conn.AccountTx(20_000)

	peer.RefreshState()

	if val, _ := conn.BandwidthRx(); val != 0 {
		t.Errorf("unexpected rx rate: %d", val)
	}

	if val, _ := conn.BandwidthTx(); val != 0 {
		t.Errorf("unexpected tx rate: %d", val)
	}
}

func TestPeer_Bandwidth_2(t *testing.T) {

	peer := proxy.Peer{
		PeerOptions: proxy.PeerOptions{
			ID:             uuid.New(),
			MaxConnections: 10,
			Bandwidth: proxy.PeerBandwidth{
				Rx:    10_000,
				Tx:    10_000,
				MinRx: 1_000,
				MinTx: 1_000,
			},
		},
	}

	for range 5 {

		conn, err := peer.Connection()
		if err != nil {
			t.Errorf("unexpected err: %v", err)
		}

		conn.AccountRx(500)
		conn.AccountTx(100)

		defer conn.Close()
	}

	conn, err := peer.Connection()
	if err != nil {
		t.Errorf("unexpected err: %v", err)
	}

	conn.AccountRx(2_000)
	conn.AccountTx(1_600)

	peer.RefreshState()

	if val, _ := conn.BandwidthRx(); val != 7496 {
		t.Errorf("unexpected rx rate: %d", val)
	}

	if val, _ := conn.BandwidthTx(); val != 9496 {
		t.Errorf("unexpected tx rate: %d", val)
	}
}

func TestPeer_Bandwidth_3(t *testing.T) {

	peer := proxy.Peer{
		PeerOptions: proxy.PeerOptions{
			ID:             uuid.New(),
			MaxConnections: 10,
			Bandwidth: proxy.PeerBandwidth{
				Rx:    10_000,
				Tx:    10_000,
				MinRx: 1_000,
				MinTx: 1_000,
			},
		},
	}

	for range 5 {

		conn, err := peer.Connection()
		if err != nil {
			t.Errorf("unexpected err: %v", err)
		}

		conn.AccountRx(500)
		conn.AccountTx(100)

		defer conn.Close()
	}

	conn, err := peer.Connection()
	if err != nil {
		t.Errorf("unexpected err: %v", err)
	}

	conn.AccountRx(500)
	conn.AccountTx(100)

	peer.RefreshState()

	if val, _ := conn.BandwidthRx(); val != 1666 {
		t.Errorf("unexpected rx rate: %d", val)
	}

	if val, _ := conn.BandwidthTx(); val != 1666 {
		t.Errorf("unexpected tx rate: %d", val)
	}
}
