package nxproxy_test

import (
	"testing"

	"github.com/google/uuid"
	nxproxy "github.com/maddsua/nx-proxy"
)

func TestPeer_ConnLimit(t *testing.T) {

	peer := nxproxy.Peer{
		ID: uuid.New(),
		PasswordAuth: &nxproxy.PeerPasswordAuth{
			UserName: "maddsua",
			Password: "test123",
		},
		MaxConnections: 10,
	}

	for idx := range 20 {

		_, err := peer.Connection()
		if idx < int(peer.MaxConnections) && err != nil {
			t.Errorf("unexpected err: %v at idx %d", err, idx)
		} else if idx > int(peer.MaxConnections) && err != nxproxy.ErrTooManyConnections {
			t.Errorf("unexpected absense of ErrTooManyConnections at idx %d", idx)
		}
	}
}

func TestPeer_Bandwidth_1(t *testing.T) {

	peer := nxproxy.Peer{
		ID: uuid.New(),
		PasswordAuth: &nxproxy.PeerPasswordAuth{
			UserName: "maddsua",
			Password: "test123",
		},
		MaxConnections: 10,
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

	conn.DataReceived.Add(200_000)
	conn.DataSent.Add(20_000)

	peer.RefreshState()

	if val := conn.DataRateDown.Load(); val != 0 {
		t.Errorf("unexpected rx rate: %d", val)
	}

	if val := conn.DataRateUp.Load(); val != 0 {
		t.Errorf("unexpected tx rate: %d", val)
	}
}

func TestPeer_Bandwidth_2(t *testing.T) {

	peer := nxproxy.Peer{
		ID: uuid.New(),
		PasswordAuth: &nxproxy.PeerPasswordAuth{
			UserName: "maddsua",
			Password: "test123",
		},
		MaxConnections: 10,
		Bandwidth: nxproxy.PeerBandwidth{
			Rx:    10_000,
			Tx:    10_000,
			MinRx: 5_000,
			MinTx: 5_000,
		},
	}

	for range 5 {

		conn, err := peer.Connection()
		if err != nil {
			t.Errorf("unexpected err: %v", err)
		}

		conn.DataReceived.Add(1_000)
		conn.DataSent.Add(500)

		defer conn.Close()
	}

	conn, err := peer.Connection()
	if err != nil {
		t.Errorf("unexpected err: %v", err)
	}

	conn.DataReceived.Add(2_000)
	conn.DataSent.Add(1_000)

	peer.RefreshState()

	if val := conn.DataRateDown.Load(); val != 0 {
		t.Errorf("unexpected rx rate: %d", val)
	}

	if val := conn.DataRateUp.Load(); val != 0 {
		t.Errorf("unexpected tx rate: %d", val)
	}
}
