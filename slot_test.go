package nxproxy_test

import (
	"testing"

	"github.com/google/uuid"
	nxproxy "github.com/maddsua/nx-proxy"
)

func TestSlotPeerImport(t *testing.T) {

	var slot nxproxy.Slot

	slot.SetPeers([]nxproxy.PeerOptions{
		{
			ID: uuid.MustParse("b9cfd40e-255c-4101-85b9-73ab9efb509f"),
			PasswordAuth: &nxproxy.PeerPasswordAuth{
				UserName: "maddsua",
				Password: "test123",
			},
		},
		{
			ID: uuid.MustParse("c0db0438-4d76-4c53-83f1-81fe053e0102"),
			PasswordAuth: &nxproxy.PeerPasswordAuth{
				UserName: "someoneelse",
				Password: "88888888888",
			},
		},
	})

	persistedPeer, err := slot.LookupWithPassword("maddsua", "test123")
	if err != nil {
		t.Fatalf("LookupWithPassword: %v", err)
	}

	ephemeralPeer, err := slot.LookupWithPassword("someoneelse", "88888888888")
	if err != nil {
		t.Fatalf("LookupWithPassword: %v", err)
	}

	slot.SetPeers([]nxproxy.PeerOptions{
		{
			ID: uuid.MustParse("b9cfd40e-255c-4101-85b9-73ab9efb509f"),
			PasswordAuth: &nxproxy.PeerPasswordAuth{
				UserName: "maddsua",
				Password: "test123",
			},
		},
	})

	if _, err := slot.LookupWithPassword("someoneelse", "88888888888"); err != nxproxy.ErrUserNotFound {
		t.Fatalf("LookupWithPassword: %v", err)
	}

	if _, err := persistedPeer.Connection(); err != nil {
		t.Errorf("unexpected err: %v", err)
	}

	if _, err := ephemeralPeer.Connection(); err != nxproxy.ErrPeerClosed {
		t.Errorf("unexpected absense of ErrPeerClosed")
	}
}

func TestSlotDeltas(t *testing.T) {

	var slot nxproxy.Slot

	slot.SetPeers([]nxproxy.PeerOptions{
		{
			ID: uuid.MustParse("4f33d96b-3f6e-4d29-8936-0e0490c44d93"),
			PasswordAuth: &nxproxy.PeerPasswordAuth{
				UserName: "maddsua",
				Password: "test123",
			},
		},
		{
			ID: uuid.MustParse("6018594e-6eee-4de8-86dc-33247142204f"),
			PasswordAuth: &nxproxy.PeerPasswordAuth{
				UserName: "notmaddsua",
				Password: "00000000",
			},
		},
		{
			ID: uuid.MustParse("3e0e7056-8ded-4546-99f0-1b0c9014773d"),
			PasswordAuth: &nxproxy.PeerPasswordAuth{
				UserName: "someone_else",
				Password: "123456",
			},
		},
	})

	if peer, err := slot.LookupWithPassword("maddsua", "test123"); err != nil {
		t.Fatalf("LookupWithPassword: %v", err)
	} else {
		peer.DataReceived.Add(2000)
		peer.DataSent.Add(1000)
	}

	if peer, err := slot.LookupWithPassword("notmaddsua", "00000000"); err != nil {
		t.Fatalf("LookupWithPassword: %v", err)
	} else {
		peer.DataReceived.Add(852000)
		peer.DataSent.Add(25000)
		peer.Close()
	}

	slot.SetPeers([]nxproxy.PeerOptions{
		{
			ID: uuid.MustParse("4f33d96b-3f6e-4d29-8936-0e0490c44d93"),
			PasswordAuth: &nxproxy.PeerPasswordAuth{
				UserName: "maddsua",
				Password: "test123",
			},
		},
	})

	deltas := slot.Deltas()
	if len(deltas) != 2 {
		t.Errorf("unexpected slice length: %d", len(deltas))
	}

	for _, entry := range deltas {

		var expectReceived int
		var expectSent int

		switch entry.PeerID {

		case uuid.MustParse("6018594e-6eee-4de8-86dc-33247142204f"):
			expectReceived = 852000
			expectSent = 25000

		case uuid.MustParse("4f33d96b-3f6e-4d29-8936-0e0490c44d93"):
			expectReceived = 2000
			expectSent = 1000

		default:
			t.Errorf("unexpected PeerID: %v", entry.PeerID)
		}

		if entry.DataReceived != uint64(expectReceived) {
			t.Errorf("unexpected 'DataReceived' of '%v': %d", entry.PeerID, entry.DataReceived)
		} else if entry.DataSent != uint64(expectSent) {
			t.Errorf("unexpected 'DataSent' of '%v': %d", entry.PeerID, entry.DataReceived)
		}
	}
}
