package service

import "testing"

// clientWithPeer builds a VK-TURN client holding a single managed peer
// pinned to the given 10.0.0.X octet, with the requested enable state.
func clientWithPeer(id string, enable bool, octet int) VKTurnProxyClient {
	return VKTurnProxyClient{
		ID:          id,
		Email:       id,
		Enable:      enable,
		PeerManaged: true,
		Peer: &VKTurnProxyClientPeer{
			PublicKey:  id + "-pub",
			AllowedIPs: []string{fmtOctet(octet)},
		},
		PeerPublicKey: id + "-pub",
	}
}

func fmtOctet(octet int) string {
	return "10.0.0." + itoa(octet) + "/32"
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	digits := ""
	for v > 0 {
		digits = string(rune('0'+v%10)) + digits
		v /= 10
	}
	return digits
}

// A disabled client keeps its reserved 10.0.0.X address: a freshly
// provisioned client must never reuse the disabled client's octet, even
// though its peer was removed from the target WG inbound. This is the
// "no duplicate AllowedIP in place of a disabled client" guarantee.
func TestVKTurnProxyAllocatorReservesDisabledClients(t *testing.T) {
	s := &InboundService{}
	settings := &VKTurnProxySettings{
		Clients: []VKTurnProxyClient{
			clientWithPeer("a", true, 2),
			clientWithPeer("b", false, 3), // disabled, peer pulled from WG inbound
		},
	}
	alloc, err := s.newVKTurnProxyPeerAllocator(settings)
	if err != nil {
		t.Fatalf("newVKTurnProxyPeerAllocator: %v", err)
	}
	got, err := alloc.Allocate()
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if got != "10.0.0.4/32" {
		t.Fatalf("expected next free octet 10.0.0.4/32 (2 and disabled 3 reserved), got %s", got)
	}
}

// Two allocations from the same allocator must stay distinct (no
// incremental-from-last collision within one batch / copy operation).
func TestVKTurnProxyAllocatorUniqueWithinBatch(t *testing.T) {
	s := &InboundService{}
	settings := &VKTurnProxySettings{
		Clients: []VKTurnProxyClient{clientWithPeer("a", true, 2)},
	}
	alloc, err := s.newVKTurnProxyPeerAllocator(settings)
	if err != nil {
		t.Fatalf("newVKTurnProxyPeerAllocator: %v", err)
	}
	first, _ := alloc.Allocate()
	second, _ := alloc.Allocate()
	if first == second {
		t.Fatalf("allocator handed out the same address twice: %s", first)
	}
	if first != "10.0.0.3/32" || second != "10.0.0.4/32" {
		t.Fatalf("expected 10.0.0.3 then 10.0.0.4, got %s then %s", first, second)
	}
}

// A hole freed by deleting a client is reused by the next allocation
// (lowest free wins), so the pool does not leak addresses.
func TestVKTurnProxyAllocatorReusesFreedHole(t *testing.T) {
	s := &InboundService{}
	settings := &VKTurnProxySettings{
		Clients: []VKTurnProxyClient{
			clientWithPeer("a", true, 2),
			clientWithPeer("c", true, 4), // 3 is a hole left by a deleted client
		},
	}
	alloc, err := s.newVKTurnProxyPeerAllocator(settings)
	if err != nil {
		t.Fatalf("newVKTurnProxyPeerAllocator: %v", err)
	}
	got, _ := alloc.Allocate()
	if got != "10.0.0.3/32" {
		t.Fatalf("expected freed hole 10.0.0.3/32 to be reused, got %s", got)
	}
}
