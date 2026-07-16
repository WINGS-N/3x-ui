package service

import (
	"encoding/json"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

// A wireguard peer is a client row since upstream v3.5 (WireguardPeersToClients).
// getWireguardSettings must decode settings.clients, and mutateWireguardPeers must
// write back into settings.clients WITHOUT dropping the client fields the peer view
// does not model - losing subId/tgId/limits would silently unlink the client rows.
func TestWireguardPeersRoundTripThroughClientsPreservingClientFields(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()

	settings := map[string]any{
		"mtu":       1420,
		"secretKey": "iLZqxL6Tn1Qe3jBJ7Bz1ULbpAFvWPLnGz0kSV0Zd2A=",
		"clients": []map[string]any{
			{
				"email":      "alice",
				"privateKey": "k1",
				"publicKey":  "pub-1",
				"allowedIPs": []string{"10.0.0.2/32"},
				"enable":     true,
				"subId":      "sub-alice",
				"totalGB":    42,
				"comment":    "keep me",
			},
			{
				"email":      "bob",
				"privateKey": "k2",
				"publicKey":  "pub-2",
				"allowedIPs": []string{"10.0.0.3/32"},
				"enable":     true,
				"subId":      "sub-bob",
			},
		},
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	wg := &model.Inbound{
		Tag:      "wg-clients",
		Enable:   true,
		Listen:   "0.0.0.0",
		Port:     51821,
		Protocol: model.WireGuard,
		Settings: string(raw),
	}
	if err := db.Create(wg).Error; err != nil {
		t.Fatalf("seed wg inbound: %v", err)
	}

	svc := &InboundService{}

	// Read: peers come out of settings.clients.
	_, peers, err := svc.getWireguardSettings(wg.Settings)
	if err != nil {
		t.Fatalf("getWireguardSettings: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("peers = %d, want 2", len(peers))
	}
	if peers[0].PublicKey != "pub-1" || peers[0].Email != "alice" {
		t.Fatalf("peer[0] = %+v, want pub-1/alice", peers[0])
	}

	// Write: change one allowedIP, add a peer.
	if _, err := svc.mutateWireguardPeers(wg.Id, func(current []wireguardPeer) ([]wireguardPeer, error) {
		current[0].AllowedIPs = []string{"10.0.0.7/32"}
		return append(current, wireguardPeer{
			PrivateKey: "k3",
			PublicKey:  "pub-3",
			AllowedIPs: []string{"10.0.0.4/32"},
			Email:      "carol",
		}), nil
	}); err != nil {
		t.Fatalf("mutateWireguardPeers: %v", err)
	}

	updated, err := svc.GetInbound(wg.Id)
	if err != nil {
		t.Fatalf("GetInbound: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal([]byte(updated.Settings), &back); err != nil {
		t.Fatalf("unmarshal updated settings: %v", err)
	}
	if _, stillInline := back["peers"]; stillInline {
		t.Fatal("settings.peers must not be written back; peers live in settings.clients")
	}
	clients, ok := back["clients"].([]any)
	if !ok || len(clients) != 3 {
		t.Fatalf("clients = %#v, want 3 entries", back["clients"])
	}

	first, _ := clients[0].(map[string]any)
	if got := first["subId"]; got != "sub-alice" {
		t.Errorf("subId = %v, want sub-alice (unmodelled client fields must survive)", got)
	}
	if got := first["comment"]; got != "keep me" {
		t.Errorf("comment = %v, want \"keep me\" (unmodelled client fields must survive)", got)
	}
	if got := first["totalGB"]; got != float64(42) {
		t.Errorf("totalGB = %v, want 42 (unmodelled client fields must survive)", got)
	}
	if got := first["email"]; got != "alice" {
		t.Errorf("email = %v, want alice", got)
	}
	ips, _ := first["allowedIPs"].([]any)
	if len(ips) != 1 || ips[0] != "10.0.0.7/32" {
		t.Errorf("allowedIPs = %v, want [10.0.0.7/32]", first["allowedIPs"])
	}

	// A minted peer must become a usable client row: email carried, enabled,
	// and given a subId so SyncInbound can materialize it.
	third, _ := clients[2].(map[string]any)
	if got := third["email"]; got != "carol" {
		t.Errorf("minted email = %v, want carol", got)
	}
	if got := third["enable"]; got != true {
		t.Errorf("minted enable = %v, want true", got)
	}
	if sub, _ := third["subId"].(string); sub == "" {
		t.Error("minted peer must get a subId")
	}
}
