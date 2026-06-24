package service

import (
	"encoding/json"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

func wgInboundSettingsJSON(t *testing.T, peers []wireguardPeer) string {
	t.Helper()
	payload := map[string]any{
		"mtu":       1420,
		"secretKey": "iLZqxL6Tn1Qe3jBJ7Bz1ULbpAFvWPLnGz0kSV0Zd2A=",
		"peers":     peers,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal wg settings: %v", err)
	}
	return string(raw)
}

func TestFixWireguardAllowedIPConflicts_ReassignsDuplicateAndSyncsClient(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()

	peers := []wireguardPeer{
		{PrivateKey: "k1", PublicKey: "pub-1", AllowedIPs: []string{"10.0.0.2/32"}},
		{PrivateKey: "k2", PublicKey: "pub-2", AllowedIPs: []string{"10.0.0.9/32"}},
		{PrivateKey: "k3", PublicKey: "pub-3", AllowedIPs: []string{"10.0.0.9/32"}},
	}
	wg := &model.Inbound{
		Tag:      "wg-1",
		Enable:   true,
		Listen:   "0.0.0.0",
		Port:     51820,
		Protocol: model.WireGuard,
		Settings: wgInboundSettingsJSON(t, peers),
	}
	if err := db.Create(wg).Error; err != nil {
		t.Fatalf("seed wg inbound: %v", err)
	}

	vkSettings := &VKTurnProxySettings{
		Forward: VKTurnProxyForward{Type: VKTurnProxyForwardWireGuardInbound, WireGuardInboundID: wg.Id},
		Link:    "vk://example",
		Clients: []VKTurnProxyClient{
			{
				ID:            "client-1",
				Email:         "alice@example.com",
				Enable:        true,
				PeerManaged:   true,
				PeerPublicKey: "pub-3",
				Peer: &VKTurnProxyClientPeer{
					PrivateKey: "k3",
					PublicKey:  "pub-3",
					AllowedIPs: []string{"10.0.0.9/32"},
				},
			},
		},
	}
	svc := &InboundService{}
	rawVK, err := svc.marshalVKTurnProxySettings(vkSettings)
	if err != nil {
		t.Fatalf("marshal vk settings: %v", err)
	}
	vk := &model.Inbound{
		Tag:      "vk-1",
		Enable:   true,
		Listen:   "0.0.0.0",
		Port:     7000,
		Protocol: model.VKTurnProxy,
		Settings: rawVK,
	}
	if err := db.Create(vk).Error; err != nil {
		t.Fatalf("seed vk inbound: %v", err)
	}

	fixed, err := svc.FixWireguardAllowedIPConflicts(wg.Id)
	if err != nil {
		t.Fatalf("FixWireguardAllowedIPConflicts: %v", err)
	}
	if len(fixed) != 1 {
		t.Fatalf("expected exactly one fixed conflict, got %d: %+v", len(fixed), fixed)
	}
	f := fixed[0]
	if f.PublicKey != "pub-3" || f.OldIP != "10.0.0.9/32" {
		t.Fatalf("unexpected fix entry: %+v", f)
	}
	if f.NewIP != "10.0.0.3/32" {
		t.Fatalf("expected next free 10.0.0.3/32, got %s", f.NewIP)
	}
	if f.Client != "alice@example.com" {
		t.Fatalf("expected bound client email, got %q", f.Client)
	}

	// WG inbound peers must now be conflict-free.
	conflicts, err := svc.WireguardAllowedIPConflicts(wg.Id)
	if err != nil {
		t.Fatalf("WireguardAllowedIPConflicts: %v", err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("expected no remaining conflicts, got %v", conflicts)
	}

	// The reassigned peer carries the new address; the first claimant keeps 10.0.0.9.
	reloaded, err := svc.GetInbound(wg.Id)
	if err != nil {
		t.Fatalf("reload wg: %v", err)
	}
	_, reloadedPeers, err := svc.getWireguardSettings(reloaded.Settings)
	if err != nil {
		t.Fatalf("parse reloaded wg: %v", err)
	}
	idx := svc.findWireguardPeerIndexByPublicKey(reloadedPeers, "pub-3")
	if idx < 0 || len(reloadedPeers[idx].AllowedIPs) != 1 || reloadedPeers[idx].AllowedIPs[0] != "10.0.0.3/32" {
		t.Fatalf("pub-3 peer not reassigned correctly: %+v", reloadedPeers)
	}
	idx2 := svc.findWireguardPeerIndexByPublicKey(reloadedPeers, "pub-2")
	if idx2 < 0 || reloadedPeers[idx2].AllowedIPs[0] != "10.0.0.9/32" {
		t.Fatalf("pub-2 peer should keep 10.0.0.9/32: %+v", reloadedPeers)
	}

	// The vk-turn client snapshot must have been updated to the new address.
	vkReloaded, err := svc.GetInbound(vk.Id)
	if err != nil {
		t.Fatalf("reload vk: %v", err)
	}
	vkParsed, err := svc.getVKTurnProxySettings(vkReloaded.Settings)
	if err != nil {
		t.Fatalf("parse reloaded vk: %v", err)
	}
	if len(vkParsed.Clients) != 1 || vkParsed.Clients[0].Peer == nil {
		t.Fatalf("vk client/peer missing: %+v", vkParsed.Clients)
	}
	if got := vkParsed.Clients[0].Peer.AllowedIPs; len(got) != 1 || got[0] != "10.0.0.3/32" {
		t.Fatalf("vk client peer AllowedIPs not synced, got %v", got)
	}
}

func TestFixWireguardAllowedIPConflicts_NoConflictsReturnsEmpty(t *testing.T) {
	setupConflictDB(t)
	db := database.GetDB()

	peers := []wireguardPeer{
		{PrivateKey: "k1", PublicKey: "pub-1", AllowedIPs: []string{"10.0.0.2/32"}},
		{PrivateKey: "k2", PublicKey: "pub-2", AllowedIPs: []string{"10.0.0.3/32"}},
	}
	wg := &model.Inbound{
		Tag:      "wg-clean",
		Enable:   true,
		Listen:   "0.0.0.0",
		Port:     51821,
		Protocol: model.WireGuard,
		Settings: wgInboundSettingsJSON(t, peers),
	}
	if err := db.Create(wg).Error; err != nil {
		t.Fatalf("seed wg inbound: %v", err)
	}

	svc := &InboundService{}
	fixed, err := svc.FixWireguardAllowedIPConflicts(wg.Id)
	if err != nil {
		t.Fatalf("FixWireguardAllowedIPConflicts: %v", err)
	}
	if len(fixed) != 0 {
		t.Fatalf("expected no fixes on a clean inbound, got %+v", fixed)
	}
}
