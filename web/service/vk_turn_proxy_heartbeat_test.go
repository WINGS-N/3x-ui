package service

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/vkturnproxy"
)

func TestWireGuardPublicKeyFingerprintMatchesWingsVFormat(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	fingerprint, err := wireGuardPublicKeyFingerprint(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("wireGuardPublicKeyFingerprint returned error: %v", err)
	}

	if fingerprint != "sha256:riFsLvUkejeCwTXvonmj5M3GEJQnD10r5YxiBLemEsk" {
		t.Fatalf("unexpected fingerprint %q", fingerprint)
	}
}

func TestBuildVKTurnProxyHeartbeatPresenceUsesRecentHeartbeats(t *testing.T) {
	freshKey := make([]byte, 32)
	for i := range freshKey {
		freshKey[i] = byte(i + 1)
	}
	staleKey := make([]byte, 32)
	for i := range staleKey {
		staleKey[i] = byte(i + 33)
	}

	freshPublicKey := base64.StdEncoding.EncodeToString(freshKey)
	freshFingerprint, err := wireGuardPublicKeyFingerprint(freshPublicKey)
	if err != nil {
		t.Fatalf("wireGuardPublicKeyFingerprint returned error: %v", err)
	}
	stalePublicKey := base64.StdEncoding.EncodeToString(staleKey)
	staleFingerprint, err := wireGuardPublicKeyFingerprint(stalePublicKey)
	if err != nil {
		t.Fatalf("wireGuardPublicKeyFingerprint returned error: %v", err)
	}

	freshSettings := `{
		"forward": {"type": "wireguardInbound", "wireguardInboundId": 4},
		"clients": [
			{"id": "client-1", "email": "fresh@example.com", "enable": true, "peerPublicKey": "` + freshPublicKey + `"}
		]
	}`
	staleSettings := `{
		"forward": {"type": "wireguardInbound", "wireguardInboundId": 4},
		"clients": [
			{"id": "client-2", "email": "stale@example.com", "enable": true, "peerPublicKey": "` + stalePublicKey + `"}
		]
	}`
	now := time.Unix(1_760_000_000, 0)
	service := new(InboundService)
	inbounds := []*model.Inbound{
		{Id: 11, Settings: freshSettings},
		{Id: 12, Settings: staleSettings},
	}
	snapshot := map[int]map[string]vkturnproxy.HeartbeatState{
		11: {
			freshFingerprint: {
				Fingerprint: freshFingerprint,
				LastSeen:    now.Add(-30 * time.Second),
				Online:      true,
				Active:      1,
				Version:     1,
			},
		},
		12: {
			staleFingerprint: {
				Fingerprint: staleFingerprint,
				LastSeen:    now.Add(-10 * time.Minute),
				Online:      true,
				Active:      1,
				Version:     1,
			},
		},
	}

	online, lastOnline := service.buildVKTurnProxyHeartbeatPresence(inbounds, snapshot, now)
	if _, ok := online["fresh@example.com"]; !ok {
		t.Fatalf("expected fresh heartbeat client to be online, got %#v", online)
	}
	if _, ok := online["stale@example.com"]; ok {
		t.Fatalf("expected stale heartbeat client to be offline, got %#v", online)
	}
	if got := lastOnline["fresh@example.com"]; got != now.Add(-30*time.Second).UnixMilli() {
		t.Fatalf("unexpected fresh client last online: %d", got)
	}
	if got := lastOnline["stale@example.com"]; got != now.Add(-10*time.Minute).UnixMilli() {
		t.Fatalf("unexpected stale client last online: %d", got)
	}
}
