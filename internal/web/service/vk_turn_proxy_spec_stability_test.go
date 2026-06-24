package service

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/vkturnproxy"
)

// vkTurnStabilityDB spins up an isolated sqlite db with one wireguard inbound
// and one vk-turn-proxy inbound forwarding into it, returning their ids.
func vkTurnStabilityDB(t *testing.T) (wgID, vkID int) {
	t.Helper()
	dbDir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dbDir)
	if err := database.InitDB(filepath.Join(dbDir, "x-ui.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { _ = database.CloseDB() })

	db := database.GetDB()
	wgSettings, _ := json.Marshal(map[string]any{
		"mtu":       1420,
		"secretKey": "iLZqxL6Tn1Qe3jBJ7Bz1ULbpAFvWPLnGz0kSV0Zd2A=",
		"peers":     []any{},
	})
	wg := &model.Inbound{Tag: "wg-1", Enable: true, Port: 51820, Protocol: model.WireGuard, Settings: string(wgSettings)}
	if err := db.Create(wg).Error; err != nil {
		t.Fatalf("create wg inbound: %v", err)
	}

	vkSettings, _ := json.Marshal(map[string]any{
		"forward": map[string]any{"type": "wireguardInbound", "wireguardInboundId": wg.Id},
	})
	vk := &model.Inbound{Tag: "vk-1", Enable: true, Port: 56000, Protocol: model.VKTurnProxy, Settings: string(vkSettings)}
	if err := db.Create(vk).Error; err != nil {
		t.Fatalf("create vk inbound: %v", err)
	}
	return wg.Id, vk.Id
}

// TestLoadDesiredSpecsStableForUnchangedInbound asserts that two consecutive
// reconciles produce an identical Spec.Key() when nothing changed, so a running
// relay is never needlessly stopped by EnsureRunning.
func TestLoadDesiredSpecsStableForUnchangedInbound(t *testing.T) {
	_, vkID := vkTurnStabilityDB(t)
	svc := &VKTurnProxyService{processes: map[int]*vkturnproxy.Process{}}

	first, err := svc.loadDesiredSpecs(nil)
	if err != nil {
		t.Fatalf("loadDesiredSpecs first: %v", err)
	}
	second, err := svc.loadDesiredSpecs(nil)
	if err != nil {
		t.Fatalf("loadDesiredSpecs second: %v", err)
	}
	a, ok := first[vkID]
	if !ok {
		t.Fatalf("vk inbound %d missing from first desired set", vkID)
	}
	b, ok := second[vkID]
	if !ok {
		t.Fatalf("vk inbound %d missing from second desired set", vkID)
	}
	if a.Key() != b.Key() {
		t.Fatalf("spec key drifted for unchanged inbound:\n  %q\n  %q", a.Key(), b.Key())
	}
}

// TestLoadDesiredSpecsCarriesRunningForwardOnResolveFailure asserts that when
// the forward target can no longer be resolved (its wireguard inbound is gone),
// a still-running relay's spec is carried forward instead of being dropped from
// the desired set, which previously stopped a live relay and flapped the status.
func TestLoadDesiredSpecsCarriesRunningForwardOnResolveFailure(t *testing.T) {
	wgID, vkID := vkTurnStabilityDB(t)
	svc := &VKTurnProxyService{processes: map[int]*vkturnproxy.Process{}}

	resolved, err := svc.loadDesiredSpecs(nil)
	if err != nil {
		t.Fatalf("loadDesiredSpecs: %v", err)
	}
	runningSpec, ok := resolved[vkID]
	if !ok {
		t.Fatalf("vk inbound %d missing from desired set", vkID)
	}

	// Break the forward target so resolveVKTurnProxyForwardAddress fails.
	if err := database.GetDB().Delete(&model.Inbound{}, wgID).Error; err != nil {
		t.Fatalf("delete wg inbound: %v", err)
	}

	// Without a running relay the inbound is dropped (cannot resolve a target).
	dropped, err := svc.loadDesiredSpecs(nil)
	if err != nil {
		t.Fatalf("loadDesiredSpecs (dropped): %v", err)
	}
	if _, present := dropped[vkID]; present {
		t.Fatalf("expected vk inbound %d dropped when target unresolved and no relay running", vkID)
	}

	// With a running relay the prior spec is carried forward, keeping the relay alive.
	carried, err := svc.loadDesiredSpecs(map[int]vkturnproxy.Spec{vkID: runningSpec})
	if err != nil {
		t.Fatalf("loadDesiredSpecs (carried): %v", err)
	}
	got, present := carried[vkID]
	if !present {
		t.Fatalf("expected vk inbound %d carried forward while relay running", vkID)
	}
	if got.Key() != runningSpec.Key() {
		t.Fatalf("carried spec key changed:\n  %q\n  %q", got.Key(), runningSpec.Key())
	}
}
