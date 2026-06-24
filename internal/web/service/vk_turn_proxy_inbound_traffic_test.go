package service

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

// TestBuildVKTurnProxyInboundTraffics asserts the per-client relay deltas are
// summed into each vk-turn-proxy inbound's own tag, so the inbound total stops
// reading 0, without touching any other inbound.
func TestBuildVKTurnProxyInboundTraffics(t *testing.T) {
	dbDir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dbDir)
	if err := database.InitDB(filepath.Join(dbDir, "x-ui.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { _ = database.CloseDB() })

	db := database.GetDB()
	vkSettings, _ := json.Marshal(map[string]any{
		"forward": map[string]any{"type": "wireguardInbound", "wireguardInboundId": 999},
	})
	vk := &model.Inbound{Tag: "vk-inbound", Enable: true, Port: 56000, Protocol: model.VKTurnProxy, Settings: string(vkSettings)}
	if err := db.Create(vk).Error; err != nil {
		t.Fatalf("create vk inbound: %v", err)
	}
	// A non-vk inbound that shares an id space; it must never get a synthesized row.
	wg := &model.Inbound{Tag: "wg-inbound", Enable: true, Port: 51820, Protocol: model.WireGuard, Settings: `{"peers":[]}`}
	if err := db.Create(wg).Error; err != nil {
		t.Fatalf("create wg inbound: %v", err)
	}

	svc := &InboundService{}
	clientTraffics := []*xray.ClientTraffic{
		{InboundId: vk.Id, Email: "a@x", Up: 100, Down: 200},
		{InboundId: vk.Id, Email: "b@x", Up: 50, Down: 0},
		{InboundId: vk.Id, Email: "c@x", Up: 0, Down: 0}, // zero delta ignored
		{InboundId: wg.Id, Email: "d@x", Up: 999, Down: 999},
	}

	got, err := svc.BuildVKTurnProxyInboundTraffics(clientTraffics)
	if err != nil {
		t.Fatalf("BuildVKTurnProxyInboundTraffics: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly one vk-turn inbound traffic row, got %d: %+v", len(got), got)
	}
	tr := got[0]
	if tr.Tag != "vk-inbound" || !tr.IsInbound {
		t.Fatalf("unexpected traffic target: %+v", tr)
	}
	if tr.Up != 150 || tr.Down != 200 {
		t.Fatalf("expected up=150 down=200, got up=%d down=%d", tr.Up, tr.Down)
	}
}
