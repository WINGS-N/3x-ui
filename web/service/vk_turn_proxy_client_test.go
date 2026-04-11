package service

import (
	"bytes"
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func TestValidateWireguardPeersRejectsDuplicateAllowedIPs(t *testing.T) {
	service := new(InboundService)
	peerA := wireguardPeer{
		PrivateKey: testWireGuardPrivateKey(0x11),
		PublicKey:  mustDeriveTestWireGuardPublicKey(t, testWireGuardPrivateKey(0x11)),
		AllowedIPs: []string{"10.0.0.2"},
	}
	peerB := wireguardPeer{
		PrivateKey: testWireGuardPrivateKey(0x22),
		PublicKey:  mustDeriveTestWireGuardPublicKey(t, testWireGuardPrivateKey(0x22)),
		AllowedIPs: []string{"10.0.0.2/32"},
	}

	err := service.validateWireguardPeers([]wireguardPeer{peerA, peerB})
	if err == nil {
		t.Fatal("expected duplicate allowedIPs error, got nil")
	}
}

func TestSetVKTurnProxyClientEnableRestoresWireGuardPeer(t *testing.T) {
	setupVKTurnProxyClientDB(t)

	service := new(InboundService)
	wgPrivateKey := testWireGuardPrivateKey(0x33)
	clientPrivateKey := testWireGuardPrivateKey(0x44)
	clientPublicKey := mustDeriveTestWireGuardPublicKey(t, clientPrivateKey)
	allowedIPs := []string{"10.0.0.2/32"}

	wgInbound := &model.Inbound{
		Enable:         true,
		Remark:         "wg",
		Listen:         "0.0.0.0",
		Port:           51820,
		Protocol:       model.WireGuard,
		Tag:            "inbound-51820",
		Settings:       `{"secretKey":"` + wgPrivateKey + `","peers":[{"privateKey":"` + clientPrivateKey + `","publicKey":"` + clientPublicKey + `","allowedIPs":["10.0.0.2/32"]}]}`,
		StreamSettings: `{}`,
		Sniffing:       `{}`,
	}
	if err := database.GetDB().Create(wgInbound).Error; err != nil {
		t.Fatalf("create wireguard inbound: %v", err)
	}

	vkSettings := &VKTurnProxySettings{
		Forward: VKTurnProxyForward{
			Type:               VKTurnProxyForwardWireGuardInbound,
			WireGuardInboundID: wgInbound.Id,
		},
		Clients: []VKTurnProxyClient{
			{
				ID:            "client-1",
				Email:         "vk-client@example.com",
				Enable:        true,
				Link:          "https://vk.com/call/join/test",
				PeerManaged:   false,
				PeerPublicKey: clientPublicKey,
				Peer: &VKTurnProxyClientPeer{
					PrivateKey: clientPrivateKey,
					PublicKey:  clientPublicKey,
					AllowedIPs: allowedIPs,
				},
			},
		},
	}
	rawSettings, err := service.marshalVKTurnProxySettings(vkSettings)
	if err != nil {
		t.Fatalf("marshal vk-turn-proxy settings: %v", err)
	}

	vkInbound := &model.Inbound{
		Enable:         true,
		Remark:         "vk",
		Listen:         "0.0.0.0",
		Port:           56000,
		Protocol:       model.VKTurnProxy,
		Tag:            "inbound-56000",
		Settings:       rawSettings,
		StreamSettings: `{}`,
		Sniffing:       `{}`,
	}
	if err := database.GetDB().Create(vkInbound).Error; err != nil {
		t.Fatalf("create vk-turn-proxy inbound: %v", err)
	}

	if _, err := service.SetVKTurnProxyClientEnable(vkInbound.Id, "client-1", false); err != nil {
		t.Fatalf("disable vk-turn-proxy client: %v", err)
	}

	wgInboundAfterDisable, err := service.GetInbound(wgInbound.Id)
	if err != nil {
		t.Fatalf("reload wireguard inbound after disable: %v", err)
	}
	_, peersAfterDisable, err := service.getWireguardSettings(wgInboundAfterDisable.Settings)
	if err != nil {
		t.Fatalf("parse wireguard settings after disable: %v", err)
	}
	if len(peersAfterDisable) != 0 {
		t.Fatalf("expected peer to be removed on disable, got %d peers", len(peersAfterDisable))
	}

	_, vkSettingsAfterDisable, clientIndex, err := service.getVKTurnProxyClient(vkInbound.Id, "client-1")
	if err != nil {
		t.Fatalf("reload vk-turn-proxy client after disable: %v", err)
	}
	if vkSettingsAfterDisable.Clients[clientIndex].Enable {
		t.Fatal("expected vk-turn-proxy client to be disabled")
	}
	if vkSettingsAfterDisable.Clients[clientIndex].Peer == nil {
		t.Fatal("expected disabled vk-turn-proxy client to keep peer snapshot")
	}

	if _, err := service.SetVKTurnProxyClientEnable(vkInbound.Id, "client-1", true); err != nil {
		t.Fatalf("enable vk-turn-proxy client: %v", err)
	}

	wgInboundAfterEnable, err := service.GetInbound(wgInbound.Id)
	if err != nil {
		t.Fatalf("reload wireguard inbound after enable: %v", err)
	}
	_, peersAfterEnable, err := service.getWireguardSettings(wgInboundAfterEnable.Settings)
	if err != nil {
		t.Fatalf("parse wireguard settings after enable: %v", err)
	}
	if len(peersAfterEnable) != 1 {
		t.Fatalf("expected peer to be restored on enable, got %d peers", len(peersAfterEnable))
	}
	if peersAfterEnable[0].PublicKey != clientPublicKey {
		t.Fatalf("expected restored peer public key %s, got %s", clientPublicKey, peersAfterEnable[0].PublicKey)
	}
	if len(peersAfterEnable[0].AllowedIPs) != 1 || peersAfterEnable[0].AllowedIPs[0] != allowedIPs[0] {
		t.Fatalf("expected restored peer allowedIPs %v, got %v", allowedIPs, peersAfterEnable[0].AllowedIPs)
	}
}

func setupVKTurnProxyClientDB(t *testing.T) {
	t.Helper()

	_ = database.CloseDB()
	dbPath := filepath.Join(t.TempDir(), "x-ui-test.db")
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("init test database: %v", err)
	}
	t.Cleanup(func() {
		_ = database.CloseDB()
	})
}

func testWireGuardPrivateKey(fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func mustDeriveTestWireGuardPublicKey(t *testing.T, privateKey string) string {
	t.Helper()

	publicKey, err := deriveWireGuardPublicKey(privateKey)
	if err != nil {
		t.Fatalf("derive wireguard public key: %v", err)
	}
	return publicKey
}
