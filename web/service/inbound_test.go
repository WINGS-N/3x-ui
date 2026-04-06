package service

import (
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func TestGetClientsNormalizesStringTgID(t *testing.T) {
	inbound := &model.Inbound{
		Settings: `{
			"clients": [
				{
					"id": "client-1",
					"email": "user1@example.com",
					"enable": true,
					"tgId": "12345"
				},
				{
					"id": "client-2",
					"email": "user2@example.com",
					"enable": true,
					"tgId": ""
				}
			]
		}`,
	}

	clients, err := new(InboundService).GetClients(inbound)
	if err != nil {
		t.Fatalf("GetClients returned error: %v", err)
	}
	if len(clients) != 2 {
		t.Fatalf("expected 2 clients, got %d", len(clients))
	}
	if clients[0].TgID != 12345 {
		t.Fatalf("expected first tgId to be 12345, got %d", clients[0].TgID)
	}
	if clients[1].TgID != 0 {
		t.Fatalf("expected empty tgId to normalize to 0, got %d", clients[1].TgID)
	}
}
