package service

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/util/crypto"
)

// panelApiTokenName is the fixed name of the API token row `grpc-connect`
// manages, so repeated runs replace it rather than accumulating tokens.
const panelApiTokenName = "wings-panel"

// GRPCConnect wires this 3x-ui to a wingsv panel from the CLI: it enables the
// management gRPC (persisted setting), registers the panel's bearer token, and
// points every vk-turn-proxy inbound at the panel for DTLS provisioning. It only
// touches the database - the caller restarts the panel so the listener comes up.
func GRPCConnect(panelGrpc, token, nodeID, grpcListen string) error {
	panelGrpc = strings.TrimSpace(panelGrpc)
	token = strings.TrimSpace(token)
	nodeID = strings.TrimSpace(nodeID)
	if panelGrpc == "" || token == "" || nodeID == "" {
		return fmt.Errorf("panel-grpc, token and node-id are required")
	}
	grpcListen = strings.TrimSpace(grpcListen)
	if grpcListen == "" {
		grpcListen = "0.0.0.0:25613"
	}

	setting := SettingService{}
	if err := setting.SetGRPCListen(grpcListen); err != nil {
		return fmt.Errorf("set grpc listen: %w", err)
	}

	db := database.GetDB()
	// Upsert the panel bearer token (stored as a SHA-256 hash).
	if err := db.Where("name = ?", panelApiTokenName).Delete(&model.ApiToken{}).Error; err != nil {
		return fmt.Errorf("clear old token: %w", err)
	}
	if err := db.Create(&model.ApiToken{
		Name:    panelApiTokenName,
		Token:   crypto.HashTokenSHA256(token),
		Enabled: true,
	}).Error; err != nil {
		return fmt.Errorf("register token: %w", err)
	}

	// Point every vk-turn-proxy inbound at the panel for DTLS provisioning.
	var inbounds []*model.Inbound
	if err := db.Model(&model.Inbound{}).Where("protocol = ?", model.VKTurnProxy).Find(&inbounds).Error; err != nil {
		return fmt.Errorf("load vk-turn inbounds: %w", err)
	}
	updated := 0
	for _, ib := range inbounds {
		settings := map[string]any{}
		if strings.TrimSpace(ib.Settings) != "" {
			if err := json.Unmarshal([]byte(ib.Settings), &settings); err != nil {
				continue
			}
		}
		settings["panelGrpc"] = panelGrpc
		settings["nodeId"] = nodeID
		out, err := json.Marshal(settings)
		if err != nil {
			continue
		}
		if err := db.Model(&model.Inbound{}).Where("id = ?", ib.Id).Update("settings", string(out)).Error; err != nil {
			return fmt.Errorf("update inbound %d: %w", ib.Id, err)
		}
		updated++
	}

	fmt.Printf("grpc-connect: management gRPC on %s, token registered, %d vk-turn inbound(s) pointed at panel %s (node %s)\n",
		grpcListen, updated, panelGrpc, nodeID)
	return nil
}
