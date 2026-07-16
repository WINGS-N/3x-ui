package service

import (
	"errors"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

type vkTurnProxyTrafficBinding struct {
	inboundID int
	client    VKTurnProxyClient
}

func vkTurnProxyClientToModelClient(client *VKTurnProxyClient) model.Client {
	return model.Client{
		ID:         client.ID,
		Email:      client.Email,
		LimitIP:    client.LimitIP,
		TotalGB:    client.TotalGB,
		ExpiryTime: client.ExpiryTime,
		Enable:     client.Enable,
		TgID:       client.TgID,
		SubID:      client.SubID,
		Comment:    client.Comment,
		Reset:      client.Reset,
		CreatedAt:  client.CreatedAt,
		UpdatedAt:  client.UpdatedAt,
	}
}

func (s *InboundService) addVKTurnProxyClientTraffic(tx *gorm.DB, inboundID int, client *VKTurnProxyClient) error {
	modelClient := vkTurnProxyClientToModelClient(client)
	return s.AddClientStat(tx, inboundID, &modelClient)
}

func (s *InboundService) updateVKTurnProxyClientTraffic(tx *gorm.DB, oldEmail string, client *VKTurnProxyClient) error {
	modelClient := vkTurnProxyClientToModelClient(client)
	if err := s.UpdateClientStat(tx, oldEmail, &modelClient); err != nil {
		return err
	}
	if oldEmail != client.Email {
		if err := s.UpdateClientIPs(tx, oldEmail, client.Email); err != nil {
			return err
		}
	}
	return nil
}

func (s *InboundService) delVKTurnProxyClientTraffic(tx *gorm.DB, email string) error {
	if err := s.DelClientStat(tx, email); err != nil {
		return err
	}
	return s.DelClientIPs(tx, email)
}

func wireGuardPeerTrafficBindingKey(inboundID int, publicKey string) string {
	return strconv.Itoa(inboundID) + "\x00" + strings.TrimSpace(publicKey)
}

func clientTrafficMapToSlice(m map[string]*xray.ClientTraffic) []*xray.ClientTraffic {
	result := make([]*xray.ClientTraffic, 0, len(m))
	for _, traffic := range m {
		result = append(result, traffic)
	}
	return result
}

func (s *InboundService) syncVKTurnProxyClientTrafficRows(tx *gorm.DB, inbounds []*model.Inbound) (bool, error) {
	clientBindings := make(map[string]vkTurnProxyTrafficBinding)
	for _, inbound := range inbounds {
		if inbound == nil || inbound.Protocol != model.VKTurnProxy {
			continue
		}

		settings, err := s.getVKTurnProxySettings(inbound.Settings)
		if err != nil {
			logger.Warningf("skip vk-turn-proxy client traffic sync for inbound %d: %v", inbound.Id, err)
			continue
		}

		for _, client := range settings.Clients {
			email := strings.TrimSpace(client.Email)
			if email == "" {
				continue
			}
			clientBindings[strings.ToLower(email)] = vkTurnProxyTrafficBinding{
				inboundID: inbound.Id,
				client:    client,
			}
		}
	}

	if len(clientBindings) == 0 {
		return false, nil
	}

	emails := make([]string, 0, len(clientBindings))
	for _, binding := range clientBindings {
		emails = append(emails, binding.client.Email)
	}

	var rows []xray.ClientTraffic
	if err := tx.Where("email IN ?", emails).Find(&rows).Error; err != nil {
		return false, err
	}

	existingByEmail := make(map[string]xray.ClientTraffic, len(rows))
	for _, row := range rows {
		existingByEmail[strings.ToLower(row.Email)] = row
	}

	changed := false
	for emailKey, binding := range clientBindings {
		if row, ok := existingByEmail[emailKey]; ok {
			updates := map[string]any{}
			if row.InboundId != binding.inboundID {
				updates["inbound_id"] = binding.inboundID
			}
			if row.Enable != binding.client.Enable {
				updates["enable"] = binding.client.Enable
			}
			if row.Total != binding.client.TotalGB {
				updates["total"] = binding.client.TotalGB
			}
			if row.ExpiryTime != binding.client.ExpiryTime {
				updates["expiry_time"] = binding.client.ExpiryTime
			}
			if row.Reset != binding.client.Reset {
				updates["reset"] = binding.client.Reset
			}
			if len(updates) == 0 {
				continue
			}
			if err := tx.Model(&xray.ClientTraffic{}).Where("email = ?", binding.client.Email).Updates(updates).Error; err != nil {
				return changed, err
			}
			changed = true
			continue
		}

		if err := s.addVKTurnProxyClientTraffic(tx, binding.inboundID, &binding.client); err != nil {
			return changed, err
		}
		changed = true
	}

	return changed, nil
}

// BuildVKTurnProxyClientTraffics maps patched WireGuard peer stats to vk-turn-proxy clients
// so the panel can keep using the existing client_traffics table and UI.
func (s *InboundService) BuildVKTurnProxyClientTraffics(wireGuardPeerTraffics []*xray.WireGuardPeerTraffic) ([]*xray.ClientTraffic, error) {
	if len(wireGuardPeerTraffics) == 0 {
		return nil, nil
	}

	db := database.GetDB()
	var wireGuardInbounds []*model.Inbound
	if err := db.Select("id", "tag").Where("protocol = ?", model.WireGuard).Find(&wireGuardInbounds).Error; err != nil {
		return nil, err
	}
	if len(wireGuardInbounds) == 0 {
		return nil, nil
	}

	wgInboundIDByTag := make(map[string]int, len(wireGuardInbounds))
	relevantWGInboundIDs := make(map[int]struct{}, len(wireGuardInbounds))
	for _, inbound := range wireGuardInbounds {
		wgInboundIDByTag[inbound.Tag] = inbound.Id
	}
	for _, traffic := range wireGuardPeerTraffics {
		if inboundID, ok := wgInboundIDByTag[traffic.InboundTag]; ok {
			relevantWGInboundIDs[inboundID] = struct{}{}
		}
	}
	if len(relevantWGInboundIDs) == 0 {
		return nil, nil
	}

	var vkTurnProxyInbounds []*model.Inbound
	if err := db.Where("protocol = ?", model.VKTurnProxy).Find(&vkTurnProxyInbounds).Error; err != nil {
		return nil, err
	}
	if len(vkTurnProxyInbounds) == 0 {
		return nil, nil
	}

	clientByBinding := make(map[string]*xray.ClientTraffic)
	for _, inbound := range vkTurnProxyInbounds {
		settings, err := s.getVKTurnProxySettings(inbound.Settings)
		if err != nil {
			logger.Warningf("skip vk-turn-proxy traffic mapping for inbound %d: %v", inbound.Id, err)
			continue
		}
		if settings.Forward.Type != VKTurnProxyForwardWireGuardInbound {
			continue
		}
		if _, ok := relevantWGInboundIDs[settings.Forward.WireGuardInboundID]; !ok {
			continue
		}
		for _, client := range settings.Clients {
			if strings.TrimSpace(client.Email) == "" || strings.TrimSpace(client.PeerPublicKey) == "" {
				continue
			}
			clientByBinding[wireGuardPeerTrafficBindingKey(settings.Forward.WireGuardInboundID, client.PeerPublicKey)] = &xray.ClientTraffic{
				InboundId:  inbound.Id,
				Email:      client.Email,
				Enable:     client.Enable,
				ExpiryTime: client.ExpiryTime,
				Total:      client.TotalGB,
				Reset:      client.Reset,
				UUID:       client.ID,
				SubId:      client.SubID,
			}
		}
	}
	if len(clientByBinding) == 0 {
		return nil, nil
	}

	clientTrafficMap := make(map[string]*xray.ClientTraffic)
	for _, traffic := range wireGuardPeerTraffics {
		wgInboundID, ok := wgInboundIDByTag[traffic.InboundTag]
		if !ok {
			continue
		}

		boundClient, ok := clientByBinding[wireGuardPeerTrafficBindingKey(wgInboundID, traffic.PublicKey)]
		if !ok {
			continue
		}

		clientTraffic, ok := clientTrafficMap[boundClient.Email]
		if !ok {
			clientTraffic = &xray.ClientTraffic{
				InboundId: boundClient.InboundId,
				Email:     boundClient.Email,
			}
			clientTrafficMap[boundClient.Email] = clientTraffic
		}
		clientTraffic.Up += traffic.Up
		clientTraffic.Down += traffic.Down
	}

	return clientTrafficMapToSlice(clientTrafficMap), nil
}

// BuildVKTurnProxyInboundTraffics turns the per-client vk-turn-proxy traffic
// deltas (already derived from the forwarded wireguard peer stats) into
// per-inbound xray.Traffic rows so addInboundTraffic bumps each vk-turn-proxy
// inbound's up/down total. The relay runs outside xray's stats API, so its
// inbound tag never appears in GetXrayTraffic and the inbound total otherwise
// stays 0. Each vk-turn-proxy inbound forwards into a wireguard inbound whose
// traffic xray DOES track per peer; summing this inbound's own client deltas is
// exactly the relay traffic attributable to it. This only writes the
// vk-turn-proxy inbound's own row (a distinct tag) and never the wireguard
// inbound's, so the wireguard inbound's accounting is untouched and nothing is
// double counted. Approximation: control-plane/overhead bytes the relay moves
// that never reach a managed peer are not counted, since the relay does not
// report them.
func (s *InboundService) BuildVKTurnProxyInboundTraffics(clientTraffics []*xray.ClientTraffic) ([]*xray.Traffic, error) {
	if len(clientTraffics) == 0 {
		return nil, nil
	}

	upByInbound := make(map[int]int64)
	downByInbound := make(map[int]int64)
	for _, ct := range clientTraffics {
		if ct == nil || (ct.Up == 0 && ct.Down == 0) {
			continue
		}
		upByInbound[ct.InboundId] += ct.Up
		downByInbound[ct.InboundId] += ct.Down
	}
	if len(upByInbound) == 0 && len(downByInbound) == 0 {
		return nil, nil
	}

	inboundIDs := make([]int, 0, len(upByInbound))
	for id := range upByInbound {
		inboundIDs = append(inboundIDs, id)
	}
	for id := range downByInbound {
		if _, ok := upByInbound[id]; !ok {
			inboundIDs = append(inboundIDs, id)
		}
	}

	db := database.GetDB()
	var inbounds []*model.Inbound
	if err := db.Select("id", "tag").
		Where("id IN ? AND protocol = ?", inboundIDs, model.VKTurnProxy).
		Find(&inbounds).Error; err != nil {
		return nil, err
	}

	traffics := make([]*xray.Traffic, 0, len(inbounds))
	for _, inbound := range inbounds {
		tag := strings.TrimSpace(inbound.Tag)
		if tag == "" {
			continue
		}
		traffics = append(traffics, &xray.Traffic{
			IsInbound: true,
			Tag:       tag,
			Up:        upByInbound[inbound.Id],
			Down:      downByInbound[inbound.Id],
		})
	}
	return traffics, nil
}

func (s *InboundService) MigrationBackfillVKTurnProxyClientTraffics() {
	db := database.GetDB()
	var inbounds []*model.Inbound
	if err := db.Where("protocol = ?", model.VKTurnProxy).Find(&inbounds).Error; err != nil {
		logger.Warningf("vk-turn-proxy traffic backfill query failed: %v", err)
		return
	}

	for _, inbound := range inbounds {
		settings, err := s.getVKTurnProxySettings(inbound.Settings)
		if err != nil {
			logger.Warningf("skip vk-turn-proxy traffic backfill for inbound %d: %v", inbound.Id, err)
			continue
		}

		for _, client := range settings.Clients {
			if strings.TrimSpace(client.Email) == "" {
				continue
			}

			modelClient := vkTurnProxyClientToModelClient(&client)
			var traffic xray.ClientTraffic
			err := db.Where("email = ?", modelClient.Email).First(&traffic).Error
			switch {
			case err == nil:
				err = db.Model(&traffic).Updates(map[string]any{
					"inbound_id":  inbound.Id,
					"enable":      modelClient.Enable,
					"total":       modelClient.TotalGB,
					"expiry_time": modelClient.ExpiryTime,
					"reset":       modelClient.Reset,
				}).Error
			case errors.Is(err, gorm.ErrRecordNotFound):
				traffic = xray.ClientTraffic{
					InboundId:  inbound.Id,
					Email:      modelClient.Email,
					Enable:     modelClient.Enable,
					Up:         0,
					Down:       0,
					ExpiryTime: modelClient.ExpiryTime,
					Total:      modelClient.TotalGB,
					Reset:      modelClient.Reset,
				}
				err = db.Create(&traffic).Error
			}
			if err != nil {
				logger.Warningf("vk-turn-proxy traffic backfill failed for client %s: %v", modelClient.Email, err)
			}
		}
	}
}
