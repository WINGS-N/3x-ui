package service

import (
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
)

// cleanupVKTurnProxyInboundPeers pulls every managed client peer of a
// vk-turn-proxy inbound from its target wireguard inbound when the inbound is
// deleted, so the freed 10.0.0.X addresses become available again. Best
// effort: failures are logged, never block the delete.
func (s *InboundService) cleanupVKTurnProxyInboundPeers(inbound *model.Inbound) {
	settings, err := s.getVKTurnProxySettings(inbound.Settings)
	if err != nil {
		return
	}
	if settings.Forward.Type != VKTurnProxyForwardWireGuardInbound || settings.Forward.WireGuardInboundID <= 0 {
		return
	}
	for i := range settings.Clients {
		publicKey := strings.TrimSpace(resolveVKTurnProxyClientPublicKey(&settings.Clients[i]))
		if publicKey == "" {
			continue
		}
		if _, rErr := s.removeWireguardPeerByPublicKey(settings.Forward.WireGuardInboundID, publicKey); rErr != nil {
			logger.Warning("vk-turn-proxy: cleanup peer on inbound delete failed:", rErr)
		}
	}
}

// applyVKTurnProxyInboundOnSave validates a vk-turn-proxy inbound's settings
// and, when it forwards into a wireguard inbound, reconciles the per-client
// managed peers: it mints a fresh keypair plus a unique 10.0.0.X address for
// any client missing peer info, upserts or pulls each client's peer in the
// target wireguard inbound based on its enable flag, and pulls peers for
// clients that were removed since the previous save. inbound.Settings is
// rewritten with the normalized result. oldInbound may be nil (fresh add).
func (s *InboundService) applyVKTurnProxyInboundOnSave(oldInbound, inbound *model.Inbound) (bool, error) {
	settings, err := s.getVKTurnProxySettings(inbound.Settings)
	if err != nil {
		return false, err
	}
	isWG := settings.Forward.Type == VKTurnProxyForwardWireGuardInbound
	if err := s.validateVKTurnProxySettings(settings, isWG); err != nil {
		return false, err
	}

	needRestart := false
	if isWG && settings.Forward.WireGuardInboundID > 0 {
		previous := map[string]VKTurnProxyClient{}
		if oldInbound != nil && oldInbound.Protocol == model.VKTurnProxy {
			if oldSettings, oErr := s.getVKTurnProxySettings(oldInbound.Settings); oErr == nil {
				for _, c := range oldSettings.Clients {
					previous[c.ID] = c
				}
			}
		}

		allocator, aErr := s.newVKTurnProxyPeerAllocator(settings)
		if aErr != nil {
			return false, aErr
		}

		newIDs := make(map[string]struct{}, len(settings.Clients))
		for i := range settings.Clients {
			s.normalizeVKTurnProxyClient(&settings.Clients[i], true)
			if pErr := s.autoProvisionVKTurnProxyManagedPeer(&settings.Clients[i], allocator); pErr != nil {
				return needRestart, pErr
			}
			var prev *VKTurnProxyClient
			if p, ok := previous[settings.Clients[i].ID]; ok {
				clone := p
				prev = &clone
			}
			restart, bErr := s.applyVKTurnProxyClientBinding(settings, &settings.Clients[i], prev)
			if bErr != nil {
				return needRestart, bErr
			}
			needRestart = needRestart || restart
			newIDs[settings.Clients[i].ID] = struct{}{}
		}

		// Clients deleted since the previous save: pull their peer from the
		// target wireguard inbound so the freed 10.0.0.X address can be reused.
		for id := range previous {
			if _, kept := newIDs[id]; kept {
				continue
			}
			removed := previous[id]
			publicKey := strings.TrimSpace(resolveVKTurnProxyClientPublicKey(&removed))
			if publicKey == "" {
				continue
			}
			restart, rErr := s.removeWireguardPeerByPublicKey(settings.Forward.WireGuardInboundID, publicKey)
			if rErr != nil {
				return needRestart, rErr
			}
			needRestart = needRestart || restart
		}
	}

	rawSettings, err := s.marshalVKTurnProxySettings(settings)
	if err != nil {
		return needRestart, err
	}
	inbound.Settings = rawSettings
	return needRestart, nil
}
