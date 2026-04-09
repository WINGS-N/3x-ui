package service

import (
	"crypto/sha256"
	"encoding/base64"
	"sort"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/vkturnproxy"
)

const vkTurnProxyHeartbeatOnlineGrace = 150 * time.Second

func (s *VKTurnProxyService) HeartbeatStatesByInbound() map[int]map[string]vkturnproxy.HeartbeatState {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.processes) == 0 {
		return nil
	}

	snapshot := make(map[int]map[string]vkturnproxy.HeartbeatState, len(s.processes))
	for inboundID, proc := range s.processes {
		if proc == nil {
			continue
		}
		beats := proc.HeartbeatSnapshot()
		if len(beats) == 0 {
			continue
		}
		snapshot[inboundID] = beats
	}
	return snapshot
}

func wireGuardPublicKeyFingerprint(publicKey string) (string, error) {
	decoded, err := decodeWireGuardKey(publicKey)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(decoded)
	return "sha256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

func mergeOnlineClientLists(base []string, extra map[string]struct{}) []string {
	if len(extra) == 0 {
		return append([]string(nil), base...)
	}

	result := make([]string, 0, len(base)+len(extra))
	seen := make(map[string]struct{}, len(base)+len(extra))
	for _, email := range base {
		trimmed := strings.TrimSpace(email)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, trimmed)
	}

	appended := make([]string, 0, len(extra))
	for email := range extra {
		trimmed := strings.TrimSpace(email)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		appended = append(appended, trimmed)
	}
	sort.Strings(appended)

	return append(result, appended...)
}

func (s *InboundService) getVKTurnProxyHeartbeatPresence(now time.Time) (map[string]struct{}, map[string]int64, error) {
	snapshot := VKTurnProxyRuntime().HeartbeatStatesByInbound()
	if len(snapshot) == 0 {
		return nil, nil, nil
	}

	inboundIDs := make([]int, 0, len(snapshot))
	for inboundID := range snapshot {
		inboundIDs = append(inboundIDs, inboundID)
	}

	db := database.GetDB()
	var inbounds []*model.Inbound
	if err := db.Where("protocol = ? AND id IN ?", model.VKTurnProxy, inboundIDs).Find(&inbounds).Error; err != nil {
		return nil, nil, err
	}

	onlineEmails, lastOnlineByEmail := s.buildVKTurnProxyHeartbeatPresence(inbounds, snapshot, now)
	return onlineEmails, lastOnlineByEmail, nil
}

func (s *InboundService) buildVKTurnProxyHeartbeatPresence(
	inbounds []*model.Inbound,
	snapshot map[int]map[string]vkturnproxy.HeartbeatState,
	now time.Time,
) (map[string]struct{}, map[string]int64) {
	onlineEmails := make(map[string]struct{})
	lastOnlineByEmail := make(map[string]int64)

	for _, inbound := range inbounds {
		if inbound == nil {
			continue
		}

		beats := snapshot[inbound.Id]
		if len(beats) == 0 {
			continue
		}

		settings, err := s.getVKTurnProxySettings(inbound.Settings)
		if err != nil {
			logger.Warningf("skip vk-turn-proxy heartbeat mapping for inbound %d: %v", inbound.Id, err)
			continue
		}

		for _, client := range settings.Clients {
			email := strings.TrimSpace(client.Email)
			if email == "" || strings.TrimSpace(client.PeerPublicKey) == "" {
				continue
			}

			fingerprint, err := wireGuardPublicKeyFingerprint(client.PeerPublicKey)
			if err != nil {
				logger.Warningf("skip vk-turn-proxy heartbeat fingerprint for client %s: %v", client.Email, err)
				continue
			}

			state, ok := beats[fingerprint]
			if !ok || state.LastSeen.IsZero() || !state.Online {
				continue
			}

			isActive := state.Active > 0
			if isActive {
				lastSeen := state.LastSeen.UnixMilli()
				if lastSeen > lastOnlineByEmail[email] {
					lastOnlineByEmail[email] = lastSeen
				}
			}

			if client.Enable && isActive && now.Sub(state.LastSeen) <= vkTurnProxyHeartbeatOnlineGrace {
				onlineEmails[email] = struct{}{}
			}
		}
	}

	if len(onlineEmails) == 0 {
		onlineEmails = nil
	}
	if len(lastOnlineByEmail) == 0 {
		lastOnlineByEmail = nil
	}
	return onlineEmails, lastOnlineByEmail
}
