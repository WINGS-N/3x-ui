package service

import (
	"fmt"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/util/common"
)

// FixedAllowedIPConflict describes one peer whose duplicate 10.0.0.X/32
// pool address was reassigned to a fresh, unique one. Client is the
// vk-turn-proxy client email bound to that peer, empty when none matches.
type FixedAllowedIPConflict struct {
	PublicKey string `json:"publicKey"`
	OldIP     string `json:"oldIp"`
	NewIP     string `json:"newIp"`
	Client    string `json:"client"`
}

// WireguardAllowedIPConflicts returns a human-readable list of the current
// duplicate-allowedIP conflicts in the wireguard inbound, so the frontend
// can decide whether to surface the "Fix conflicting" action. An empty
// slice means the inbound is clean.
func (s *InboundService) WireguardAllowedIPConflicts(inboundID int) ([]string, error) {
	inbound, err := s.GetInbound(inboundID)
	if err != nil {
		return nil, err
	}
	if inbound.Protocol != model.WireGuard {
		return nil, common.NewError("inbound is not wireguard")
	}
	_, peers, err := s.getWireguardSettings(inbound.Settings)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]int)
	conflicts := make([]string, 0)
	for i, peer := range peers {
		for _, rawAllowedIP := range peer.AllowedIPs {
			allowedIP, err := normalizeWireGuardAllowedIP(rawAllowedIP)
			if err != nil {
				continue
			}
			if previous, exists := seen[allowedIP]; exists {
				conflicts = append(conflicts, fmt.Sprintf(
					"duplicate wireguard allowedIP %s between peer #%d and peer #%d",
					allowedIP, previous, i+1,
				))
				continue
			}
			seen[allowedIP] = i + 1
		}
	}
	return conflicts, nil
}

// FixWireguardAllowedIPConflicts walks the wireguard inbound's peers and
// reassigns every duplicate 10.0.0.X/32 pool address to a fresh unique one.
// The first peer that claims a given octet keeps it; any later peer holding
// an already-claimed octet is reassigned to the next free 2..254 slot,
// avoiding every octet currently in use across all peers. Non-pool
// AllowedIPs (e.g. 0.0.0.0/0) are left untouched. Each reassigned peer that
// is bound to a vk-turn-proxy client also has that client's stored peer
// snapshot updated so the next vk-turn save does not re-upsert the old IP.
func (s *InboundService) FixWireguardAllowedIPConflicts(inboundID int) ([]FixedAllowedIPConflict, error) {
	inbound, err := s.GetInbound(inboundID)
	if err != nil {
		return nil, err
	}
	if inbound.Protocol != model.WireGuard {
		return nil, common.NewError("inbound is not wireguard")
	}
	_, peers, err := s.getWireguardSettings(inbound.Settings)
	if err != nil {
		return nil, err
	}

	// Reserve every pool octet currently in use so reassignments never
	// collide with a kept peer's address or with each other.
	used := make(map[byte]struct{})
	for _, peer := range peers {
		for _, addr := range peer.AllowedIPs {
			if octet, ok := extractVKTurnAllocOctet(addr); ok {
				used[octet] = struct{}{}
			}
		}
	}

	// reassignments maps a peer public key to the new pool address it
	// should carry, keyed alongside the old address it replaces.
	type reassignment struct {
		publicKey string
		oldIP     string
		newIP     string
	}
	var reassignments []reassignment
	claimed := make(map[byte]int)
	next := byte(2)
	allocate := func() (string, error) {
		for octet := next; octet <= 254; octet++ {
			if _, taken := used[octet]; taken {
				continue
			}
			used[octet] = struct{}{}
			next = octet + 1
			return fmt.Sprintf("10.0.0.%d/32", octet), nil
		}
		return "", common.NewError("vk-turn-proxy: no free 10.0.0.X/32 slot left to resolve allowedIP conflicts")
	}

	for i := range peers {
		for j, addr := range peers[i].AllowedIPs {
			octet, ok := extractVKTurnAllocOctet(addr)
			if !ok {
				continue
			}
			if _, exists := claimed[octet]; !exists {
				claimed[octet] = i
				continue
			}
			newIP, allocErr := allocate()
			if allocErr != nil {
				return nil, allocErr
			}
			if newOctet, ok := extractVKTurnAllocOctet(newIP); ok {
				claimed[newOctet] = i
			}
			reassignments = append(reassignments, reassignment{
				publicKey: strings.TrimSpace(peers[i].PublicKey),
				oldIP:     strings.TrimSpace(addr),
				newIP:     newIP,
			})
			peers[i].AllowedIPs[j] = newIP
		}
	}

	if len(reassignments) == 0 {
		return []FixedAllowedIPConflict{}, nil
	}

	if _, err := s.mutateWireguardPeers(inboundID, func(current []wireguardPeer) ([]wireguardPeer, error) {
		for _, r := range reassignments {
			index := s.findWireguardPeerIndexByPublicKey(current, r.publicKey)
			if index < 0 {
				continue
			}
			for j, addr := range current[index].AllowedIPs {
				if strings.TrimSpace(addr) == r.oldIP {
					current[index].AllowedIPs[j] = r.newIP
					break
				}
			}
		}
		return current, nil
	}); err != nil {
		return nil, err
	}

	fixed := make([]FixedAllowedIPConflict, 0, len(reassignments))
	for _, r := range reassignments {
		client, err := s.syncVKTurnProxyClientAllowedIP(inboundID, r.publicKey, r.oldIP, r.newIP)
		if err != nil {
			return nil, err
		}
		fixed = append(fixed, FixedAllowedIPConflict{
			PublicKey: r.publicKey,
			OldIP:     r.oldIP,
			NewIP:     r.newIP,
			Client:    client,
		})
	}
	return fixed, nil
}

// syncVKTurnProxyClientAllowedIP finds the vk-turn-proxy client (across all
// vk-turn inbounds forwarding into wgInboundID) bound to publicKey and
// rewrites its stored peer's pool AllowedIPs entry from oldIP to newIP,
// persisting that vk-turn inbound. Returns the matched client's email, or
// an empty string when no client maps to the peer.
func (s *InboundService) syncVKTurnProxyClientAllowedIP(wgInboundID int, publicKey, oldIP, newIP string) (string, error) {
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" {
		return "", nil
	}

	db := database.GetDB()
	var inbounds []*model.Inbound
	if err := db.Where("protocol = ?", model.VKTurnProxy).Find(&inbounds).Error; err != nil {
		return "", err
	}

	for _, inbound := range inbounds {
		settings, err := s.getVKTurnProxySettings(inbound.Settings)
		if err != nil {
			continue
		}
		if settings.Forward.Type != VKTurnProxyForwardWireGuardInbound || settings.Forward.WireGuardInboundID != wgInboundID {
			continue
		}
		changed := false
		email := ""
		for i := range settings.Clients {
			client := &settings.Clients[i]
			if resolveVKTurnProxyClientPublicKey(client) != publicKey {
				continue
			}
			email = client.Email
			if client.Peer == nil {
				continue
			}
			for j, addr := range client.Peer.AllowedIPs {
				if strings.TrimSpace(addr) == oldIP {
					client.Peer.AllowedIPs[j] = newIP
					changed = true
					break
				}
			}
		}
		if !changed {
			if email != "" {
				return email, nil
			}
			continue
		}

		rawSettings, err := s.marshalVKTurnProxySettings(settings)
		if err != nil {
			return "", err
		}
		inbound.Settings = rawSettings
		if err := db.Save(inbound).Error; err != nil {
			return "", err
		}
		return email, nil
	}
	return "", nil
}
