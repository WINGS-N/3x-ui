package service

import (
	"encoding/json"
	"maps"
	"net"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/util/common"
	"github.com/mhsanaei/3x-ui/v3/internal/util/random"
)

// wireguardPeer is the peer-shaped view of a WireGuard client. Since upstream
// v3.5 a WireGuard inbound stores its peers as settings.clients (the
// WireguardPeersToClients migration drops the legacy inline settings.peers), so
// this decodes from and encodes back into a client object.
type wireguardPeer struct {
	PrivateKey   string   `json:"privateKey"`
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey,omitempty"`
	AllowedIPs   []string `json:"allowedIPs"`
	KeepAlive    int      `json:"keepAlive,omitempty"`
	Email        string   `json:"email,omitempty"`

	// raw is the client object this peer was decoded from. Kept so writing back
	// preserves the client fields this peer view does not model (subId, tgId,
	// enable, limits, timestamps). Nil for a peer minted in code.
	raw map[string]any
}

// toClientObject renders the peer back into its client object, preserving any
// unmodelled fields carried in raw.
func (p wireguardPeer) toClientObject() map[string]any {
	obj := map[string]any{}
	maps.Copy(obj, p.raw)
	obj["privateKey"] = p.PrivateKey
	obj["publicKey"] = p.PublicKey
	if strings.TrimSpace(p.PreSharedKey) == "" {
		delete(obj, "preSharedKey")
	} else {
		obj["preSharedKey"] = p.PreSharedKey
	}
	obj["allowedIPs"] = p.AllowedIPs
	if p.KeepAlive == 0 {
		delete(obj, "keepAlive")
	} else {
		obj["keepAlive"] = p.KeepAlive
	}
	if strings.TrimSpace(p.Email) != "" {
		obj["email"] = p.Email
	}
	// A client row is keyed by email and must be enabled to reach the runtime;
	// a freshly minted peer carries neither.
	if _, ok := obj["enable"]; !ok {
		obj["enable"] = true
	}
	if sub, _ := obj["subId"].(string); strings.TrimSpace(sub) == "" {
		obj["subId"] = random.NumLower(16)
	}
	return obj
}

func normalizeClientTGIDInMap(client map[string]any) bool {
	tgIDRaw, ok := client["tgId"]
	if !ok {
		return false
	}

	switch value := tgIDRaw.(type) {
	case nil:
		client["tgId"] = int64(0)
		return true
	case string:
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			client["tgId"] = int64(0)
			return true
		}
		tgID, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil {
			client["tgId"] = int64(0)
			return true
		}
		client["tgId"] = tgID
		return true
	case json.Number:
		tgID, err := value.Int64()
		if err != nil {
			client["tgId"] = int64(0)
			return true
		}
		client["tgId"] = tgID
		return true
	default:
		return false
	}
}

func normalizeRawClientsTGID(rawClients json.RawMessage) (json.RawMessage, bool, error) {
	var clients []map[string]any
	if err := json.Unmarshal(rawClients, &clients); err != nil {
		return nil, false, err
	}

	changed := false
	for _, client := range clients {
		if normalizeClientTGIDInMap(client) {
			changed = true
		}
	}

	if !changed {
		return rawClients, false, nil
	}

	normalizedClients, err := json.Marshal(clients)
	if err != nil {
		return nil, false, err
	}
	return normalizedClients, true, nil
}

func (s *InboundService) AddInboundPeer(data *model.Inbound) (bool, error) {
	_, newPeers, err := s.getWireguardSettings(data.Settings)
	if err != nil {
		return false, err
	}
	if len(newPeers) == 0 {
		return false, common.NewError("wireguard peers is empty")
	}

	return s.mutateWireguardPeers(data.Id, func(peers []wireguardPeer) ([]wireguardPeer, error) {
		return append(peers, newPeers...), nil
	})
}

func (s *InboundService) UpdateInboundPeer(data *model.Inbound, peerIndex int) (bool, error) {
	_, newPeers, err := s.getWireguardSettings(data.Settings)
	if err != nil {
		return false, err
	}
	if len(newPeers) != 1 {
		return false, common.NewError("wireguard peer update expects exactly one peer")
	}

	return s.mutateWireguardPeers(data.Id, func(peers []wireguardPeer) ([]wireguardPeer, error) {
		if peerIndex < 0 || peerIndex >= len(peers) {
			return nil, common.NewError("wireguard peer index out of range:", peerIndex)
		}
		peers[peerIndex] = newPeers[0]
		return peers, nil
	})
}

func (s *InboundService) DelInboundPeer(inboundId int, peerIndex int) (bool, error) {
	return s.mutateWireguardPeers(inboundId, func(peers []wireguardPeer) ([]wireguardPeer, error) {
		if peerIndex < 0 || peerIndex >= len(peers) {
			return nil, common.NewError("wireguard peer index out of range:", peerIndex)
		}
		if len(peers) <= 1 {
			return nil, common.NewError("no wireguard peer remained in inbound")
		}
		return append(peers[:peerIndex], peers[peerIndex+1:]...), nil
	})
}

func (s *InboundService) mutateWireguardPeers(inboundId int, mutate func([]wireguardPeer) ([]wireguardPeer, error)) (bool, error) {
	oldInbound, err := s.GetInbound(inboundId)
	if err != nil {
		return false, err
	}
	if oldInbound.Protocol != model.WireGuard {
		return false, common.NewError("inbound is not wireguard")
	}

	settings, peers, err := s.getWireguardSettings(oldInbound.Settings)
	if err != nil {
		return false, err
	}

	updatedPeers, err := mutate(peers)
	if err != nil {
		return false, err
	}
	if err := s.validateWireguardPeers(updatedPeers); err != nil {
		return false, err
	}

	clientObjs := make([]any, 0, len(updatedPeers))
	for _, peer := range updatedPeers {
		clientObjs = append(clientObjs, peer.toClientObject())
	}
	settings["clients"] = clientObjs
	// Legacy inbounds that predate WireguardPeersToClients may still carry the
	// inline list; drop it so the two never diverge.
	delete(settings, "peers")
	newSettings, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return false, err
	}

	updatedInbound := *oldInbound
	updatedInbound.Settings = string(newSettings)

	_, needRestart, err := s.UpdateInbound(&updatedInbound)
	return needRestart, err
}

func (s *InboundService) getWireguardSettings(raw string) (map[string]any, []wireguardPeer, error) {
	settings := map[string]any{}
	if err := json.Unmarshal([]byte(raw), &settings); err != nil {
		return nil, nil, err
	}

	// Peers live in settings.clients since upstream v3.5; settings.peers is only
	// still read so an inbound that has not been through the migration yet (or a
	// payload posted in the legacy shape) keeps working.
	peerValue, ok := settings["clients"]
	if !ok {
		peerValue, ok = settings["peers"]
	}
	if !ok {
		return nil, nil, common.NewError("wireguard peers is empty")
	}

	rawObjs := make([]map[string]any, 0)
	peerBytes, err := json.Marshal(peerValue)
	if err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(peerBytes, &rawObjs); err != nil {
		return nil, nil, err
	}

	peers := make([]wireguardPeer, 0, len(rawObjs))
	for _, obj := range rawObjs {
		objBytes, err := json.Marshal(obj)
		if err != nil {
			return nil, nil, err
		}
		var peer wireguardPeer
		if err := json.Unmarshal(objBytes, &peer); err != nil {
			return nil, nil, err
		}
		peer.raw = obj
		peers = append(peers, peer)
	}
	return settings, peers, nil
}

func (s *InboundService) validateWireguardPeers(peers []wireguardPeer) error {
	seenPublicKeys := make(map[string]struct{}, len(peers))
	seenAllowedIPs := make(map[string]int)
	for i, peer := range peers {
		if strings.TrimSpace(peer.PrivateKey) == "" {
			return common.NewErrorf("wireguard peer #%d privateKey is empty", i+1)
		}
		publicKey := strings.TrimSpace(peer.PublicKey)
		if publicKey == "" {
			return common.NewErrorf("wireguard peer #%d publicKey is empty", i+1)
		}
		if len(peer.AllowedIPs) == 0 {
			return common.NewErrorf("wireguard peer #%d allowedIPs is empty", i+1)
		}
		if _, exists := seenPublicKeys[publicKey]; exists {
			return common.NewError("Duplicate wireguard publicKey:", publicKey)
		}
		seenPublicKeys[publicKey] = struct{}{}
		for _, rawAllowedIP := range peer.AllowedIPs {
			allowedIP, err := normalizeWireGuardAllowedIP(rawAllowedIP)
			if err != nil {
				return common.NewErrorf("wireguard peer #%d allowedIP %q is invalid: %v", i+1, rawAllowedIP, err)
			}
			if previousPeerIndex, exists := seenAllowedIPs[allowedIP]; exists {
				return common.NewErrorf(
					"duplicate wireguard allowedIP %s between peer #%d and peer #%d",
					allowedIP,
					previousPeerIndex,
					i+1,
				)
			}
			seenAllowedIPs[allowedIP] = i + 1
		}
	}
	return nil
}

func normalizeWireGuardAllowedIP(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", common.NewError("allowedIP is empty")
	}

	if !strings.Contains(value, "/") {
		ip := net.ParseIP(value)
		if ip == nil {
			return "", common.NewError("invalid IP")
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String() + "/32", nil
		}
		return ip.String() + "/128", nil
	}

	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return "", err
	}
	return network.String(), nil
}
