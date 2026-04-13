package service

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/common"
	wingsvproto "github.com/mhsanaei/3x-ui/v2/wingsv/proto"
	"github.com/mhsanaei/3x-ui/v2/xray"
	"gorm.io/gorm"
)

func sanitizeIPv4Host(raw string) string {
	host := strings.TrimSpace(strings.Trim(raw, "[]"))
	if host == "" {
		return ""
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}

	ip = ip.To4()
	if ip == nil || ip.IsUnspecified() {
		return ""
	}
	return ip.String()
}

func extractRawHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}

	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}

	return strings.Trim(host, "[]")
}

func getPrimaryServerIPv4(includePrivate bool) string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	privateIPv4 := ""
	for _, iface := range interfaces {
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP == nil || ipNet.IP.IsLoopback() {
				continue
			}

			ip := ipNet.IP.To4()
			if ip == nil || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
				continue
			}

			ipv4 := ip.String()
			if !ip.IsPrivate() {
				return ipv4
			}
			if includePrivate && privateIPv4 == "" {
				privateIPv4 = ipv4
			}
		}
	}

	return privateIPv4
}

func getPublicServerIPv4() string {
	ip := strings.TrimSpace(getPublicIP("https://api4.ipify.org"))
	return sanitizeIPv4Host(ip)
}

func resolveVKTurnProxyExportIPv4(inbound *model.Inbound, requestHost string) string {
	if host := sanitizeIPv4Host(strings.TrimSpace(inbound.Listen)); host != "" {
		return host
	}

	if host := sanitizeIPv4Host(extractRawHost(requestHost)); host != "" {
		return host
	}

	if host := getPrimaryServerIPv4(false); host != "" {
		return host
	}

	if host := getPublicServerIPv4(); host != "" {
		return host
	}

	return getPrimaryServerIPv4(true)
}

func (s *InboundService) getVKTurnProxyClientEnvelope(raw string) ([]VKTurnProxyClient, error) {
	payload := struct {
		Clients []VKTurnProxyClient `json:"clients"`
	}{}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, err
	}
	return payload.Clients, nil
}

func (s *InboundService) findVKTurnProxyClientIndex(clients []VKTurnProxyClient, clientID string) int {
	for i, client := range clients {
		if client.ID == clientID {
			return i
		}
	}
	return -1
}

func (s *InboundService) findWireguardPeerIndexByPublicKey(peers []wireguardPeer, publicKey string) int {
	publicKey = strings.TrimSpace(publicKey)
	for i, peer := range peers {
		if strings.TrimSpace(peer.PublicKey) == publicKey {
			return i
		}
	}
	return -1
}

func resolveVKTurnProxyClientPublicKey(client *VKTurnProxyClient) string {
	if client == nil {
		return ""
	}
	if client.Peer != nil && strings.TrimSpace(client.Peer.PublicKey) != "" {
		return strings.TrimSpace(client.Peer.PublicKey)
	}
	return strings.TrimSpace(client.PeerPublicKey)
}

func cloneWireguardPeerToVKTurnProxyClientPeer(peer *wireguardPeer) *VKTurnProxyClientPeer {
	if peer == nil {
		return nil
	}
	allowedIPs := make([]string, len(peer.AllowedIPs))
	copy(allowedIPs, peer.AllowedIPs)
	return &VKTurnProxyClientPeer{
		PrivateKey:   strings.TrimSpace(peer.PrivateKey),
		PublicKey:    strings.TrimSpace(peer.PublicKey),
		PreSharedKey: strings.TrimSpace(peer.PreSharedKey),
		AllowedIPs:   allowedIPs,
		KeepAlive:    peer.KeepAlive,
	}
}

func vkTurnProxyClientPeerToWireguardPeer(peer *VKTurnProxyClientPeer) wireguardPeer {
	allowedIPs := make([]string, len(peer.AllowedIPs))
	copy(allowedIPs, peer.AllowedIPs)
	return wireguardPeer{
		PrivateKey:   strings.TrimSpace(peer.PrivateKey),
		PublicKey:    strings.TrimSpace(peer.PublicKey),
		PreSharedKey: strings.TrimSpace(peer.PreSharedKey),
		AllowedIPs:   allowedIPs,
		KeepAlive:    peer.KeepAlive,
	}
}

func (s *InboundService) getVKTurnProxyPeerBindings(wgInboundID int) (map[string]VKTurnProxyPeerBinding, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	if err := db.Where("protocol = ?", model.VKTurnProxy).Find(&inbounds).Error; err != nil {
		return nil, err
	}

	bindings := make(map[string]VKTurnProxyPeerBinding)
	for _, inbound := range inbounds {
		settings, err := s.getVKTurnProxySettings(inbound.Settings)
		if err != nil {
			continue
		}
		if settings.Forward.Type != VKTurnProxyForwardWireGuardInbound || settings.Forward.WireGuardInboundID != wgInboundID {
			continue
		}
		for _, client := range settings.Clients {
			publicKey := strings.TrimSpace(client.PeerPublicKey)
			if publicKey == "" {
				continue
			}
			bindings[publicKey] = VKTurnProxyPeerBinding{
				InboundID:     inbound.Id,
				InboundRemark: inbound.Remark,
				ClientID:      client.ID,
				ClientEmail:   client.Email,
			}
		}
	}
	return bindings, nil
}

func (s *InboundService) ensureVKTurnProxyBindingAvailable(wgInboundID int, publicKey string, currentClientID string) error {
	bindings, err := s.getVKTurnProxyPeerBindings(wgInboundID)
	if err != nil {
		return err
	}
	if binding, ok := bindings[strings.TrimSpace(publicKey)]; ok && binding.ClientID != currentClientID {
		return common.NewErrorf("wireguard peer %s is already bound to client %s", publicKey, binding.ClientEmail)
	}
	return nil
}

func (s *InboundService) validateVKTurnProxyClient(client *VKTurnProxyClient) error {
	if strings.TrimSpace(client.ID) == "" {
		return common.NewError("vk-turn-proxy client id is empty")
	}
	if strings.TrimSpace(client.Email) == "" {
		return common.NewError("vk-turn-proxy client email is empty")
	}
	if strings.TrimSpace(client.Link) == "" {
		return common.NewError("vk-turn-proxy client link is empty")
	}
	if client.PeerManaged {
		if client.Peer == nil {
			return common.NewError("managed wireguard peer is empty")
		}
		if strings.TrimSpace(client.Peer.PrivateKey) == "" {
			return common.NewError("managed wireguard peer privateKey is empty")
		}
		derivedPublicKey, err := deriveWireGuardPublicKey(client.Peer.PrivateKey)
		if err != nil {
			return err
		}
		client.Peer.PublicKey = derivedPublicKey
		if len(client.Peer.AllowedIPs) == 0 {
			return common.NewError("managed wireguard peer allowedIPs is empty")
		}
		client.PeerPublicKey = client.Peer.PublicKey
		return nil
	}

	if strings.TrimSpace(client.PeerPublicKey) == "" && client.Peer != nil {
		client.PeerPublicKey = client.Peer.PublicKey
	}
	if strings.TrimSpace(client.PeerPublicKey) == "" {
		return common.NewError("wireguard peer binding is required")
	}
	return nil
}

func (s *InboundService) snapshotVKTurnProxyClientPeer(wgInboundID int, client *VKTurnProxyClient) {
	publicKey := resolveVKTurnProxyClientPublicKey(client)
	if publicKey == "" {
		return
	}
	peer, _, err := s.getWireguardPeerByPublicKey(wgInboundID, publicKey)
	if err != nil {
		return
	}
	client.Peer = cloneWireguardPeerToVKTurnProxyClientPeer(peer)
	client.PeerPublicKey = strings.TrimSpace(peer.PublicKey)
}

func (s *InboundService) ensureVKTurnProxyClientPeerEnabled(wgInboundID int, client *VKTurnProxyClient) (bool, error) {
	publicKey := resolveVKTurnProxyClientPublicKey(client)
	if publicKey == "" {
		return false, common.NewError("wireguard peer binding is required")
	}
	if err := s.ensureVKTurnProxyBindingAvailable(wgInboundID, publicKey, client.ID); err != nil {
		return false, err
	}

	if client.PeerManaged {
		if client.Peer == nil {
			return false, common.NewError("managed wireguard peer is empty")
		}
		peer := vkTurnProxyClientPeerToWireguardPeer(client.Peer)
		restart, err := s.upsertWireguardPeerByPublicKey(wgInboundID, peer)
		if err != nil {
			return restart, err
		}
		client.PeerPublicKey = peer.PublicKey
		return restart, nil
	}

	if client.Peer != nil && strings.TrimSpace(client.Peer.PublicKey) != "" {
		peer := vkTurnProxyClientPeerToWireguardPeer(client.Peer)
		restart, err := s.upsertWireguardPeerByPublicKey(wgInboundID, peer)
		if err != nil {
			return restart, err
		}
		client.PeerPublicKey = peer.PublicKey
		return restart, nil
	}

	if _, _, err := s.getWireguardPeerByPublicKey(wgInboundID, publicKey); err != nil {
		return false, common.NewError("wireguard peer is missing and no stored snapshot is available:", publicKey)
	}
	client.PeerPublicKey = publicKey
	return false, nil
}

func (s *InboundService) ensureVKTurnProxyClientPeerDisabled(wgInboundID int, client *VKTurnProxyClient) (bool, error) {
	publicKey := resolveVKTurnProxyClientPublicKey(client)
	if publicKey == "" {
		return false, nil
	}
	s.snapshotVKTurnProxyClientPeer(wgInboundID, client)
	client.PeerPublicKey = publicKey
	if client.Peer == nil {
		return false, common.NewError("wireguard peer not found:", publicKey)
	}
	return s.removeWireguardPeerByPublicKey(wgInboundID, publicKey)
}

func (s *InboundService) upsertWireguardPeerByPublicKey(inboundID int, peer wireguardPeer) (bool, error) {
	return s.mutateWireguardPeers(inboundID, func(peers []wireguardPeer) ([]wireguardPeer, error) {
		index := s.findWireguardPeerIndexByPublicKey(peers, peer.PublicKey)
		if index >= 0 {
			peers[index] = peer
			return peers, nil
		}
		return append(peers, peer), nil
	})
}

func (s *InboundService) removeWireguardPeerByPublicKey(inboundID int, publicKey string) (bool, error) {
	return s.mutateWireguardPeers(inboundID, func(peers []wireguardPeer) ([]wireguardPeer, error) {
		index := s.findWireguardPeerIndexByPublicKey(peers, publicKey)
		if index < 0 {
			return peers, nil
		}
		return append(peers[:index], peers[index+1:]...), nil
	})
}

func (s *InboundService) getWireguardPeerByPublicKey(inboundID int, publicKey string) (*wireguardPeer, *model.Inbound, error) {
	inbound, err := s.GetInbound(inboundID)
	if err != nil {
		return nil, nil, err
	}
	if inbound.Protocol != model.WireGuard {
		return nil, nil, common.NewError("inbound is not wireguard")
	}
	_, peers, err := s.getWireguardSettings(inbound.Settings)
	if err != nil {
		return nil, nil, err
	}
	index := s.findWireguardPeerIndexByPublicKey(peers, publicKey)
	if index < 0 {
		return nil, nil, common.NewError("wireguard peer not found:", publicKey)
	}
	peer := peers[index]
	return &peer, inbound, nil
}

func (s *InboundService) applyVKTurnProxyClientBinding(settings *VKTurnProxySettings, client *VKTurnProxyClient, previous *VKTurnProxyClient) (bool, error) {
	if settings.Forward.Type != VKTurnProxyForwardWireGuardInbound {
		return false, common.NewError("vk-turn-proxy client management requires a wireguard inbound forward target")
	}

	wgInboundID := settings.Forward.WireGuardInboundID
	needRestart := false
	oldPeerKey := ""
	if previous != nil {
		oldPeerKey = strings.TrimSpace(previous.PeerPublicKey)
	}
	newPeerKey := resolveVKTurnProxyClientPublicKey(client)
	if newPeerKey != "" {
		client.PeerPublicKey = newPeerKey
	}

	if previous != nil && previous.Peer != nil && client.Peer == nil && strings.TrimSpace(previous.PeerPublicKey) == strings.TrimSpace(client.PeerPublicKey) {
		client.Peer = cloneWireguardPeerToVKTurnProxyClientPeer(&wireguardPeer{
			PrivateKey:   previous.Peer.PrivateKey,
			PublicKey:    previous.Peer.PublicKey,
			PreSharedKey: previous.Peer.PreSharedKey,
			AllowedIPs:   previous.Peer.AllowedIPs,
			KeepAlive:    previous.Peer.KeepAlive,
		})
	}

	if client.Enable {
		restart, err := s.ensureVKTurnProxyClientPeerEnabled(wgInboundID, client)
		if err != nil {
			return needRestart, err
		}
		needRestart = needRestart || restart
	} else {
		if client.PeerPublicKey != "" {
			if err := s.ensureVKTurnProxyBindingAvailable(wgInboundID, client.PeerPublicKey, client.ID); err != nil {
				return needRestart, err
			}
		}
		restart, err := s.ensureVKTurnProxyClientPeerDisabled(wgInboundID, client)
		if err != nil {
			return needRestart, err
		}
		needRestart = needRestart || restart
	}

	if oldPeerKey != "" && oldPeerKey != strings.TrimSpace(client.PeerPublicKey) {
		restart, err := s.removeWireguardPeerByPublicKey(wgInboundID, oldPeerKey)
		if err != nil {
			return needRestart, err
		}
		needRestart = needRestart || restart
	}
	return needRestart, nil
}

func (s *InboundService) getVKTurnProxyClient(inboundID int, clientID string) (*model.Inbound, *VKTurnProxySettings, int, error) {
	inbound, err := s.GetInbound(inboundID)
	if err != nil {
		return nil, nil, -1, err
	}
	if inbound.Protocol != model.VKTurnProxy {
		return nil, nil, -1, common.NewError("inbound is not vk-turn-proxy")
	}
	settings, err := s.getVKTurnProxySettings(inbound.Settings)
	if err != nil {
		return nil, nil, -1, err
	}
	index := s.findVKTurnProxyClientIndex(settings.Clients, clientID)
	if index < 0 {
		return nil, nil, -1, common.NewError("vk-turn-proxy client not found:", clientID)
	}
	return inbound, settings, index, nil
}

func marshalVKTurnProxyClientEnvelope(client *VKTurnProxyClient) (string, error) {
	payload := struct {
		Clients []VKTurnProxyClient `json:"clients"`
	}{
		Clients: []VKTurnProxyClient{*client},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (s *InboundService) AddVKTurnProxyClientDirect(inboundID int, client *VKTurnProxyClient, requestHost string) (*VKTurnProxyClientCreateResult, bool, error) {
	if client == nil {
		return nil, false, common.NewError("vk-turn-proxy client is required")
	}

	s.normalizeVKTurnProxyClient(client, true)
	rawSettings, err := marshalVKTurnProxyClientEnvelope(client)
	if err != nil {
		return nil, false, err
	}

	needRestart, err := s.AddVKTurnProxyClient(&model.Inbound{
		Id:       inboundID,
		Settings: rawSettings,
	})
	if err != nil {
		return nil, needRestart, err
	}

	result := &VKTurnProxyClientCreateResult{
		ClientID: client.ID,
		Email:    client.Email,
	}
	link, err := s.ExportVKTurnProxyClient(inboundID, client.ID, requestHost)
	if err != nil {
		return result, needRestart, nil
	}
	result.Link = link
	return result, needRestart, nil
}

func (s *InboundService) GetVKTurnProxyClientTraffic(inboundID int, clientID string) (*xray.ClientTraffic, error) {
	inbound, settings, index, err := s.getVKTurnProxyClient(inboundID, clientID)
	if err != nil {
		return nil, err
	}
	client := settings.Clients[index]

	db := database.GetDB()
	var traffic xray.ClientTraffic
	err = db.Where("email = ?", client.Email).First(&traffic).Error
	if err == nil {
		return s.GetClientTrafficByEmail(client.Email)
	}
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}

	if err := db.Transaction(func(tx *gorm.DB) error {
		_, err := s.syncVKTurnProxyClientTrafficRows(tx, []*model.Inbound{inbound})
		return err
	}); err != nil {
		return nil, err
	}

	return s.GetClientTrafficByEmail(client.Email)
}

func (s *InboundService) SetVKTurnProxyClientEnable(inboundID int, clientID string, enable bool) (bool, error) {
	_, settings, index, err := s.getVKTurnProxyClient(inboundID, clientID)
	if err != nil {
		return false, err
	}
	client := settings.Clients[index]
	if client.Enable == enable {
		return false, nil
	}
	client.Enable = enable
	rawSettings, err := marshalVKTurnProxyClientEnvelope(&client)
	if err != nil {
		return false, err
	}
	return s.UpdateVKTurnProxyClient(&model.Inbound{
		Id:       inboundID,
		Settings: rawSettings,
	}, clientID)
}

func (s *InboundService) AddVKTurnProxyClient(data *model.Inbound) (bool, error) {
	oldInbound, err := s.GetInbound(data.Id)
	if err != nil {
		return false, err
	}
	settings, err := s.getVKTurnProxySettings(oldInbound.Settings)
	if err != nil {
		return false, err
	}
	if err := s.validateVKTurnProxySettings(settings, true); err != nil {
		return false, err
	}

	clients, err := s.getVKTurnProxyClientEnvelope(data.Settings)
	if err != nil {
		return false, err
	}
	if len(clients) != 1 {
		return false, common.NewError("vk-turn-proxy add client expects exactly one client")
	}
	client := clients[0]
	s.normalizeVKTurnProxyClient(&client, true)
	if err := s.validateVKTurnProxyClient(&client); err != nil {
		return false, err
	}

	existEmail, err := s.checkEmailsExistForClients([]model.Client{{ID: client.ID, Email: client.Email}})
	if err != nil {
		return false, err
	}
	if existEmail != "" {
		return false, common.NewError("Duplicate email:", existEmail)
	}

	needRestart, err := s.applyVKTurnProxyClientBinding(settings, &client, nil)
	if err != nil {
		return needRestart, err
	}

	settings.Clients = append(settings.Clients, client)
	rawSettings, err := s.marshalVKTurnProxySettings(settings)
	if err != nil {
		return needRestart, err
	}
	oldInbound.Settings = rawSettings
	db := database.GetDB()
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(oldInbound).Error; err != nil {
			return err
		}
		return s.addVKTurnProxyClientTraffic(tx, oldInbound.Id, &client)
	})
	return needRestart, err
}

func (s *InboundService) UpdateVKTurnProxyClient(data *model.Inbound, clientID string) (bool, error) {
	oldInbound, err := s.GetInbound(data.Id)
	if err != nil {
		return false, err
	}
	settings, err := s.getVKTurnProxySettings(oldInbound.Settings)
	if err != nil {
		return false, err
	}
	if err := s.validateVKTurnProxySettings(settings, true); err != nil {
		return false, err
	}

	clients, err := s.getVKTurnProxyClientEnvelope(data.Settings)
	if err != nil {
		return false, err
	}
	if len(clients) != 1 {
		return false, common.NewError("vk-turn-proxy update client expects exactly one client")
	}

	index := s.findVKTurnProxyClientIndex(settings.Clients, clientID)
	if index < 0 {
		return false, common.NewError("vk-turn-proxy client not found:", clientID)
	}

	previous := settings.Clients[index]
	client := clients[0]
	if client.ID == "" {
		client.ID = previous.ID
	}
	client.CreatedAt = previous.CreatedAt
	s.normalizeVKTurnProxyClient(&client, false)
	if err := s.validateVKTurnProxyClient(&client); err != nil {
		return false, err
	}

	if !strings.EqualFold(client.Email, previous.Email) {
		existEmail, err := s.checkEmailsExistForClients([]model.Client{{ID: client.ID, Email: client.Email}})
		if err != nil {
			return false, err
		}
		if existEmail != "" {
			return false, common.NewError("Duplicate email:", existEmail)
		}
	}

	needRestart, err := s.applyVKTurnProxyClientBinding(settings, &client, &previous)
	if err != nil {
		return needRestart, err
	}

	settings.Clients[index] = client
	rawSettings, err := s.marshalVKTurnProxySettings(settings)
	if err != nil {
		return needRestart, err
	}
	oldInbound.Settings = rawSettings
	db := database.GetDB()
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(oldInbound).Error; err != nil {
			return err
		}
		return s.updateVKTurnProxyClientTraffic(tx, previous.Email, &client)
	})
	return needRestart, err
}

func (s *InboundService) DelVKTurnProxyClient(inboundID int, clientID string) (bool, error) {
	oldInbound, err := s.GetInbound(inboundID)
	if err != nil {
		return false, err
	}
	settings, err := s.getVKTurnProxySettings(oldInbound.Settings)
	if err != nil {
		return false, err
	}

	index := s.findVKTurnProxyClientIndex(settings.Clients, clientID)
	if index < 0 {
		return false, common.NewError("vk-turn-proxy client not found:", clientID)
	}
	client := settings.Clients[index]
	settings.Clients = append(settings.Clients[:index], settings.Clients[index+1:]...)

	needRestart := false
	if client.PeerManaged && settings.Forward.Type == VKTurnProxyForwardWireGuardInbound && strings.TrimSpace(client.PeerPublicKey) != "" {
		restart, err := s.removeWireguardPeerByPublicKey(settings.Forward.WireGuardInboundID, client.PeerPublicKey)
		if err != nil {
			return restart, err
		}
		needRestart = needRestart || restart
	}

	rawSettings, err := s.marshalVKTurnProxySettings(settings)
	if err != nil {
		return needRestart, err
	}
	oldInbound.Settings = rawSettings
	db := database.GetDB()
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(oldInbound).Error; err != nil {
			return err
		}
		return s.delVKTurnProxyClientTraffic(tx, client.Email)
	})
	return needRestart, err
}

func (s *InboundService) GetVKTurnProxyPeerOptions(inboundID int) (*VKTurnProxyPeerOptionsResponse, error) {
	inbound, err := s.GetInbound(inboundID)
	if err != nil {
		return nil, err
	}
	if inbound.Protocol != model.VKTurnProxy {
		return nil, common.NewError("inbound is not vk-turn-proxy")
	}

	settings, err := s.getVKTurnProxySettings(inbound.Settings)
	if err != nil {
		return nil, err
	}
	if settings.Forward.Type != VKTurnProxyForwardWireGuardInbound {
		return nil, common.NewError("vk-turn-proxy inbound is not linked to a wireguard inbound")
	}

	wgInbound, err := s.GetInbound(settings.Forward.WireGuardInboundID)
	if err != nil {
		return nil, err
	}
	_, peers, err := s.getWireguardSettings(wgInbound.Settings)
	if err != nil {
		return nil, err
	}
	bindings, err := s.getVKTurnProxyPeerBindings(wgInbound.Id)
	if err != nil {
		return nil, err
	}

	resp := &VKTurnProxyPeerOptionsResponse{
		WireGuardInboundID: wgInbound.Id,
		WireGuardRemark:    wgInbound.Remark,
		Peers:              make([]VKTurnProxyPeerOption, 0, len(peers)),
	}
	for _, peer := range peers {
		option := VKTurnProxyPeerOption{
			PublicKey:  peer.PublicKey,
			AllowedIPs: peer.AllowedIPs,
		}
		if binding, ok := bindings[strings.TrimSpace(peer.PublicKey)]; ok {
			bindingCopy := binding
			option.Bound = &bindingCopy
		}
		resp.Peers = append(resp.Peers, option)
	}
	return resp, nil
}

func (s *InboundService) buildVKTurnProxyExportConfig(inbound *model.Inbound, settings *VKTurnProxySettings, client *VKTurnProxyClient, peer *wireguardPeer, requestHost string) (*wingsvproto.Config, error) {
	host := resolveVKTurnProxyExportIPv4(inbound, requestHost)
	if host == "" {
		return nil, common.NewError("unable to determine export host for vk-turn-proxy")
	}

	wgInbound, err := s.GetInbound(settings.Forward.WireGuardInboundID)
	if err != nil {
		return nil, err
	}
	wgSettings, _, err := s.getWireguardSettings(wgInbound.Settings)
	if err != nil {
		return nil, err
	}

	secretKey, _ := wgSettings["secretKey"].(string)
	serverPublicKey, err := deriveWireGuardPublicKey(secretKey)
	if err != nil {
		return nil, err
	}

	privateKeyBytes, err := decodeWireGuardKey(peer.PrivateKey)
	if err != nil {
		return nil, err
	}
	serverPublicKeyBytes, err := decodeWireGuardKey(serverPublicKey)
	if err != nil {
		return nil, err
	}

	config := &wingsvproto.Config{
		Ver:     vkTurnProxyCurrentVersion,
		Type:    wingsvproto.ConfigType_CONFIG_TYPE_VK,
		Backend: wingsvproto.BackendType_BACKEND_TYPE_VK_TURN_WIREGUARD,
		Turn: &wingsvproto.Turn{
			Endpoint: &wingsvproto.Endpoint{
				Host: host,
				Port: uint32(inbound.Port),
			},
			Link:        client.Link,
			SessionMode: wingsvproto.TurnSessionMode_TURN_SESSION_MODE_AUTO,
		},
		Wg: &wingsvproto.WireGuard{
			Iface: &wingsvproto.Interface{
				PrivateKey: privateKeyBytes,
				Addrs:      append([]string(nil), peer.AllowedIPs...),
			},
			Peer: &wingsvproto.Peer{
				PublicKey: serverPublicKeyBytes,
			},
		},
	}

	if settings.LocalEndpoint != "" && settings.LocalEndpoint != vkTurnProxyDefaultLocalAddress {
		localHost, localPort, err := net.SplitHostPort(settings.LocalEndpoint)
		if err == nil {
			config.Turn.LocalEndpoint = &wingsvproto.Endpoint{
				Host: localHost,
				Port: mustParseUint32(localPort),
			}
		}
	}
	switch settings.SessionMode {
	case "mainline":
		config.Turn.SessionMode = wingsvproto.TurnSessionMode_TURN_SESSION_MODE_MAINLINE
	case "mux":
		config.Turn.SessionMode = wingsvproto.TurnSessionMode_TURN_SESSION_MODE_MUX
	}

	config.Wg.Iface.Dns = append(config.Wg.Iface.Dns, splitCSV(settings.WGDNS)...)
	if settings.WGMTU > 0 {
		mtu := uint32(settings.WGMTU)
		config.Wg.Iface.Mtu = &mtu
	}
	for _, cidr := range splitCSV(settings.WGAllowedIPs) {
		parsedCIDR, err := parseWireGuardCIDR(cidr)
		if err != nil {
			return nil, err
		}
		config.Wg.Peer.AllowedIps = append(config.Wg.Peer.AllowedIps, parsedCIDR)
	}
	if strings.TrimSpace(peer.PreSharedKey) != "" {
		pskBytes, err := decodeWireGuardKey(peer.PreSharedKey)
		if err != nil {
			return nil, err
		}
		config.Wg.Peer.PresharedKey = pskBytes
	}

	return config, nil
}

func mustParseUint32(raw string) uint32 {
	port, err := strconv.Atoi(raw)
	if err != nil || port <= 0 {
		return 0
	}
	return uint32(port)
}

func (s *InboundService) ExportVKTurnProxyClient(inboundID int, clientID string, requestHost string) (string, error) {
	inbound, err := s.GetInbound(inboundID)
	if err != nil {
		return "", err
	}
	if inbound.Protocol != model.VKTurnProxy {
		return "", common.NewError("inbound is not vk-turn-proxy")
	}
	settings, err := s.getVKTurnProxySettings(inbound.Settings)
	if err != nil {
		return "", err
	}
	if settings.Forward.Type != VKTurnProxyForwardWireGuardInbound {
		return "", common.NewError("vk-turn-proxy export requires a wireguard inbound target")
	}

	index := s.findVKTurnProxyClientIndex(settings.Clients, clientID)
	if index < 0 {
		return "", common.NewError("vk-turn-proxy client not found:", clientID)
	}
	client := settings.Clients[index]
	peer, _, err := s.getWireguardPeerByPublicKey(settings.Forward.WireGuardInboundID, client.PeerPublicKey)
	if err != nil {
		return "", err
	}

	config, err := s.buildVKTurnProxyExportConfig(inbound, settings, &client, peer, requestHost)
	if err != nil {
		return "", err
	}
	return encodeVKTurnProxyConfig(config)
}

func (s *InboundService) ExportAllVKTurnProxyClients(inboundID int, requestHost string) ([]VKTurnProxyExportedClient, error) {
	inbound, err := s.GetInbound(inboundID)
	if err != nil {
		return nil, err
	}
	if inbound.Protocol != model.VKTurnProxy {
		return nil, common.NewError("inbound is not vk-turn-proxy")
	}
	settings, err := s.getVKTurnProxySettings(inbound.Settings)
	if err != nil {
		return nil, err
	}

	exported := make([]VKTurnProxyExportedClient, 0, len(settings.Clients))
	for _, client := range settings.Clients {
		link, err := s.ExportVKTurnProxyClient(inboundID, client.ID, requestHost)
		if err != nil {
			return nil, err
		}
		exported = append(exported, VKTurnProxyExportedClient{
			ClientID: client.ID,
			Email:    client.Email,
			Link:     link,
		})
	}
	return exported, nil
}
