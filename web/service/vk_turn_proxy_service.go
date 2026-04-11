package service

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/common"
	"github.com/mhsanaei/3x-ui/v2/vkturnproxy"
	wingsvproto "github.com/mhsanaei/3x-ui/v2/wingsv/proto"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
)

const (
	vkTurnProxyReleaseRepo         = "WINGS-N/vk-turn-proxy"
	vkTurnProxyCurrentVersion      = 1
	vkTurnProxySchemePrefix        = "wingsv://"
	vkTurnProxyFormatProtoDeflate  = 0x12
	vkTurnProxyDefaultSessionMode  = "auto"
	vkTurnProxyDefaultLocalAddress = "127.0.0.1:9000"
	vkTurnProxyDefaultWGDNS        = "1.1.1.1, 1.0.0.1"
	vkTurnProxyDefaultWGMTU        = 1280
	vkTurnProxyDefaultWGAllowedIPs = "0.0.0.0/0, ::/0"
)

type VKTurnProxyForwardType string

const (
	VKTurnProxyForwardWireGuardInbound VKTurnProxyForwardType = "wireguardInbound"
	VKTurnProxyForwardExternal         VKTurnProxyForwardType = "external"
)

type VKTurnProxyForward struct {
	Type               VKTurnProxyForwardType `json:"type"`
	WireGuardInboundID int                    `json:"wireguardInboundId,omitempty"`
	Host               string                 `json:"host,omitempty"`
	Port               int                    `json:"port,omitempty"`
}

type VKTurnProxyClientPeer struct {
	PrivateKey   string   `json:"privateKey"`
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey,omitempty"`
	AllowedIPs   []string `json:"allowedIPs,omitempty"`
	KeepAlive    int      `json:"keepAlive,omitempty"`
}

type VKTurnProxyClient struct {
	ID            string                 `json:"id"`
	Email         string                 `json:"email"`
	Enable        bool                   `json:"enable"`
	Comment       string                 `json:"comment,omitempty"`
	LimitIP       int                    `json:"limitIp,omitempty"`
	TotalGB       int64                  `json:"totalGB,omitempty"`
	ExpiryTime    int64                  `json:"expiryTime,omitempty"`
	TgID          int64                  `json:"tgId,omitempty"`
	SubID         string                 `json:"subId,omitempty"`
	Reset         int                    `json:"reset,omitempty"`
	CreatedAt     int64                  `json:"created_at,omitempty"`
	UpdatedAt     int64                  `json:"updated_at,omitempty"`
	Link          string                 `json:"link"`
	PeerPublicKey string                 `json:"peerPublicKey"`
	PeerManaged   bool                   `json:"peerManaged,omitempty"`
	Peer          *VKTurnProxyClientPeer `json:"peer,omitempty"`
}

type VKTurnProxySettings struct {
	Forward       VKTurnProxyForward  `json:"forward"`
	SessionMode   string              `json:"sessionMode,omitempty"`
	LocalEndpoint string              `json:"localEndpoint,omitempty"`
	WGDNS         string              `json:"wgDns,omitempty"`
	WGMTU         int                 `json:"wgMtu,omitempty"`
	WGAllowedIPs  string              `json:"wgAllowedIps,omitempty"`
	Clients       []VKTurnProxyClient `json:"clients,omitempty"`
}

type VKTurnProxyPeerBinding struct {
	InboundID     int    `json:"inboundId"`
	InboundRemark string `json:"inboundRemark"`
	ClientID      string `json:"clientId"`
	ClientEmail   string `json:"clientEmail"`
}

type VKTurnProxyPeerOption struct {
	PublicKey  string                  `json:"publicKey"`
	AllowedIPs []string                `json:"allowedIPs"`
	Bound      *VKTurnProxyPeerBinding `json:"bound,omitempty"`
}

type VKTurnProxyPeerOptionsResponse struct {
	WireGuardInboundID int                     `json:"wireguardInboundId"`
	WireGuardRemark    string                  `json:"wireguardRemark"`
	Peers              []VKTurnProxyPeerOption `json:"peers"`
}

type VKTurnProxyExportedClient struct {
	ClientID string `json:"clientId"`
	Email    string `json:"email"`
	Link     string `json:"link"`
}

type VKTurnProxyRuntimeStatus struct {
	Available bool         `json:"available"`
	Total     int          `json:"total"`
	Enabled   int          `json:"enabled"`
	Running   int          `json:"running"`
	State     ProcessState `json:"state"`
	ErrorMsg  string       `json:"errorMsg"`
	Version   string       `json:"version"`
	Uptime    uint64       `json:"uptime"`
}

type VKTurnProxyService struct {
	inboundService InboundService
	mu             sync.Mutex
	processes      map[int]*vkturnproxy.Process
	manualStop     bool
	lastError      string
}

var vkTurnProxyRuntime = &VKTurnProxyService{
	processes: make(map[int]*vkturnproxy.Process),
}

func VKTurnProxyRuntime() *VKTurnProxyService {
	return vkTurnProxyRuntime
}

func (s *VKTurnProxyService) EnsureRunning() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.manualStop {
		s.lastError = ""
		return nil
	}

	desired, err := s.loadDesiredSpecs()
	if err != nil {
		s.lastError = err.Error()
		return err
	}

	for inboundID, proc := range s.processes {
		spec, ok := desired[inboundID]
		if !ok || !proc.IsRunning() || proc.Spec().Key() != spec.Key() {
			_ = proc.Stop()
			delete(s.processes, inboundID)
		}
	}

	if len(desired) == 0 {
		s.lastError = ""
		return nil
	}
	if err := s.ensureBinary(); err != nil {
		s.lastError = err.Error()
		return err
	}

	var errs []error
	for inboundID, spec := range desired {
		if _, ok := s.processes[inboundID]; ok {
			continue
		}
		proc := vkturnproxy.NewProcess(spec)
		if err := proc.Start(); err != nil {
			logger.Warningf("failed to start vk-turn-proxy inbound %d: %v", inboundID, err)
			errs = append(errs, fmt.Errorf("inbound %d: %w", inboundID, err))
			continue
		}
		s.processes[inboundID] = proc
	}
	if combined := common.Combine(errs...); combined != nil {
		s.lastError = combined.Error()
		return combined
	}
	s.lastError = ""
	return nil
}

func (s *VKTurnProxyService) StopAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.manualStop = true
	s.lastError = ""
	logger.Infof("VKTURN[service] stop requested")
	return s.stopAllLocked()
}

func (s *VKTurnProxyService) StartAll() error {
	s.mu.Lock()
	s.manualStop = false
	s.lastError = ""
	s.mu.Unlock()
	logger.Infof("VKTURN[service] start requested")
	return s.EnsureRunning()
}

func (s *VKTurnProxyService) RestartAll() error {
	s.mu.Lock()
	s.manualStop = false
	s.lastError = ""
	logger.Infof("VKTURN[service] restart requested")
	err := s.stopAllLocked()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.EnsureRunning()
}

func (s *VKTurnProxyService) GetStatus() VKTurnProxyRuntimeStatus {
	total, err := s.countInbounds(nil)
	status := VKTurnProxyRuntimeStatus{
		Available: total > 0,
		Total:     total,
		State:     Stop,
	}
	if err != nil {
		status.State = Error
		status.ErrorMsg = err.Error()
		return status
	}

	desired, err := s.loadDesiredSpecs()
	if err != nil {
		status.Enabled = len(desired)
		status.State = Error
		status.ErrorMsg = err.Error()
		return status
	}
	status.Enabled = len(desired)

	s.mu.Lock()
	defer s.mu.Unlock()

	status.ErrorMsg = s.lastError
	var maxUptime uint64
	for inboundID, spec := range desired {
		proc, ok := s.processes[inboundID]
		if !ok {
			continue
		}
		if proc.Spec().Key() != spec.Key() {
			continue
		}
		if proc.IsRunning() {
			status.Running++
			if uptime := proc.GetUptime(); uptime > maxUptime {
				maxUptime = uptime
			}
			continue
		}
		if result := proc.GetResult(); result != "" && status.ErrorMsg == "" {
			status.ErrorMsg = result
		}
	}
	status.Uptime = maxUptime

	switch {
	case !status.Available:
		status.State = Stop
	case s.manualStop || status.Enabled == 0 || status.Running == 0 && status.ErrorMsg == "":
		status.State = Stop
	case status.Running == status.Enabled:
		status.State = Running
	default:
		status.State = Error
		if status.ErrorMsg == "" {
			status.ErrorMsg = "vk-turn-proxy is partially running"
		}
	}
	return status
}

func (s *VKTurnProxyService) stopAllLocked() error {

	var errs []error
	for inboundID, proc := range s.processes {
		if err := proc.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("inbound %d: %w", inboundID, err))
		}
		delete(s.processes, inboundID)
	}
	return common.Combine(errs...)
}

func (s *VKTurnProxyService) countInbounds(enabled *bool) (int, error) {
	db := database.GetDB()
	query := db.Model(&model.Inbound{}).Where("protocol = ?", model.VKTurnProxy)
	if enabled != nil {
		query = query.Where("enable = ?", *enabled)
	}

	var count int64
	if err := query.Count(&count).Error; err != nil {
		return 0, err
	}
	return int(count), nil
}

func (s *VKTurnProxyService) loadDesiredSpecs() (map[int]vkturnproxy.Spec, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	if err := db.Where("protocol = ? AND enable = ?", model.VKTurnProxy, true).Find(&inbounds).Error; err != nil {
		return nil, err
	}

	specs := make(map[int]vkturnproxy.Spec, len(inbounds))
	for _, inbound := range inbounds {
		settings, err := s.inboundService.getVKTurnProxySettings(inbound.Settings)
		if err != nil {
			logger.Warningf("skip vk-turn-proxy inbound %d: %v", inbound.Id, err)
			continue
		}

		connect, err := s.inboundService.resolveVKTurnProxyForwardAddress(settings)
		if err != nil {
			logger.Warningf("skip vk-turn-proxy inbound %d: %v", inbound.Id, err)
			continue
		}

		listenHost := strings.TrimSpace(inbound.Listen)
		if listenHost == "" || listenHost == "0.0.0.0" || listenHost == "::" || listenHost == "::0" {
			listenHost = "0.0.0.0"
		}
		specs[inbound.Id] = vkturnproxy.Spec{
			ID:          inbound.Id,
			Remark:      inbound.Remark,
			Listen:      net.JoinHostPort(listenHost, fmt.Sprintf("%d", inbound.Port)),
			Connect:     connect,
			SessionMode: settings.SessionMode,
		}
	}
	return specs, nil
}

func (s *VKTurnProxyService) ensureBinary() error {
	if err := vkturnproxy.EnsureBinaryExecutable(); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		logger.Warning("vk-turn-proxy binary check failed:", err)
	}

	_, err := s.downloadBinary("latest")
	return err
}

func (s *VKTurnProxyService) downloadBinary(version string) (string, error) {
	assetName, err := vkturnproxy.GetReleaseAssetName()
	if err != nil {
		return "", err
	}

	version = strings.TrimSpace(version)
	if version == "" {
		return "", common.NewError("vk-turn-proxy version is empty")
	}

	resolvedVersion := version
	if version == "latest" {
		resolvedVersion, err = getGitHubLatestReleaseVersion(vkTurnProxyReleaseRepo)
		if err != nil {
			return "", err
		}
	}
	downloadURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", vkTurnProxyReleaseRepo, url.PathEscape(resolvedVersion), assetName)

	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Get(downloadURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("vk-turn-proxy download failed: %s (%s)", resp.Status, strings.TrimSpace(string(body)))
	}

	if err := os.MkdirAll(filepath.Dir(vkturnproxy.GetBinaryPath()), 0o755); err != nil {
		return "", err
	}

	tmpPath := vkturnproxy.GetBinaryPath() + ".tmp"
	defer os.Remove(tmpPath)
	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(file, resp.Body); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return "", err
	}
	_ = os.Remove(vkturnproxy.GetBinaryPath())
	if err := os.Rename(tmpPath, vkturnproxy.GetBinaryPath()); err != nil {
		return "", err
	}
	if err := os.Chmod(vkturnproxy.GetBinaryPath(), 0o755); err != nil {
		return "", err
	}
	if err := writeReleaseMetadata(vkturnproxy.GetBinaryPath(), resolvedVersion); err != nil {
		return "", err
	}
	if err := (&SettingService{}).SetVKTurnProxyReleaseTag(resolvedVersion); err != nil {
		return "", err
	}
	return resolvedVersion, nil
}

func (s *VKTurnProxyService) UpdateBinary(version string) error {
	version = strings.TrimSpace(version)
	if version == "" {
		return common.NewError("vk-turn-proxy version is empty")
	}

	s.mu.Lock()
	previousManualStop := s.manualStop
	s.manualStop = true
	s.lastError = ""
	stopErr := s.stopAllLocked()
	s.mu.Unlock()
	if stopErr != nil {
		return stopErr
	}

	if _, err := s.downloadBinary(version); err != nil {
		s.mu.Lock()
		s.manualStop = previousManualStop
		s.lastError = err.Error()
		s.mu.Unlock()
		if !previousManualStop {
			_ = s.EnsureRunning()
		}
		return err
	}

	s.mu.Lock()
	s.manualStop = false
	s.lastError = ""
	s.mu.Unlock()
	return s.EnsureRunning()
}

func (s *InboundService) getVKTurnProxySettings(raw string) (*VKTurnProxySettings, error) {
	settings := &VKTurnProxySettings{}
	if strings.TrimSpace(raw) == "" {
		s.normalizeVKTurnProxySettings(settings)
		return settings, nil
	}
	sanitizedRaw, err := sanitizeVKTurnProxySettingsJSON(raw)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(sanitizedRaw, settings); err != nil {
		return nil, err
	}
	s.normalizeVKTurnProxySettings(settings)
	return settings, nil
}

func sanitizeVKTurnProxySettingsJSON(raw string) ([]byte, error) {
	settings := map[string]any{}
	if err := json.Unmarshal([]byte(raw), &settings); err != nil {
		return nil, err
	}

	clients, ok := settings["clients"].([]any)
	if !ok {
		return []byte(raw), nil
	}

	for i, rawClient := range clients {
		client, ok := rawClient.(map[string]any)
		if !ok {
			continue
		}
		normalizeVKTurnProxyClientJSON(client)
		clients[i] = client
	}
	settings["clients"] = clients

	return json.Marshal(settings)
}

func normalizeVKTurnProxyClientJSON(client map[string]any) {
	tgIDRaw, ok := client["tgId"]
	if !ok {
		return
	}

	switch value := tgIDRaw.(type) {
	case string:
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			client["tgId"] = 0
			return
		}
		if tgID, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
			client["tgId"] = tgID
		}
	case nil:
		client["tgId"] = 0
	}
}

func (s *InboundService) normalizeVKTurnProxySettings(settings *VKTurnProxySettings) {
	if settings.SessionMode == "" {
		settings.SessionMode = vkTurnProxyDefaultSessionMode
	}
	if settings.LocalEndpoint == "" {
		settings.LocalEndpoint = vkTurnProxyDefaultLocalAddress
	}
	if settings.WGDNS == "" {
		settings.WGDNS = vkTurnProxyDefaultWGDNS
	}
	if settings.WGMTU == 0 {
		settings.WGMTU = vkTurnProxyDefaultWGMTU
	}
	if settings.WGAllowedIPs == "" {
		settings.WGAllowedIPs = vkTurnProxyDefaultWGAllowedIPs
	}
	for i := range settings.Clients {
		s.normalizeVKTurnProxyClient(&settings.Clients[i], false)
	}
}

func (s *InboundService) normalizeVKTurnProxyClient(client *VKTurnProxyClient, isNew bool) {
	now := time.Now().UnixMilli()
	if client.ID == "" {
		client.ID = uuid.NewString()
	}
	if isNew && client.CreatedAt == 0 {
		client.CreatedAt = now
	}
	if client.CreatedAt == 0 {
		client.CreatedAt = now
	}
	client.UpdatedAt = now
}

func (s *InboundService) validateVKTurnProxySettings(settings *VKTurnProxySettings, allowClients bool) error {
	switch settings.Forward.Type {
	case VKTurnProxyForwardWireGuardInbound:
		if settings.Forward.WireGuardInboundID <= 0 {
			return common.NewError("wireguard inbound is required")
		}
		target, err := s.GetInbound(settings.Forward.WireGuardInboundID)
		if err != nil {
			return err
		}
		if target.Protocol != model.WireGuard {
			return common.NewError("selected forward target is not a wireguard inbound")
		}
	case VKTurnProxyForwardExternal:
		if strings.TrimSpace(settings.Forward.Host) == "" {
			return common.NewError("external forward host is required")
		}
		if settings.Forward.Port <= 0 || settings.Forward.Port > 65535 {
			return common.NewError("external forward port is invalid")
		}
	default:
		return common.NewError("forward type is required")
	}

	if settings.SessionMode != "" &&
		settings.SessionMode != vkTurnProxyDefaultSessionMode &&
		settings.SessionMode != "mainline" &&
		settings.SessionMode != "mux" {
		return common.NewError("vk-turn-proxy sessionMode is invalid")
	}

	if !allowClients && len(settings.Clients) > 0 {
		return common.NewError("clients can be configured only for wireguard inbound forwarding")
	}
	return nil
}

func (s *InboundService) resolveVKTurnProxyForwardAddress(settings *VKTurnProxySettings) (string, error) {
	switch settings.Forward.Type {
	case VKTurnProxyForwardExternal:
		return net.JoinHostPort(strings.TrimSpace(settings.Forward.Host), fmt.Sprintf("%d", settings.Forward.Port)), nil
	case VKTurnProxyForwardWireGuardInbound:
		inbound, err := s.GetInbound(settings.Forward.WireGuardInboundID)
		if err != nil {
			return "", err
		}
		if inbound.Protocol != model.WireGuard {
			return "", common.NewError("selected inbound is not wireguard")
		}
		host := strings.TrimSpace(inbound.Listen)
		switch host {
		case "", "0.0.0.0", "::", "::0":
			host = "127.0.0.1"
		}
		return net.JoinHostPort(host, fmt.Sprintf("%d", inbound.Port)), nil
	default:
		return "", common.NewError("forward type is invalid")
	}
}

func (s *InboundService) marshalVKTurnProxySettings(settings *VKTurnProxySettings) (string, error) {
	payload, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		result = append(result, part)
	}
	return result
}

func encodeVKTurnProxyConfig(config *wingsvproto.Config) (string, error) {
	sanitized, ok := proto.Clone(config).(*wingsvproto.Config)
	if !ok {
		return "", common.NewError("failed to clone vk-turn-proxy export config")
	}
	if sanitized.Turn != nil {
		sanitized.Turn.Threads = nil
	}

	payload, err := proto.Marshal(sanitized)
	if err != nil {
		return "", err
	}

	var compressed bytes.Buffer
	writer, err := zlib.NewWriterLevel(&compressed, zlib.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := writer.Write(payload); err != nil {
		_ = writer.Close()
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}

	framed := make([]byte, 1+compressed.Len())
	framed[0] = vkTurnProxyFormatProtoDeflate
	copy(framed[1:], compressed.Bytes())

	return vkTurnProxySchemePrefix + base64.URLEncoding.EncodeToString(framed), nil
}

func parseWireGuardCIDR(raw string) (*wingsvproto.Cidr, error) {
	_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	prefix, _ := network.Mask.Size()
	return &wingsvproto.Cidr{
		Addr:   network.IP,
		Prefix: uint32(prefix),
	}, nil
}

func decodeWireGuardKey(raw string) ([]byte, error) {
	key, err := parseWireGuardKey(raw)
	if err != nil {
		return nil, err
	}
	keyBytes := key[:]
	return keyBytes, nil
}

func deriveWireGuardPublicKey(privateKey string) (string, error) {
	key, err := parseWireGuardKey(privateKey)
	if err != nil {
		return "", err
	}

	publicKey, err := curve25519.X25519(key[:], curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(publicKey), nil
}

func parseWireGuardKey(raw string) ([32]byte, error) {
	encoded := strings.TrimSpace(raw)
	var key [32]byte
	if encoded == "" {
		return key, common.NewError("wireguard key is empty")
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return key, err
		}
	}
	if len(decoded) != len(key) {
		return key, common.NewErrorf("wireguard key must be %d bytes, got %d", len(key), len(decoded))
	}
	copy(key[:], decoded)
	return key, nil
}
