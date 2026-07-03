package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	wgutil "github.com/mhsanaei/3x-ui/v3/internal/util/wireguard"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service/panel"
	"github.com/mhsanaei/3x-ui/v3/internal/wingsv/panelapi"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

type panelService struct {
	panelapi.UnimplementedPanelServer
	inbound       *service.InboundService
	client        *service.ClientService
	server        *service.ServerService
	onNeedRestart func()
}

func (p *panelService) markRestart(needRestart bool) bool {
	if needRestart && p.onNeedRestart != nil {
		p.onNeedRestart()
	}
	return needRestart
}

func (p *panelService) GetServerStatus(context.Context, *panelapi.GetServerStatusRequest) (*panelapi.ServerStatus, error) {
	st := p.server.GetStatus(&service.Status{})
	return &panelapi.ServerStatus{
		Cpu:         st.Cpu,
		CpuCores:    int32(st.CpuCores),
		MemCurrent:  st.Mem.Current,
		MemTotal:    st.Mem.Total,
		Uptime:      st.Uptime,
		XrayState:   string(st.Xray.State),
		XrayVersion: st.Xray.Version,
		NetUp:       st.NetIO.Up,
		NetDown:     st.NetIO.Down,
		TcpCount:    int32(st.TcpCount),
		UdpCount:    int32(st.UdpCount),
	}, nil
}

func (p *panelService) ListInbounds(context.Context, *panelapi.ListInboundsRequest) (*panelapi.Inbounds, error) {
	inbounds, err := p.inbound.GetAllInbounds()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	out := make([]*panelapi.InboundSummary, 0, len(inbounds))
	for _, ib := range inbounds {
		out = append(out, &panelapi.InboundSummary{
			Id:       int64(ib.Id),
			Tag:      ib.Tag,
			Remark:   ib.Remark,
			Protocol: string(ib.Protocol),
			Listen:   ib.Listen,
			Port:     int32(ib.Port),
			Enable:   ib.Enable,
			Up:       ib.Up,
			Down:     ib.Down,
			Total:    ib.Total,
		})
	}
	return &panelapi.Inbounds{Inbounds: out}, nil
}

func (p *panelService) GetClientTraffic(_ context.Context, req *panelapi.GetClientTrafficRequest) (*panelapi.ClientTraffic, error) {
	t, err := p.inbound.GetClientTrafficByEmail(req.GetEmail())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if t == nil {
		return nil, status.Errorf(codes.NotFound, "no client with email %q", req.GetEmail())
	}
	return toClientTraffic(t), nil
}

func (p *panelService) ListOnlineClients(context.Context, *panelapi.ListOnlineClientsRequest) (*panelapi.OnlineClients, error) {
	return &panelapi.OnlineClients{Emails: p.inbound.GetOnlineClients()}, nil
}

// CreateWireguardClient adds a peer to a WireGuard inbound (generating a keypair
// and allocating a tunnel address) and returns the peer config. It is idempotent
// on client_id: a re-provision returns the already-created peer.
func (p *panelService) CreateWireguardClient(_ context.Context, req *panelapi.CreateWireguardClientRequest) (*panelapi.WireguardClientConfig, error) {
	if req.GetClientId() == "" {
		return nil, status.Error(codes.InvalidArgument, "client_id is required")
	}
	inbounds, err := p.inbound.GetAllInbounds()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	var wg *model.Inbound
	for _, ib := range inbounds {
		if ib.Protocol == model.WireGuard && (req.GetInboundTag() == "" || ib.Tag == req.GetInboundTag()) {
			wg = ib
			break
		}
	}
	if wg == nil {
		return nil, status.Error(codes.NotFound, "no matching wireguard inbound")
	}
	serverPub, mtu := wireguardServerInfo(wg.Settings)

	if existing, ok := p.findWireguardPeer(wg, req.GetClientId()); ok {
		return wireguardConfig(existing, serverPub, mtu, wg), nil
	}

	priv, pub, err := wgutil.GenerateWireguardKeypair()
	if err != nil {
		return nil, status.Error(codes.Internal, "keypair: "+err.Error())
	}
	needRestart, err := p.client.CreateOne(p.inbound, wg.Id, model.Client{
		Email: req.GetClientId(), Enable: true, PublicKey: pub, PrivateKey: priv,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	p.markRestart(needRestart)

	created, err := p.inbound.GetInbound(wg.Id)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	peer, ok := p.findWireguardPeer(created, req.GetClientId())
	if !ok {
		return nil, status.Error(codes.Internal, "created peer not found")
	}
	return wireguardConfig(peer, serverPub, mtu, created), nil
}

func (p *panelService) findWireguardPeer(inbound *model.Inbound, email string) (model.Client, bool) {
	clients, err := p.inbound.GetClients(inbound)
	if err != nil {
		return model.Client{}, false
	}
	for _, c := range clients {
		if c.Email == email {
			return c, true
		}
	}
	return model.Client{}, false
}

func wireguardConfig(c model.Client, serverPub string, mtu int, inbound *model.Inbound) *panelapi.WireguardClientConfig {
	addr := ""
	if len(c.AllowedIPs) > 0 {
		addr = c.AllowedIPs[0]
	}
	return &panelapi.WireguardClientConfig{
		PrivateKey:      c.PrivateKey,
		PublicKey:       c.PublicKey,
		Address:         addr,
		ServerPublicKey: serverPub,
		Mtu:             uint32(mtu),
		Endpoint:        fmt.Sprintf("%s:%d", inbound.Listen, inbound.Port),
	}
}

func wireguardServerInfo(settings string) (string, int) {
	var parsed struct {
		PublicKey string `json:"publicKey"`
		PubKey    string `json:"pubKey"`
		SecretKey string `json:"secretKey"`
		MTU       int    `json:"mtu"`
	}
	if json.Unmarshal([]byte(settings), &parsed) != nil {
		return "", 0
	}
	pub := parsed.PublicKey
	if pub == "" {
		pub = parsed.PubKey
	}
	if pub == "" && parsed.SecretKey != "" {
		if derived, derr := wgutil.PublicKeyFromPrivate(parsed.SecretKey); derr == nil {
			pub = derived
		}
	}
	return pub, parsed.MTU
}

func (p *panelService) AddClient(_ context.Context, req *panelapi.AddClientRequest) (*panelapi.MutationResponse, error) {
	var payload service.ClientCreatePayload
	if err := json.Unmarshal([]byte(req.GetPayloadJson()), &payload); err != nil {
		return nil, status.Error(codes.InvalidArgument, "payload_json: "+err.Error())
	}
	needRestart, err := p.client.Create(p.inbound, &payload)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &panelapi.MutationResponse{Ok: true, NeedRestart: p.markRestart(needRestart)}, nil
}

func (p *panelService) UpdateClient(_ context.Context, req *panelapi.UpdateClientRequest) (*panelapi.MutationResponse, error) {
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	var updated model.Client
	if err := json.Unmarshal([]byte(req.GetPayloadJson()), &updated); err != nil {
		return nil, status.Error(codes.InvalidArgument, "payload_json: "+err.Error())
	}
	needRestart, err := p.client.UpdateByEmail(p.inbound, req.GetEmail(), updated)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &panelapi.MutationResponse{Ok: true, NeedRestart: p.markRestart(needRestart)}, nil
}

func (p *panelService) DeleteClient(_ context.Context, req *panelapi.DeleteClientRequest) (*panelapi.MutationResponse, error) {
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	needRestart, err := p.client.DeleteByEmail(p.inbound, req.GetEmail(), req.GetKeepTraffic())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &panelapi.MutationResponse{Ok: true, NeedRestart: p.markRestart(needRestart)}, nil
}

func (p *panelService) StreamClientTraffic(req *panelapi.StreamClientTrafficRequest, stream grpc.ServerStreamingServer[panelapi.ClientTraffic]) error {
	interval := time.Duration(req.GetIntervalSeconds()) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := p.sendTraffic(req.GetEmail(), stream); err != nil {
			return err
		}
		select {
		case <-stream.Context().Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (p *panelService) sendTraffic(email string, stream grpc.ServerStreamingServer[panelapi.ClientTraffic]) error {
	if email != "" {
		t, err := p.inbound.GetClientTrafficByEmail(email)
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}
		if t == nil {
			return nil
		}
		return stream.Send(toClientTraffic(t))
	}
	traffics, err := p.inbound.GetAllClientTraffics()
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	for _, t := range traffics {
		if err := stream.Send(toClientTraffic(t)); err != nil {
			return err
		}
	}
	return nil
}

func toClientTraffic(t *xray.ClientTraffic) *panelapi.ClientTraffic {
	return &panelapi.ClientTraffic{
		Id:         int64(t.Id),
		InboundId:  int64(t.InboundId),
		Enable:     t.Enable,
		Email:      t.Email,
		Up:         t.Up,
		Down:       t.Down,
		ExpiryTime: t.ExpiryTime,
		Total:      t.Total,
		LastOnline: t.LastOnline,
	}
}

type authenticator struct {
	tokens *panel.ApiTokenService
}

func (a *authenticator) authorize(ctx context.Context) bool {
	if pr, ok := peer.FromContext(ctx); ok && pr.AuthInfo != nil {
		if ti, ok := pr.AuthInfo.(credentials.TLSInfo); ok && len(ti.State.VerifiedChains) > 0 {
			return true
		}
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	for _, v := range md.Get("authorization") {
		if tok, ok := strings.CutPrefix(v, "Bearer "); ok && a.tokens.Match(tok) {
			return true
		}
	}
	return false
}

func (a *authenticator) unary(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if !a.authorize(ctx) {
		return nil, status.Error(codes.Unauthenticated, "missing or invalid API credentials")
	}
	return handler(ctx, req)
}

func (a *authenticator) stream(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if !a.authorize(ss.Context()) {
		return status.Error(codes.Unauthenticated, "missing or invalid API credentials")
	}
	return handler(srv, ss)
}

func NewServer(creds credentials.TransportCredentials, onNeedRestart func()) *grpc.Server {
	auth := &authenticator{tokens: &panel.ApiTokenService{}}
	options := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(auth.unary),
		grpc.ChainStreamInterceptor(auth.stream),
	}
	if creds != nil {
		options = append(options, grpc.Creds(creds))
	}
	gs := grpc.NewServer(options...)
	panelapi.RegisterPanelServer(gs, &panelService{
		inbound:       &service.InboundService{},
		client:        &service.ClientService{},
		server:        &service.ServerService{},
		onNeedRestart: onNeedRestart,
	})
	return gs
}
