package grpcapi

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service/panel"
	"github.com/mhsanaei/3x-ui/v3/internal/wingsv/panelapi"
)

type panelService struct {
	panelapi.UnimplementedPanelServer
	inbound *service.InboundService
}

func (p *panelService) GetClientTraffic(ctx context.Context, req *panelapi.GetClientTrafficRequest) (*panelapi.ClientTraffic, error) {
	t, err := p.inbound.GetClientTrafficByEmail(req.GetEmail())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if t == nil {
		return nil, status.Errorf(codes.NotFound, "no client with email %q", req.GetEmail())
	}
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
	}, nil
}

func (p *panelService) ListOnlineClients(ctx context.Context, _ *panelapi.ListOnlineClientsRequest) (*panelapi.OnlineClients, error) {
	return &panelapi.OnlineClients{Emails: p.inbound.GetOnlineClients()}, nil
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

func (a *authenticator) unary(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if !a.authorize(ctx) {
		return nil, status.Error(codes.Unauthenticated, "missing or invalid API credentials")
	}
	return handler(ctx, req)
}

func NewServer(creds credentials.TransportCredentials) *grpc.Server {
	auth := &authenticator{tokens: &panel.ApiTokenService{}}
	options := []grpc.ServerOption{grpc.ChainUnaryInterceptor(auth.unary)}
	if creds != nil {
		options = append(options, grpc.Creds(creds))
	}
	gs := grpc.NewServer(options...)
	panelapi.RegisterPanelServer(gs, &panelService{inbound: &service.InboundService{}})
	return gs
}
