package grpcapi

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service/panel"
	"github.com/mhsanaei/3x-ui/v3/internal/wingsv/panelapi"
)

func newTestClient(t *testing.T) panelapi.PanelClient {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { _ = database.CloseDB() })

	lis := bufconn.Listen(1 << 20)
	gs := NewServer(nil, nil)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return panelapi.NewPanelClient(conn)
}

func bearerContext(t *testing.T) context.Context {
	t.Helper()
	view, err := (&panel.ApiTokenService{}).Create("grpc-test")
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+view.Token)
}

func TestUnauthenticatedRejected(t *testing.T) {
	client := newTestClient(t)
	_, err := client.ListOnlineClients(context.Background(), &panelapi.ListOnlineClientsRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}
}

func TestListOnlineClientsAuthed(t *testing.T) {
	client := newTestClient(t)
	resp, err := client.ListOnlineClients(bearerContext(t), &panelapi.ListOnlineClientsRequest{})
	if err != nil {
		t.Fatalf("ListOnlineClients: %v", err)
	}
	if len(resp.GetEmails()) != 0 {
		t.Fatalf("online emails = %v, want empty on a fresh panel", resp.GetEmails())
	}
}

func TestGetClientTrafficNotFound(t *testing.T) {
	client := newTestClient(t)
	_, err := client.GetClientTraffic(bearerContext(t), &panelapi.GetClientTrafficRequest{Email: "nobody@example"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound (err=%v)", status.Code(err), err)
	}
}

func TestListInboundsEmpty(t *testing.T) {
	client := newTestClient(t)
	resp, err := client.ListInbounds(bearerContext(t), &panelapi.ListInboundsRequest{})
	if err != nil {
		t.Fatalf("ListInbounds: %v", err)
	}
	if len(resp.GetInbounds()) != 0 {
		t.Fatalf("inbounds = %d, want 0 on a fresh panel", len(resp.GetInbounds()))
	}
}

func TestGetServerStatus(t *testing.T) {
	client := newTestClient(t)
	resp, err := client.GetServerStatus(bearerContext(t), &panelapi.GetServerStatusRequest{})
	if err != nil {
		t.Fatalf("GetServerStatus: %v", err)
	}
	if resp.GetCpuCores() < 1 {
		t.Fatalf("cpu_cores = %d, want >= 1", resp.GetCpuCores())
	}
}

func TestAddClientRejectsBadJSON(t *testing.T) {
	client := newTestClient(t)
	_, err := client.AddClient(bearerContext(t), &panelapi.AddClientRequest{PayloadJson: "{not json"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestStreamClientTrafficUnauthenticated(t *testing.T) {
	client := newTestClient(t)
	stream, err := client.StreamClientTraffic(context.Background(), &panelapi.StreamClientTrafficRequest{})
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
}
