package service

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"io"
	"strings"
	"testing"

	wingsvproto "github.com/mhsanaei/3x-ui/v2/wingsv/proto"
	"google.golang.org/protobuf/proto"
)

func TestEncodeVKTurnProxyConfigUsesWingsVZlibFormat(t *testing.T) {
	expected := &wingsvproto.Config{
		Ver:     vkTurnProxyCurrentVersion,
		Type:    wingsvproto.ConfigType_CONFIG_TYPE_VK,
		Backend: wingsvproto.BackendType_BACKEND_TYPE_VK_TURN_WIREGUARD,
		Turn: &wingsvproto.Turn{
			Endpoint: &wingsvproto.Endpoint{
				Host: "203.0.113.10",
				Port: 56000,
			},
			Link: "https://vk.com/call/join/test",
		},
		Wg: &wingsvproto.WireGuard{
			Iface: &wingsvproto.Interface{
				PrivateKey: bytes.Repeat([]byte{0x11}, 32),
				Addrs:      []string{"10.0.0.2/32"},
				Dns:        []string{"1.1.1.1"},
			},
			Peer: &wingsvproto.Peer{
				PublicKey: bytes.Repeat([]byte{0x22}, 32),
				AllowedIps: []*wingsvproto.Cidr{
					{
						Addr:   []byte{0, 0, 0, 0},
						Prefix: 0,
					},
				},
			},
		},
	}

	link, err := encodeVKTurnProxyConfig(expected)
	if err != nil {
		t.Fatalf("encode config: %v", err)
	}
	if !strings.HasPrefix(link, vkTurnProxySchemePrefix) {
		t.Fatalf("expected %q prefix, got %q", vkTurnProxySchemePrefix, link)
	}

	payload, err := base64.URLEncoding.DecodeString(strings.TrimPrefix(link, vkTurnProxySchemePrefix))
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if len(payload) == 0 || payload[0] != vkTurnProxyFormatProtoDeflate {
		t.Fatalf("unexpected payload framing: %v", payload)
	}

	reader, err := zlib.NewReader(bytes.NewReader(payload[1:]))
	if err != nil {
		t.Fatalf("open zlib reader: %v", err)
	}
	defer reader.Close()

	protobufPayload, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("inflate payload: %v", err)
	}

	actual := &wingsvproto.Config{}
	if err := proto.Unmarshal(protobufPayload, actual); err != nil {
		t.Fatalf("unmarshal proto: %v", err)
	}
	if !proto.Equal(actual, expected) {
		t.Fatalf("decoded config mismatch:\nexpected: %v\nactual: %v", expected, actual)
	}
}
