package xray

// WireGuardPeerTraffic represents peer-level traffic exposed by the patched
// Xray WireGuard inbound stats provider.
type WireGuardPeerTraffic struct {
	InboundTag string
	PublicKey  string
	Up         int64
	Down       int64
}
