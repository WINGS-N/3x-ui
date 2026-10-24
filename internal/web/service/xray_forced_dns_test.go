package service

import (
	"encoding/json"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/util/json_util"
	"github.com/mhsanaei/3x-ui/v3/internal/xray"
)

// forcedDNSConfig is a generated config as the injection finds it: one template
// outbound and one rule that pins the inbound to its egress.
func forcedDNSConfig() *xray.Config {
	return &xray.Config{
		OutboundConfigs: json_util.RawMessage(`[{"tag":"direct","protocol":"freedom"}]`),
		RouterConfig:    json_util.RawMessage(`{"rules":[{"type":"field","inboundTag":["in-wg"],"outboundTag":"warp"}]}`),
	}
}

func forcedDNSInbound(settings string) *model.Inbound {
	return &model.Inbound{Tag: "in-wg", Protocol: model.WireGuard, Settings: settings}
}

// The resolver of the settings takes the DNS of the inbound, and the rule that
// does it comes before the one that pins the inbound to its egress.
func TestInjectInboundForcedDNS(t *testing.T) {
	cfg := forcedDNSConfig()
	injectInboundForcedDNS(cfg, forcedDNSInbound(`{"forcedDns":"9.9.9.9","outboundTag":"warp"}`))

	var outbounds []map[string]any
	if err := json.Unmarshal(cfg.OutboundConfigs, &outbounds); err != nil {
		t.Fatal(err)
	}
	if len(outbounds) != 2 {
		t.Fatalf("outbounds: got %d, want the template one plus ours", len(outbounds))
	}
	added := outbounds[1]
	if added["tag"] != "forced-dns-in-wg" || added["protocol"] != "freedom" {
		t.Fatalf("the added outbound is %v", added)
	}
	settings, _ := added["settings"].(map[string]any)
	if settings["redirect"] != "9.9.9.9:53" {
		t.Fatalf("the resolver is %v, want it with the dns port", settings["redirect"])
	}

	var routing struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(cfg.RouterConfig, &routing); err != nil {
		t.Fatal(err)
	}
	if len(routing.Rules) != 2 {
		t.Fatalf("rules: got %d, want ours plus the one that was there", len(routing.Rules))
	}
	first := routing.Rules[0]
	if first["outboundTag"] != "forced-dns-in-wg" {
		t.Fatalf("the first rule goes to %v, want ours", first["outboundTag"])
	}
	if first["port"] != "53" || first["network"] != "udp,tcp" {
		t.Fatalf("the first rule matches %v on %v, want the dns port on both networks", first["port"], first["network"])
	}
	if routing.Rules[1]["outboundTag"] != "warp" {
		t.Fatal("the rule that was there must stay after ours")
	}
}

// A resolver that already carries a port keeps it.
func TestInjectInboundForcedDNSKeepsThePort(t *testing.T) {
	cfg := forcedDNSConfig()
	injectInboundForcedDNS(cfg, forcedDNSInbound(`{"forcedDns":"9.9.9.9:5353"}`))

	var outbounds []map[string]any
	if err := json.Unmarshal(cfg.OutboundConfigs, &outbounds); err != nil {
		t.Fatal(err)
	}
	settings, _ := outbounds[1]["settings"].(map[string]any)
	if settings["redirect"] != "9.9.9.9:5353" {
		t.Fatalf("the resolver is %v, want the port it was given", settings["redirect"])
	}
}

// Nothing is touched without a resolver, by a second pass, or by a resolver
// that is not an address.
func TestInjectInboundForcedDNSLeavesTheConfigAlone(t *testing.T) {
	for _, test := range []struct{ name, settings string }{
		{"no resolver", `{"outboundTag":"warp"}`},
		{"empty resolver", `{"forcedDns":"  "}`},
		{"a domain", `{"forcedDns":"dns.quad9.net"}`},
		{"unparsable settings", `not json`},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := forcedDNSConfig()
			before := forcedDNSConfig()
			injectInboundForcedDNS(cfg, forcedDNSInbound(test.settings))
			if string(cfg.OutboundConfigs) != string(before.OutboundConfigs) {
				t.Fatalf("outbounds changed: %s", cfg.OutboundConfigs)
			}
			if string(cfg.RouterConfig) != string(before.RouterConfig) {
				t.Fatalf("routing changed: %s", cfg.RouterConfig)
			}
		})
	}

	// twice over the same config adds one outbound and one rule, not two
	cfg := forcedDNSConfig()
	inbound := forcedDNSInbound(`{"forcedDns":"9.9.9.9"}`)
	injectInboundForcedDNS(cfg, inbound)
	once := string(cfg.OutboundConfigs)
	injectInboundForcedDNS(cfg, inbound)
	if string(cfg.OutboundConfigs) != once {
		t.Fatalf("a second pass added another outbound: %s", cfg.OutboundConfigs)
	}
}

// An inbound with no tag has nothing to match on.
func TestInjectInboundForcedDNSNeedsATag(t *testing.T) {
	cfg := forcedDNSConfig()
	before := string(cfg.RouterConfig)
	injectInboundForcedDNS(cfg, &model.Inbound{Protocol: model.WireGuard, Settings: `{"forcedDns":"9.9.9.9"}`})
	if string(cfg.RouterConfig) != before {
		t.Fatalf("routing changed for an inbound without a tag: %s", cfg.RouterConfig)
	}
}
