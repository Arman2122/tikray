package runnerapi

import (
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"
)

// xrayRefusals are what xray printed when "xray run -test" refused a config
// (exit status 23), captured from the releases named, for the configs in
// which an outbound has: a legacy VLESS flow (flow), no TLS to a public
// address (plainvless, plainvlessdomain, plaintrojan), allowInsecure, a bad
// REALITY key, an unknown uTLS fingerprint, an unknown transport or security,
// an unknown protocol, an unknown Shadowsocks method, an empty password, a
// Shadowsocks 2022 key that is not base64, an unknown VLESS encryption, port
// 0, port 70000, a port that is a string, an address that is a number, a
// VLESS id that is not a UUID, JSON cut short, JSON with a missing comma,
// users that are an object, and Hysteria version 1. Only the config file's
// path was changed, to the runner's.
var xrayRefusals = []struct {
	xray, config, tag, category, output string
}{
	{xray: "26.10.21", config: "flow", tag: "srv-deadbeef", category: "unsupported flow", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-deadbeef > infra/conf: failed to build outbound handler for protocol vless > infra/conf: VLESS users: \"flow\" doesn't support \"xtls-rprx-direct\" in this version\n"},
	{xray: "26.1.18", config: "flow", tag: "srv-deadbeef", category: "unsupported flow", output: "Xray 26.1.18 (Xray, Penetrates Everything.) Custom (go1.25.6 linux/amd64)\nA unified platform for anti-censorship.\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-deadbeef > infra/conf: failed to build outbound handler for protocol vless > infra/conf: VLESS users: \"flow\" doesn't support \"xtls-rprx-direct\" in this version\n"},
	{xray: "26.10.21", config: "plainvless", tag: "srv-0000beef", category: "transport needs TLS or encryption", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:27.965353 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-0000beef > infra/conf: vless without TLS or other encryption is prohibited unless the server address is a private IP or domain\n"},
	{xray: "26.9.30", config: "plainvlessdomain", tag: "srv-0000beef", category: "transport needs TLS or encryption", output: "Xray 26.9.30 (Xray, Penetrates Everything.) b26a91d (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:27.929312 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-0000beef > infra/conf: vless without TLS or other encryption is prohibited unless the server address is a private IP or domain\n"},
	{xray: "26.10.21", config: "plaintrojan", tag: "srv-1234abcd", category: "transport needs TLS or encryption", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:27.996338 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\n2026/11/05 16:34:27.997060 [Warning] common/errors: The feature Trojan (with no Flow, etc.) is deprecated, not recommended for using and might be removed. Please migrate to VLESS with Flow & Seed as soon as possible.\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-1234abcd > infra/conf: trojan without TLS is prohibited unless the server address is a private IP or domain\n"},
	{xray: "26.10.21", config: "insecure", tag: "srv-0000cafe", category: "allowInsecure refused", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:17.491406 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-0000cafe > infra/conf: failed to build stream settings for outbound detour > infra/conf: Failed to build TLS config. > common/errors: The feature \"allowInsecure\" has been removed and migrated to \"pinnedPeerCertSha256\"(pcs) and \"verifyPeerCertByName\"(vcn). Please update your config(s) according to release note and documentation.\n"},
	{xray: "26.10.21", config: "reality", tag: "srv-00001111", category: "invalid TLS or REALITY settings", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:17.767891 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-00001111 > infra/conf: failed to build stream settings for outbound detour > infra/conf: Failed to build REALITY config. > infra/conf: invalid \"password\": fixture-bad-public-key\n"},
	{xray: "26.1.18", config: "fp", tag: "srv-00006666", category: "invalid TLS or REALITY settings", output: "Xray 26.1.18 (Xray, Penetrates Everything.) Custom (go1.25.6 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:16.980379 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-00006666 > infra/conf: failed to build stream settings for outbound detour > infra/conf: Failed to build TLS config. > infra/conf: unknown \"fingerprint\": fixturefp\n"},
	{xray: "26.10.21", config: "network", tag: "srv-00002222", category: "unsupported transport or security", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:17.540832 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-00002222 > infra/conf: failed to build stream settings for outbound detour > infra/conf: Config: unknown transport protocol: fixturenet\n"},
	{xray: "26.10.21", config: "security", tag: "srv-00003333", category: "unsupported transport or security", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:17.787794 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-00003333 > infra/conf: failed to build stream settings for outbound detour > infra/conf: Unknown security \"fixturesec\".\n"},
	{xray: "26.10.21", config: "proto", tag: "srv-00000f0f", category: "unknown protocol", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:17.741921 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-00000f0f > infra/conf: failed to load outbound detour config for protocol fixtureproto > infra/conf: unknown config id: fixtureproto\n"},
	{xray: "26.10.21", config: "ssmethod", tag: "srv-0000bbbb", category: "unsupported cipher", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:17.837410 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-0000bbbb > infra/conf: failed to build outbound handler for protocol shadowsocks > infra/conf: unknown cipher method: fixture-cipher\n"},
	{xray: "26.10.21", config: "sspass", tag: "srv-0000cccc", category: "missing or invalid password", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:17.865674 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-0000cccc > infra/conf: failed to build outbound handler for protocol shadowsocks > infra/conf: Shadowsocks password is not specified.\n"},
	{xray: "26.10.21", config: "trojanpass", tag: "srv-0000eeee", category: "missing or invalid password", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:17.896619 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\n2026/11/05 16:34:17.897995 [Warning] common/errors: The feature Trojan (with no Flow, etc.) is deprecated, not recommended for using and might be removed. Please migrate to VLESS with Flow & Seed as soon as possible.\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-0000eeee > infra/conf: failed to build outbound handler for protocol trojan > infra/conf: Trojan password is not specified.\n"},
	{xray: "26.10.21", config: "ss2022", tag: "", category: "missing or invalid password", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:17.814087 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\n2026/11/05 16:34:17.815065 [Warning] common/errors: The feature Shadowsocks (with no Forward Secrecy, etc.) is deprecated, not recommended for using and might be removed. Please migrate to VLESS Encryption as soon as possible.\nFailed to start: main: failed to create server > proxy/shadowsocks_2022: invalid key: fixture-not-base64!! > proxy/shadowsocks_2022: bad key\n"},
	{xray: "26.1.18", config: "ss2022", tag: "", category: "missing or invalid password", output: "Xray 26.1.18 (Xray, Penetrates Everything.) Custom (go1.25.6 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:17.235689 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\n2026/11/05 16:34:17.237652 [Warning] common/errors: This feature Shadowsocks is deprecated and being migrated to VLESS Encryption. Please update your config(s) according to release note and documentation before removal.\nFailed to start: main: failed to create server > proxy/shadowsocks_2022: create method > decode key: illegal base64 data at input byte 7\n"},
	{xray: "26.10.21", config: "vlessenc", tag: "srv-00004444", category: "unsupported VLESS encryption", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:17.919736 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-00004444 > infra/conf: failed to build outbound handler for protocol vless > infra/conf: VLESS users: unsupported \"encryption\": fixture-enc-secret\n"},
	{xray: "26.10.21", config: "port0", tag: "srv-00000a0a", category: "invalid port or address", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:17.660249 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-00000a0a > infra/conf: failed to build outbound handler for protocol trojan > infra/conf: Invalid Trojan port.\n"},
	{xray: "26.10.21", config: "portbig", tag: "srv-00000b0b", category: "invalid port or address", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:17.687740 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-00000b0b > infra/conf: failed to load outbound detour config for protocol vless > json: cannot unmarshal number 70000 into Go struct field VLessOutboundConfig.vnext.0.port of type uint16\n"},
	{xray: "26.1.18", config: "portstr", tag: "srv-00000c0c", category: "invalid port or address", output: "Xray 26.1.18 (Xray, Penetrates Everything.) Custom (go1.25.6 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:17.168608 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-00000c0c > infra/conf: failed to load outbound detour config for protocol vless > json: cannot unmarshal string into Go struct field VLessOutboundVnext.vnext.port of type uint16\n"},
	{xray: "26.10.21", config: "badaddr", tag: "srv-00000e0e", category: "invalid port or address", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:17.380324 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-00000e0e > infra/conf: failed to load outbound detour config for protocol vless > infra/conf: invalid address: 12345 > json: cannot unmarshal number into Go value of type string\n"},
	{xray: "26.10.21", config: "baduuid", tag: "srv-0badc0de", category: "invalid user", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:17.407192 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-0badc0de > infra/conf: failed to build outbound handler for protocol vless > common/uuid: invalid UUID: fixture-secret-not-a-uuid-but-long-enough-to-hash-31\n"},
	{xray: "26.10.21", config: "json", tag: "", category: "invalid JSON", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf/serial: failed to decode config: &{Name:/data/run/.test-1234/config.json Format:json} > infra/conf/serial: failed to read config file > unexpected EOF\n"},
	{xray: "26.1.18", config: "jsonsyntax", tag: "", category: "invalid JSON", output: "Xray 26.1.18 (Xray, Penetrates Everything.) Custom (go1.25.6 linux/amd64)\nA unified platform for anti-censorship.\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf/serial: failed to decode config: &{Name:/data/run/.test-1234/config.json Format:json} > infra/conf/serial: failed to read config file at line 1 char 150 > invalid character '\"' after object key:value pair\n"},
	{xray: "26.10.21", config: "jsontype", tag: "srv-0000aaac", category: "", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:38.298444 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-0000aaac > infra/conf: failed to load outbound detour config for protocol vless > json: cannot unmarshal object into Go struct field VLessOutboundConfig.vnext.0.users of type []jsontext.Value\n"},
	{xray: "26.10.21", config: "hysteria", tag: "srv-00005555", category: "", output: "Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.0 linux/amd64)\nA unified platform for anti-censorship.\n2026/11/05 16:34:17.470105 [Info] infra/conf/serial: Reading config: &{Name:/data/run/.test-1234/config.json Format:json}\nFailed to start: main: failed to load config files: [/data/run/.test-1234/config.json] > infra/conf: failed to build outbound config with tag srv-00005555 > infra/conf: failed to build outbound handler for protocol hysteria > infra/conf: version != 2\n"},
}

// xraySecrets are the fixture credentials and other private values of those
// configs that xray quotes when it refuses them.
var xraySecrets = []string{
	"11111111-2222-4333-8444-555555555555",
	"fixture-secret-not-a-uuid-but-long-enough-to-hash-31",
	"fixture-trojan-pass", "fixture-port-secret", "fixture-json-secret", "fixture-ss-pass",
	"fixture-not-base64", "fixture-bad-public-key", "fixture-enc-secret", "fixture-cipher",
	"fixtureproto", "fixturenet", "fixturesec", "fixturefp", "xtls-rprx-direct",
	"fixture-host.example.com", "example.com", "8.8.4.4", "12345", "70000", "/data/run",
}

// wantPublic fails when text holds anything of xraySecrets.
func wantPublic(t *testing.T, text string) {
	t.Helper()
	for _, s := range xraySecrets {
		if strings.Contains(text, s) {
			t.Errorf("%q repeats %q", text, s)
		}
	}
}

// An older runner sent what xray printed, which the client still reduces to
// the tags and a category.
func TestPublicRefusalOfRealXrayOutput(t *testing.T) {
	for _, tc := range xrayRefusals {
		t.Run(tc.xray+"/"+tc.config, func(t *testing.T) {
			want := tc.category
			if want == "" {
				want = "xray failed to load config"
			}
			if tc.tag != "" {
				want = "outbound " + tc.tag + ": " + want
			}
			got := publicRefusal(tc.output)
			if got != want {
				t.Errorf("publicRefusal = %q, want %q", got, want)
			}
			wantPublic(t, got)
		})
	}
}

// The runner reads xray's refusal itself and passes on only the tags and a
// category, which the client keeps as they are.
func TestConfigRefusalOfRealXrayOutput(t *testing.T) {
	for _, tc := range xrayRefusals {
		t.Run(tc.xray+"/"+tc.config, func(t *testing.T) {
			want := tc.category
			if want == "" {
				want = "invalid config"
			}
			if tc.tag != "" {
				want = "outbound " + tc.tag + ": " + want
			}
			want = "xray rejected the config: " + want
			got := ConfigRefusal(tc.output)
			if got != want {
				t.Errorf("ConfigRefusal = %q, want %q", got, want)
			}
			wantPublic(t, got)
			if !publicRefusalRE.MatchString(got) || publicRefusal(got) != got {
				t.Errorf("the client would not keep %q as it is", got)
			}
		})
	}
}

func TestConfigRefusalTags(t *testing.T) {
	const chain = "Failed to start: main: failed to load config files: [c.json] > infra/conf: "
	for _, tc := range []struct{ name, output, want string }{
		{"none", chain + "failed to build outbound handler", "xray rejected the config: invalid config"},
		{"one", chain + "failed to build outbound config with tag srv-0123abcd > infra/conf: x",
			"xray rejected the config: outbound srv-0123abcd: invalid config"},
		{"at the end", chain + "failed to build outbound config with tag srv-0123abcd",
			"xray rejected the config: outbound srv-0123abcd: invalid config"},
		{"repeated, with others, at most four", chain +
			"failed to build outbound config with tag srv-00000001 > failed to build outbound config with tag srv-00000001\n" +
			"failed to build outbound config with tag srv-00000002 > failed to build outbound config with tag srv-00000003 >" +
			"failed to build outbound config with tag srv-00000004\nfailed to build outbound config with tag srv-00000005",
			"xray rejected the config: outbound srv-00000001, srv-00000002, srv-00000003, srv-00000004: invalid config"},
		{"not a server's", chain + "failed to build outbound config with tag direct > x", "xray rejected the config: invalid config"},
		{"longer than a server's", chain + "failed to build outbound config with tag srv-0123abcdef > x", "xray rejected the config: invalid config"},
		{"followed by more", chain + "failed to build outbound config with tag srv-0123abcd-private > x", "xray rejected the config: invalid config"},
		{"in capitals", chain + "failed to build outbound config with tag srv-0123ABCD > x", "xray rejected the config: invalid config"},
		{"an inbound's", chain + "failed to build inbound config with tag srv-0123abcd > x", "xray rejected the config: invalid config"},
		{"only xray's last line", "failed to build outbound config with tag srv-00000009\n" + chain + "unknown config id: x",
			"xray rejected the config: unknown protocol"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ConfigRefusal(tc.output); got != tc.want {
				t.Errorf("ConfigRefusal = %q, want %q", got, tc.want)
			}
		})
	}
}

// What xray warns of before "Failed to start:" is not why it refused.
func TestConfigRefusalReadsOnlyXraysReason(t *testing.T) {
	output := "2026/11/05 16:34:17 [Warning] common/errors: This feature VLESS without flow is deprecated and being migrated to VLESS with flow.\n" +
		"2026/11/05 16:34:17 [Warning] common/errors: invalid user 11111111-2222-4333-8444-555555555555 is deprecated, \"flow\" doesn't support\n" +
		"Failed to start: main: failed to load config files: [c.json] > infra/conf: failed to build outbound config with tag srv-00000f0f > " +
		"infra/conf: failed to load outbound detour config for protocol x > infra/conf: unknown config id: x\n"
	if got, want := ConfigRefusal(output), "xray rejected the config: outbound srv-00000f0f: unknown protocol"; got != want {
		t.Errorf("ConfigRefusal = %q, want %q", got, want)
	}
}

// Whatever xray prints, and whatever of the config it quotes, a refusal is
// made of fixed words and srv- tags only.
func TestConfigRefusalNeverQuotesTheConfig(t *testing.T) {
	credentials := append([]string{
		"b831381d-6324-4d53-ad4f-8cda48b30811", "fixture pass with spaces", "fixture\"quoted\\pass", "fixture>pass\nnext",
		"srv-fixture", "srv-0123abcd-fixture", "fixture-srv-0123abc", "ss://fixture@host:1/", "vless://fixture@host",
		"ünicøde-fixture", "Failed to start: fixture", "with tag fixture", "%2Ffixture%40", "fixture\u0000x",
	}, xraySecrets...)
	words := []string{
		"Failed to start: ", "main: failed to load config files: [", "] > ", " > ", "infra/conf: ", "\n",
		"failed to build outbound config with tag ", "failed to build outbound config with tag srv-", "failed to build outbound handler for protocol ",
		"srv-deadbeef", "srv-0000cafe", "srv-", " ", ": ", "\"", "VLESS users: \"flow\" doesn't support \"", "\" in this version",
		"invalid UUID: ", "unknown config id: ", "trojan without TLS is prohibited", "The feature \"allowInsecure\" has been removed",
		"Failed to build REALITY config.", "invalid \"password\": ", "unknown cipher method: ", "invalid address: ", "json: cannot unmarshal ",
		"failed to read config file at line 1 char 9", "[Warning] common/errors: ", "Xray 26.10.21 (Xray, Penetrates Everything.)\n",
	}
	for _, tc := range xrayRefusals {
		words = append(words, tc.output)
	}
	rng := rand.New(rand.NewPCG(26, 1031))
	tagged, categories := 0, map[string]bool{}
	for i := range 20000 {
		var b strings.Builder
		for range 1 + rng.IntN(24) {
			if rng.IntN(3) == 0 {
				b.WriteString(credentials[rng.IntN(len(credentials))])
			} else {
				b.WriteString(words[rng.IntN(len(words))])
			}
		}
		output := b.String()
		tags, category := classifyRefusal(output)
		if len(tags) > 0 {
			tagged++
		}
		categories[category] = true
		for _, got := range []string{ConfigRefusal(output), publicRefusal(output)} {
			if !publicRefusalRE.MatchString(got) {
				t.Fatalf("case %d: %q is not a fixed refusal; output %q", i, got, output)
			}
			for _, c := range credentials {
				if strings.Contains(got, c) {
					t.Fatalf("case %d: %q quotes %q; output %q", i, got, c, output)
				}
			}
			for _, tag := range regexp.MustCompile(`srv-[0-9a-f]{8}`).FindAllString(got, -1) {
				if !strings.Contains(output, "failed to build outbound config with tag "+tag) {
					t.Fatalf("case %d: %q names %s, which xray did not; output %q", i, got, tag, output)
				}
			}
		}
	}
	// The cases must reach what they test.
	if tagged < 1000 || len(categories) < len(refusalRules) {
		t.Errorf("%d cases with a tag and %d categories of %d; the cases are too tame", tagged, len(categories), len(refusalRules)+1)
	}
}

// Every category can be told apart by the client.
func TestRefusalCategoriesAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range refusalRules {
		if seen[r.category] {
			t.Errorf("category %q twice", r.category)
		}
		seen[r.category] = true
		for _, text := range []string{r.category, refusalPrefix + r.category, fmt.Sprintf("%soutbound srv-0123abcd: %s", refusalPrefix, r.category)} {
			if !publicRefusalRE.MatchString(text) || publicRefusal(text) != text {
				t.Errorf("the client would not keep %q as it is", text)
			}
		}
	}
}
