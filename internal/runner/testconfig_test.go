package runner

import (
	"encoding/json"
	"reflect"
	"testing"
)

func decodeJSON(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("decoding %s: %v", b, err)
	}
	return v
}

func TestTestConfigRenamesTunInbounds(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{
			"the M1 client config",
			`{"log": {"loglevel": "warning"}, "api": {"tag": "api", "listen": "127.0.0.1:10085"},
			  "inbounds": [
			    {"tag": "tun-in", "protocol": "tun", "settings": {"name": "xray0", "MTU": 1500}, "sniffing": {"enabled": true}},
			    {"tag": "dns-in", "port": 53, "protocol": "dokodemo-door", "settings": {"address": "203.0.113.53", "port": 53}}
			  ],
			  "outbounds": [{"protocol": "freedom"}]}`,
			`{"log": {"loglevel": "warning"}, "api": {"tag": "api", "listen": "127.0.0.1:10085"},
			  "inbounds": [
			    {"tag": "tun-in", "protocol": "tun", "settings": {"name": "xray-test0", "MTU": 1500}, "sniffing": {"enabled": true}},
			    {"tag": "dns-in", "port": 53, "protocol": "dokodemo-door", "settings": {"address": "203.0.113.53", "port": 53}}
			  ],
			  "outbounds": [{"protocol": "freedom"}]}`,
		},
		{
			"two TUN inbounds",
			`{"inbounds": [{"protocol": "tun", "settings": {"name": "a"}}, {"protocol": "tun", "settings": {"name": "b"}}]}`,
			`{"inbounds": [{"protocol": "tun", "settings": {"name": "xray-test0"}}, {"protocol": "tun", "settings": {"name": "xray-test1"}}]}`,
		},
		{
			// xray reads keys and the protocol without regard to case.
			"keys in another case",
			`{"Inbounds": [{"Protocol": "TUN", "Settings": {"Name": "xray0", "NAME": "xray1", "mtu": 1500}}]}`,
			`{"Inbounds": [{"Protocol": "TUN", "Settings": {"name": "xray-test0", "mtu": 1500}}]}`,
		},
		{
			// The device then gets xray's default name, which may be xray0.
			"TUN inbound without settings",
			`{"inbounds": [{"protocol": "tun"}]}`,
			`{"inbounds": [{"protocol": "tun", "settings": {"name": "xray-test0"}}]}`,
		},
		{
			"TUN inbound with null settings",
			`{"inbounds": [{"protocol": "tun", "settings": null}]}`,
			`{"inbounds": [{"protocol": "tun", "settings": {"name": "xray-test0"}}]}`,
		},
		{
			"numbers keep their text",
			`{"inbounds": [{"protocol": "tun", "settings": {"name": "xray0"}}], "policy": {"levels": {"0": {"bufferSize": 12345678901234567890, "connIdle": 1.50}}}}`,
			`{"inbounds": [{"protocol": "tun", "settings": {"name": "xray-test0"}}], "policy": {"levels": {"0": {"bufferSize": 12345678901234567890, "connIdle": 1.50}}}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, changed := testConfig([]byte(tt.in))
			if !changed {
				t.Fatalf("testConfig(%s) reported no change", tt.in)
			}
			if got, want := decodeJSON(t, out), decodeJSON(t, []byte(tt.want)); !reflect.DeepEqual(got, want) {
				t.Errorf("testConfig(%s)\n = %s\nwant %s", tt.in, out, tt.want)
			}
		})
	}
}

func TestTestConfigKeepsNumbersExact(t *testing.T) {
	out, _ := testConfig([]byte(`{"inbounds": [{"protocol": "tun"}], "x": 12345678901234567890, "y": 1.50}`))
	var got map[string]json.RawMessage
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if string(got["x"]) != "12345678901234567890" || string(got["y"]) != "1.50" {
		t.Errorf("numbers became %s and %s, want 12345678901234567890 and 1.50", got["x"], got["y"])
	}
}

func TestTestConfigLeavesOthersAlone(t *testing.T) {
	// Each of these is returned as it is, for xray to judge: there is no TUN
	// inbound to rename, or the config is not what the rename understands.
	for _, in := range []string{
		`{}`,
		`{"inbounds": [{"protocol": "socks", "settings": {"name": "xray0"}}]}`,
		`{"outbounds": [{"protocol": "tun"}]}`,
		`not json`,
		`{"inbounds": [{"protocol": "tun"}]} {"trailing": true}`,
		`// a comment, which xray allows
		{"inbounds": [{"protocol": "tun"}]}`,
		`[{"inbounds": [{"protocol": "tun"}]}]`,
		`{"inbounds": {"protocol": "tun"}}`,
		`{"inbounds": ["tun"]}`,
		`{"inbounds": [{"protocol": "tun", "settings": "xray0"}]}`,
		`{"inbounds": [{"protocol": 7, "settings": {"name": "xray0"}}]}`,
		``,
	} {
		out, changed := testConfig([]byte(in))
		if changed || string(out) != in {
			t.Errorf("testConfig(%q) = %q, changed %v; want it unchanged", in, out, changed)
		}
	}
}
