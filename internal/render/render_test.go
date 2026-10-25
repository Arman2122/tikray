package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/store"
)

// realityOutbound is the VLESS Reality outbound that sharelink builds from
// Task 3's "reality and vision" link.
const realityOutbound = `{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.10","port":443,"users":[{"encryption":"none","flow":"xtls-rprx-vision","id":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}]},"streamSettings":{"network":"tcp","realitySettings":{"fingerprint":"chrome","publicKey":"SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc","serverName":"www.example.com","shortId":"6ba85179e30d4fc2"},"security":"reality"}}`

// The server IDs the tests use.
const (
	idA = "a1b2c3d4"
	idB = "0badf00d"
)

// testCore is the core every test renders for unless it says otherwise.
var testCore = version(26, 10, 21)

// testServer is a server holding realityOutbound.
func testServer(id string, disabled bool) store.Server {
	return store.Server{ID: id, Name: "server " + id, Disabled: disabled, Outbound: json.RawMessage(realityOutbound)}
}

// smart is the default state with the default policy smart and the given
// servers.
func smart(servers ...store.Server) store.State {
	st := store.Default()
	st.DefaultPolicy = store.Policy{Mode: store.ModeSmart}
	st.Servers = append([]store.Server{}, servers...)
	return st
}

// pinned is st with the server id pinned.
func pinned(st store.State, id string) store.State {
	st.Routing.Pinned = id
	return st
}

// output is the part of a rendered config the tests read.
type output struct {
	Log         json.RawMessage   `json:"log"`
	API         json.RawMessage   `json:"api"`
	Stats       json.RawMessage   `json:"stats"`
	Policy      json.RawMessage   `json:"policy"`
	DNS         json.RawMessage   `json:"dns"`
	Inbounds    []json.RawMessage `json:"inbounds"`
	Outbounds   []json.RawMessage `json:"outbounds"`
	Observatory json.RawMessage   `json:"observatory"`
	Routing     struct {
		Rules     []json.RawMessage `json:"rules"`
		Balancers json.RawMessage   `json:"balancers"`
	} `json:"routing"`
}

// mustRender renders st for testCore with no geo and decodes the result.
func mustRender(t *testing.T, st store.State) (output, []byte) {
	t.Helper()
	return mustRenderInput(t, Input{State: st, Core: testCore})
}

// mustRenderInput renders in and decodes the result.
func mustRenderInput(t *testing.T, in Input) (output, []byte) {
	t.Helper()
	b, err := Render(in)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var out output
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("Render gave invalid JSON: %v\n%s", err, b)
	}
	return out, b
}

// jsonEqual fails the test unless got and want hold the same JSON value.
func jsonEqual(t *testing.T, what string, got json.RawMessage, want string) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("%s: invalid JSON %s: %v", what, got, err)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("%s: the test's own JSON %s is invalid: %v", what, want, err)
	}
	if !reflect.DeepEqual(g, w) {
		gc, _ := json.Marshal(g)
		wc, _ := json.Marshal(w)
		t.Fatalf("%s:\n got %s\nwant %s", what, gc, wc)
	}
}

// field returns the string at key in the JSON object raw, or "" if there is
// none.
func field(t *testing.T, raw json.RawMessage, key string) string {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("not a JSON object: %s", raw)
	}
	var s string
	if v, ok := obj[key]; ok {
		if err := json.Unmarshal(v, &s); err != nil {
			t.Fatalf("%s is not a string in %s", key, raw)
		}
	}
	return s
}

// tags returns the tag of each object in list.
func tags(t *testing.T, list []json.RawMessage) []string {
	t.Helper()
	var out []string
	for _, raw := range list {
		out = append(out, field(t, raw, "tag"))
	}
	return out
}

// withTag returns the outbound JSON raw with tag added.
func withTag(t *testing.T, raw, tag string) string {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		t.Fatal(err)
	}
	obj["tag"] = tag
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// serviceRules are the five rules every config starts with, for tikray at
// tikray and the runner at runner, with socks4 as the target of rule 4.
func serviceRules(tikray, runner, socks4 string) []string {
	return []string{
		`{"inboundTag":["api-in"],"source":["` + tikray + `/32","` + runner + `/32"],"outboundTag":"api"}`,
		`{"inboundTag":["api-in"],"outboundTag":"block"}`,
		`{"inboundTag":["dns-in"],"outboundTag":"dns-out"}`,
		`{"inboundTag":["socks-in"],"source":["` + tikray + `/32"],` + socks4 + `}`,
		`{"inboundTag":["socks-in"],"outboundTag":"block"}`,
	}
}

// checkServiceRules checks that rules starts with want. Task 7 appends its
// rules after them, so only the prefix is checked.
func checkServiceRules(t *testing.T, rules []json.RawMessage, want []string) {
	t.Helper()
	if len(rules) < len(want) {
		t.Fatalf("routing.rules has %d rules, want at least the %d service rules", len(rules), len(want))
	}
	for i, w := range want {
		jsonEqual(t, fmt.Sprintf("routing.rules[%d]", i), rules[i], w)
	}
}

func TestProxyAvailable(t *testing.T) {
	tests := []struct {
		name string
		st   store.State
		want bool
	}{
		{"no servers", smart(), false},
		{"one disabled server", smart(testServer(idA, true)), false},
		{"one enabled server", smart(testServer(idA, false)), true},
		{"pinned to a disabled server while another is enabled", pinned(smart(testServer(idA, true), testServer(idB, false)), idA), false},
		{"pinned to an enabled server", pinned(smart(testServer(idA, false), testServer(idB, false)), idA), true},
		{"pinned to an enabled server beside a disabled one", pinned(smart(testServer(idB, true), testServer(idA, false)), idA), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ProxyAvailable(tt.st); got != tt.want {
				t.Fatalf("ProxyAvailable = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRenderSkeleton(t *testing.T) {
	out, b := mustRender(t, smart(testServer(idA, false)))

	// The output is canonical: MarshalIndent with two spaces, and a newline.
	var compact, canonical bytes.Buffer
	if err := json.Compact(&compact, b); err != nil {
		t.Fatal(err)
	}
	if err := json.Indent(&canonical, compact.Bytes(), "", "  "); err != nil {
		t.Fatal(err)
	}
	canonical.WriteByte('\n')
	if !bytes.Equal(b, canonical.Bytes()) {
		t.Fatalf("output is not indented with two spaces and a trailing newline:\n%s", b)
	}

	jsonEqual(t, "log", out.Log, `{"loglevel":"warning"}`)
	jsonEqual(t, "api", out.API, `{"tag":"api","services":["HandlerService","RoutingService","StatsService","ObservatoryService"]}`)
	jsonEqual(t, "stats", out.Stats, `{}`)
	jsonEqual(t, "policy", out.Policy, `{"system":{"statsOutboundUplink":true,"statsOutboundDownlink":true}}`)

	inboundTags := []string{TagTUN, TagDNSIn, TagSOCKS, TagAPIIn}
	if got := tags(t, out.Inbounds); !slices.Equal(got, inboundTags) {
		t.Fatalf("inbound tags = %q, want %q", got, inboundTags)
	}
	wantInbounds := []string{
		`{"tag":"tun-in","protocol":"tun","settings":{"name":"xray0","mtu":1500},"sniffing":{"enabled":true,"destOverride":["http","tls","quic"],"routeOnly":true}}`,
		`{"tag":"dns-in","protocol":"dokodemo-door","listen":"172.31.255.3","port":53,"settings":{"address":"1.1.1.1","port":53,"network":"tcp,udp"}}`,
		`{"tag":"socks-in","protocol":"socks","listen":"172.31.255.3","port":1080,"settings":{"auth":"noauth","udp":false}}`,
		`{"tag":"api-in","protocol":"dokodemo-door","listen":"172.31.255.3","port":10085,"settings":{"address":"127.0.0.1"}}`,
	}
	for i, w := range wantInbounds {
		jsonEqual(t, "inbound "+inboundTags[i], out.Inbounds[i], w)
	}

	if got, want := tags(t, out.Outbounds), []string{TagBlock, TagDirect, TagDNSOut, "srv-" + idA}; !slices.Equal(got, want) {
		t.Fatalf("outbound tags = %q, want %q", got, want)
	}
	jsonEqual(t, "outbound block", out.Outbounds[0], `{"tag":"block","protocol":"blackhole"}`)
	jsonEqual(t, "outbound direct", out.Outbounds[1], `{"tag":"direct","protocol":"freedom"}`)
	jsonEqual(t, "outbound dns-out", out.Outbounds[2], `{"tag":"dns-out","protocol":"dns","settings":{"nonIPQuery":"reject"}}`)
	jsonEqual(t, "outbound srv-"+idA, out.Outbounds[3], withTag(t, realityOutbound, "srv-"+idA))

	jsonEqual(t, "observatory", out.Observatory,
		`{"subjectSelector":["srv-"],"probeURL":"https://www.gstatic.com/generate_204","probeInterval":"10s","enableConcurrency":true}`)
	jsonEqual(t, "routing.balancers", out.Routing.Balancers, `[
		{"tag":"proxy-open","selector":["srv-"],"strategy":{"type":"leastPing"},"fallbackTag":"direct"},
		{"tag":"proxy-closed","selector":["srv-"],"strategy":{"type":"leastPing"},"fallbackTag":"block"}]`)

	checkServiceRules(t, out.Routing.Rules, serviceRules("172.31.255.2", "172.31.255.3", `"balancerTag":"proxy-closed"`))

	for _, i := range []int{1, 2, 3} {
		if got := field(t, out.Inbounds[i], "listen"); got != "172.31.255.3" {
			t.Errorf("inbound %s listens on %q, want 172.31.255.3", field(t, out.Inbounds[i], "tag"), got)
		}
	}
}

func TestRenderNoServers(t *testing.T) {
	tests := []struct {
		name string
		st   store.State
		// wantServers are the server outbound tags still rendered.
		wantServers []string
	}{
		{"defaults", store.Default(), nil},
		{"smart, no servers", smart(), nil},
		{"only a disabled server", smart(testServer(idA, true)), nil},
		{"pinned to a disabled server", pinned(smart(testServer(idA, true), testServer(idB, false)), idA), []string{"srv-" + idB}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, b := mustRender(t, tt.st)
			if out.Observatory != nil {
				t.Errorf("observatory = %s, want none", out.Observatory)
			}
			if out.Routing.Balancers != nil {
				t.Errorf("routing.balancers = %s, want none", out.Routing.Balancers)
			}
			if bytes.Contains(b, []byte("balancerTag")) {
				t.Errorf("a rule still names a balancer:\n%s", b)
			}
			checkServiceRules(t, out.Routing.Rules, serviceRules("172.31.255.2", "172.31.255.3", `"outboundTag":"block"`))
			want := append([]string{TagBlock, TagDirect, TagDNSOut}, tt.wantServers...)
			if got := tags(t, out.Outbounds); !slices.Equal(got, want) {
				t.Fatalf("outbound tags = %q, want %q", got, want)
			}
		})
	}
}

// TestRenderObservatoryService checks that the API offers ObservatoryService
// exactly when the observatory is rendered: xray refuses to start a config
// whose ObservatoryService has no observatory ("not all dependencies are
// resolved").
func TestRenderObservatoryService(t *testing.T) {
	tests := []struct {
		name            string
		st              store.State
		wantObservatory bool
		wantServices    string
	}{
		{"no servers", smart(), false, `["HandlerService","RoutingService","StatsService"]`},
		{"pinned to a disabled server", pinned(smart(testServer(idA, true), testServer(idB, false)), idA), false, `["HandlerService","RoutingService","StatsService"]`},
		{"one enabled server", smart(testServer(idA, false)), true, `["HandlerService","RoutingService","StatsService","ObservatoryService"]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, _ := mustRender(t, tt.st)
			jsonEqual(t, "api", out.API, `{"tag":"api","services":`+tt.wantServices+`}`)
			if got := out.Observatory != nil; got != tt.wantObservatory {
				t.Fatalf("observatory rendered = %v, want %v", got, tt.wantObservatory)
			}
		})
	}
}

func TestRenderPinned(t *testing.T) {
	out, _ := mustRender(t, pinned(smart(testServer(idB, false), testServer(idA, false)), idA))
	sel := `["srv-` + idA + `"]`
	jsonEqual(t, "observatory", out.Observatory,
		`{"subjectSelector":`+sel+`,"probeURL":"https://www.gstatic.com/generate_204","probeInterval":"10s","enableConcurrency":true}`)
	jsonEqual(t, "routing.balancers", out.Routing.Balancers, `[
		{"tag":"proxy-open","selector":`+sel+`,"strategy":{"type":"leastPing"},"fallbackTag":"direct"},
		{"tag":"proxy-closed","selector":`+sel+`,"strategy":{"type":"leastPing"},"fallbackTag":"block"}]`)
	// The other server keeps its outbound: a custom rule may name it.
	if got, want := tags(t, out.Outbounds), []string{TagBlock, TagDirect, TagDNSOut, "srv-" + idB, "srv-" + idA}; !slices.Equal(got, want) {
		t.Fatalf("outbound tags = %q, want %q", got, want)
	}
}

func TestRenderDisabledServerOmitted(t *testing.T) {
	tests := []struct {
		name    string
		servers []store.Server
		want    []string
	}{
		{"disabled after enabled", []store.Server{testServer(idA, false), testServer(idB, true)}, []string{"srv-" + idA}},
		{"disabled before enabled", []store.Server{testServer(idB, true), testServer(idA, false)}, []string{"srv-" + idA}},
		{"enabled ones keep state order", []store.Server{testServer(idA, false), testServer(idB, false)}, []string{"srv-" + idA, "srv-" + idB}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, _ := mustRender(t, smart(tt.servers...))
			want := append([]string{TagBlock, TagDirect, TagDNSOut}, tt.want...)
			if got := tags(t, out.Outbounds); !slices.Equal(got, want) {
				t.Fatalf("outbound tags = %q, want %q", got, want)
			}
		})
	}
}

func TestRenderDeterministic(t *testing.T) {
	st := pinned(smart(testServer(idA, false), testServer(idB, false), testServer("deadbeef", true)), idB)
	before := st.Clone()
	first, err := Render(Input{State: st, Core: testCore})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Render(Input{State: st, Core: testCore})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("two renders differ:\n%s\n---\n%s", first, second)
	}
	if !reflect.DeepEqual(st, before) {
		t.Fatal("Render changed its input state")
	}

	// A stored outbound comes back re-indented after a state file round
	// trip, and a hand-written one may order its keys differently. Neither
	// may change the output.
	var parts map[string]json.RawMessage
	if err := json.Unmarshal([]byte(realityOutbound), &parts); err != nil {
		t.Fatal(err)
	}
	reordered := "{\n\t\"streamSettings\": " + string(parts["streamSettings"]) +
		",\n\t\"settings\": " + string(parts["settings"]) +
		",\n\t\"protocol\": \"vless\"\n}"
	var indented bytes.Buffer
	if err := json.Indent(&indented, []byte(reordered), "", "\t"); err != nil {
		t.Fatal(err)
	}
	other := st.Clone()
	for i := range other.Servers {
		other.Servers[i].Outbound = json.RawMessage(indented.String())
	}
	third, err := Render(Input{State: other, Core: testCore})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, third) {
		t.Fatalf("a re-indented outbound changed the output:\n%s\n---\n%s", first, third)
	}
}

func TestRenderSubnet(t *testing.T) {
	st := smart(testServer(idA, false))
	st.Network.Subnet = netip.MustParsePrefix("10.9.8.0/29")
	out, b := mustRender(t, st)
	checkServiceRules(t, out.Routing.Rules, serviceRules("10.9.8.2", "10.9.8.3", `"balancerTag":"proxy-closed"`))
	for _, i := range []int{1, 2, 3} {
		if got := field(t, out.Inbounds[i], "listen"); got != "10.9.8.3" {
			t.Errorf("inbound %s listens on %q, want 10.9.8.3", field(t, out.Inbounds[i], "tag"), got)
		}
	}
	if bytes.Contains(b, []byte("172.31.255.")) {
		t.Fatalf("an address of the default subnet is left:\n%s", b)
	}
}

func TestRenderDNSInAddress(t *testing.T) {
	tests := []struct {
		remote string
		want   string
	}{
		{"https://1.1.1.1/dns-query", "1.1.1.1"},
		{"https://dns.example/dns-query", "1.1.1.1"},
		{"203.0.113.53", "203.0.113.53"},
	}
	for _, tt := range tests {
		t.Run(tt.remote, func(t *testing.T) {
			st := smart(testServer(idA, false))
			st.DNS.Remote = tt.remote
			out, _ := mustRender(t, st)
			jsonEqual(t, "dns-in", out.Inbounds[1],
				`{"tag":"dns-in","protocol":"dokodemo-door","listen":"172.31.255.3","port":53,"settings":{"address":"`+tt.want+`","port":53,"network":"tcp,udp"}}`)
		})
	}
}

func TestRenderRefusesOldCore(t *testing.T) {
	b, err := Render(Input{State: smart(testServer(idA, false)), Core: version(26, 1, 17)})
	if err == nil {
		t.Fatalf("Render for 26.1.17 succeeded:\n%s", b)
	}
	if !strings.HasPrefix(err.Error(), "render: ") || !strings.Contains(err.Error(), "TUN inbound") {
		t.Fatalf("Render for 26.1.17 = %q, want a render: error naming the TUN inbound", err)
	}
}

func TestRenderRefusesInvalidState(t *testing.T) {
	st := smart(testServer("NOT-AN-ID", false))
	b, err := Render(Input{State: st, Core: testCore})
	if err == nil {
		t.Fatalf("Render of an invalid state succeeded:\n%s", b)
	}
	if !strings.HasPrefix(err.Error(), "render: ") || !strings.Contains(err.Error(), "servers[0].id") {
		t.Fatalf("Render = %q, want a render: error naming servers[0].id", err)
	}
}

func TestVia(t *testing.T) {
	tests := []struct {
		name     string
		proxy    bool
		balancer string
		want     rule
	}{
		{"open with members", true, BalancerOpen, rule{BalancerTag: BalancerOpen}},
		{"closed with members", true, BalancerClosed, rule{BalancerTag: BalancerClosed}},
		{"open without members", false, BalancerOpen, rule{OutboundTag: TagDirect}},
		{"closed without members", false, BalancerClosed, rule{OutboundTag: TagBlock}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &renderer{proxy: tt.proxy}
			if got := r.via(tt.balancer); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("via(%s) = %+v, want %+v", tt.balancer, got, tt.want)
			}
		})
	}
}

func TestTagged(t *testing.T) {
	want := withTag(t, realityOutbound, "srv-"+idA)
	var indented bytes.Buffer
	if err := json.Indent(&indented, []byte(realityOutbound), "", "    "); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{realityOutbound, indented.String()} {
		got, err := tagged(json.RawMessage(raw), "srv-"+idA)
		if err != nil {
			t.Fatalf("tagged: %v", err)
		}
		if string(got) != want {
			t.Fatalf("tagged =\n%s\nwant\n%s", got, want)
		}
	}

	for _, raw := range []string{``, `null`, `[]`, `"secret-key"`, `1`, `{"protocol":`} {
		t.Run(raw, func(t *testing.T) {
			_, err := tagged(json.RawMessage(raw), "srv-"+idA)
			if err == nil {
				t.Fatalf("tagged(%s) succeeded, want an error", raw)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("tagged's error %q repeats the outbound", err)
			}
		})
	}
}
