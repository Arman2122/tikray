package api

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
)

func TestSuccessfulResponsesKeepCredentialsWriteOnly(t *testing.T) {
	f := newFake()
	const opaque = "fixture transport option"
	const probePass = "private-probe-fixture"
	f.state.Health.ProbeURL = "https://user:" + probePass + "@probe.example/path"
	f.state.Servers[0].Outbound = json.RawMessage(strings.Replace(string(f.state.Servers[0].Outbound), `"protocol":`, `"customTransportKey":"`+opaque+`","protocol":`, 1))
	srv := serve(t, f)
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/v1/state", ""},
		{"GET", "/v1/servers", ""},
		{"GET", "/v1/subscriptions", ""},
		{"GET", "/v1/health", ""},
		{"POST", "/v1/servers", mustJSON(t, map[string]string{"link": f.state.Servers[0].Link})},
		{"PATCH", "/v1/servers/5ab3c4d5", `{"disabled":true}`},
		{"POST", "/v1/subscriptions", mustJSON(t, map[string]string{"url": secretURL, "name": "provider"})},
		{"PATCH", "/v1/subscriptions/9be8f7a6", `{"name":"provider"}`},
		{"PUT", "/v1/health", mustJSON(t, f.state.Health)},
		{"PUT", "/v1/dns", mustJSON(t, store.DNS{Remote: f.state.Health.ProbeURL})},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			res := request(t, srv, tc.method, tc.path, tc.body, authed())
			if res.status < 200 || res.status >= 300 {
				t.Fatalf("response %d, want success", res.status)
			}
			for _, secret := range []string{secretID, secretURL, opaque, probePass, "https://sub.example/x", f.state.Servers[0].Link} {
				if strings.Contains(string(res.body), secret) {
					t.Fatal("response contains a credential or private transport setting")
				}
			}
		})
	}
	var servers []store.Server
	if err := json.Unmarshal(request(t, srv, "GET", "/v1/servers", "", authed()).body, &servers); err != nil || len(servers) != 1 {
		t.Fatal("missing server summary")
	}
	var meta struct {
		Protocol string
		Settings struct {
			Address string
			Port    int
		}
	}
	if json.Unmarshal(servers[0].Outbound, &meta) != nil || meta.Protocol != "vless" || meta.Settings.Address != "203.0.113.10" || meta.Settings.Port != 443 {
		t.Fatal("server response lost its public protocol or endpoint")
	}
}

func TestBadBodyDoesNotRepeatUnstoredCredentials(t *testing.T) {
	const misplaced = "misplaced-credential-fixture"
	srv := serve(t, newFake())
	for _, tc := range []struct{ path, body string }{
		{"/v1/auth/login", `{"` + misplaced + `":1}`},
		{"/v1/subscriptions", `{"interval":"` + misplaced + `"}`},
	} {
		res := request(t, srv, "POST", tc.path, tc.body, authed())
		if res.status != 400 || strings.Contains(string(res.body), misplaced) {
			t.Errorf("%s must reject the request without repeating the value or key", tc.path)
		}
	}
}

func TestSkippedLinkDoesNotExposeBrokenCredential(t *testing.T) {
	const private = "credential-tail-fixture"
	if strings.Contains(lineLabel("trojan://prefix#"+private+"@host"), private) {
		t.Error("a malformed skipped link exposed a credential fragment")
	}
}

// A credential copied into a routing expression or a probe path is still
// private even though these settings are normally safe to display.
func TestSettingsDoNotReflectCredentialsInOtherFields(t *testing.T) {
	f := newFake()
	f.state.Routing.BlockList = []string{"regexp:" + secretID}
	f.state.Health.ProbeURL = "https://probe.example/" + testToken + "?key=private-query"
	f.state.DNS.Remote = "https://" + testToken + ".example/dns"
	srv := serve(t, f)
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/v1/state", ""},
		{"GET", "/v1/health", ""},
		{"PUT", "/v1/routing", mustJSON(t, f.state.Routing)},
		{"PUT", "/v1/dns", mustJSON(t, f.state.DNS)},
	} {
		res := request(t, srv, tc.method, tc.path, tc.body, authed())
		if res.status != 200 || strings.Contains(string(res.body), secretID) || strings.Contains(string(res.body), testToken) || strings.Contains(string(res.body), "private-query") {
			t.Errorf("%s %s failed to protect settings", tc.method, tc.path)
		}
	}
}

func TestProbeCannotRevealPartOfSubscriptionURL(t *testing.T) {
	f := newFake()
	const path = "private-account-fixture"
	f.state.Subscriptions[0].URL = "https://provider.example/" + path + "?format=links"
	f.state.Health.ProbeURL = f.state.Subscriptions[0].URL
	f.state.DNS.Remote = "https://provider.example/" + path + "?format=other"
	srv := serve(t, f)
	for _, tc := range []struct{ method, route, body string }{
		{"GET", "/v1/state", ""},
		{"GET", "/v1/health", ""},
		{"PUT", "/v1/health", mustJSON(t, f.state.Health)},
		{"PUT", "/v1/dns", mustJSON(t, f.state.DNS)},
	} {
		res := request(t, srv, tc.method, tc.route, tc.body, authed())
		if res.status != 200 || strings.Contains(string(res.body), path) {
			t.Errorf("%s %s exposed an account path or refused the settings", tc.method, tc.route)
		}
	}
}

// A subscription URL of the SSPanel form ".../link/<token>?sub=3" has a
// one-character query value, which is no secret: an error's detail and the
// views keep their "3"s, and the token stays hidden.
func TestShortQueryValueKeepsDetailsAndViews(t *testing.T) {
	const token = "4f9a1c7e2b5d6a8c"
	f := newFake()
	f.state.Subscriptions[0].URL = "https://provider.example/link/" + token + "?sub=3"
	f.state.Servers[0].Name = "HK 03"
	f.state.Routing.BlockList = []string{"domain:ads.example", "domain:tracker3.example"}
	f.state.Routing.Domestic.Domains = []string{"domain:163.com"}
	f.err = fmt.Errorf("%w: server 3fa9c1d2", service.ErrNotFound)
	srv := serve(t, f)

	r := request(t, srv, "PATCH", "/v1/servers/3fa9c1d2", `{"disabled":true}`, authed())
	if _, detail := errorOf(t, r); r.status != 404 || detail != "service: not found: server 3fa9c1d2" {
		t.Errorf("PATCH of a missing server: status %d, detail %q", r.status, detail)
	}
	var got store.State
	r = request(t, srv, "GET", "/v1/state", "", authed())
	if err := json.Unmarshal(r.body, &got); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(r.body), token) {
		t.Error("the state view shows the subscription token")
	}
	if got.Servers[0].Name != "HK 03" || !slices.Equal(got.Routing.BlockList, f.state.Routing.BlockList) || !slices.Equal(got.Routing.Domestic.Domains, f.state.Routing.Domestic.Domains) {
		t.Errorf("the view masked ordinary values: name %q, block_list %q, domestic %q", got.Servers[0].Name, got.Routing.BlockList, got.Routing.Domestic.Domains)
	}
}

// A script reads the state and writes one section back, the usual way to edit
// a whole-object PUT. A view masks a value that holds a credential, and the
// placeholder must not replace the rule it stood for: the PUT fails loudly
// and the backend is never asked to store it.
func TestRoutingRoundTripRefusesMaskedValues(t *testing.T) {
	f := newFake()
	f.state.Subscriptions[0].URL = "https://provider.example/link/4f9a1c7e2b5d6a8c?sub=3"
	f.state.Routing.BlockList = []string{"domain:ads.example", "domain:tracker3.example", "regexp:" + secretID}
	f.state.Routing.Domestic.Domains = []string{"domain:163.com"}
	srv := serve(t, f)
	var got store.State
	if err := json.Unmarshal(request(t, srv, "GET", "/v1/state", "", authed()).body, &got); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Routing.Domestic.Domains, f.state.Routing.Domestic.Domains) || !slices.Equal(got.Routing.BlockList[:2], f.state.Routing.BlockList[:2]) {
		t.Errorf("the view masked ordinary routing values: %q, %q", fixtureText(got.Routing.BlockList...), got.Routing.Domestic.Domains)
	}
	r := request(t, srv, "PUT", "/v1/routing", mustJSON(t, got.Routing), authed())
	code, detail := errorOf(t, r)
	if r.status != 400 || code != "bad_request" || !strings.Contains(detail, "masked placeholder from a view") {
		t.Errorf("PUT of the viewed routing: status %d, %s: %q; want 400 that names the placeholder", r.status, code, detail)
	}
	for _, c := range f.recorded() {
		if c.Method == "SetRouting" {
			t.Error("the masked routing reached the backend")
		}
	}
}

// Only a real secret is masked in a view: a name or a routing value that only
// looks like a credential label, a link or a setup code is shown as it is.
func TestViewsShowOrdinaryNames(t *testing.T) {
	f := newFake()
	f.state.Servers[0].Name = "VMESS-HTTP-WS01"
	f.state.Subscriptions[0].Name = "test-test-test"
	f.state.Devices[0].Name = "https://provider.example"
	f.state.Routing.BlockList = []string{"keyword:test-test-test", "domain:vmess-http-ws01.example"}
	f.state.Devices = append(f.state.Devices,
		store.Device{Address: netip.MustParsePrefix("192.168.88.11/32"), Name: "root " + testToken, Policy: store.Policy{Mode: store.ModeSmart}},
		store.Device{Address: netip.MustParsePrefix("192.168.88.12/32"), Name: "id " + secretID, Policy: store.Policy{Mode: store.ModeSmart}})
	srv := serve(t, f)
	var st store.State
	r := request(t, srv, "GET", "/v1/state", "", authed())
	if err := json.Unmarshal(r.body, &st); err != nil {
		t.Fatal(err)
	}
	if st.Servers[0].Name != "VMESS-HTTP-WS01" || st.Subscriptions[0].Name != "test-test-test" || st.Devices[0].Name != "https://provider.example" ||
		!slices.Equal(st.Routing.BlockList, f.state.Routing.BlockList) {
		t.Errorf("the state view masked ordinary values: %q, %q, %q, %q", st.Servers[0].Name, st.Subscriptions[0].Name, st.Devices[0].Name, st.Routing.BlockList)
	}
	if st.Devices[1].Name != "‹redacted›" || st.Devices[2].Name != "id ‹redacted›" || strings.Contains(string(r.body), testToken) || strings.Contains(string(r.body), secretID) {
		t.Errorf("the state view shows a real secret: %q", fixtureText(st.Devices[1].Name, st.Devices[2].Name))
	}
	for path, name := range map[string]string{"/v1/servers": "VMESS-HTTP-WS01", "/v1/subscriptions": "test-test-test", "/v1/devices": "https://provider.example"} {
		if r := request(t, srv, "GET", path, "", authed()); r.status != 200 || !strings.Contains(string(r.body), `"name":"`+name+`"`) {
			t.Errorf("GET %s: status %d, the name %q is masked", path, r.status, name)
		}
	}
	r = request(t, srv, "PUT", "/v1/devices/192.168.88.20", `{"name":"test-test-test","policy":{"mode":"smart"}}`, authed())
	if r.status != 200 || !strings.Contains(string(r.body), `"name":"test-test-test"`) {
		t.Errorf("PUT of a device: status %d, %s", r.status, r.body)
	}
	r = request(t, srv, "PUT", "/v1/routing", mustJSON(t, f.state.Routing), authed())
	if r.status != 200 || !strings.Contains(string(r.body), "keyword:test-test-test") {
		t.Errorf("PUT of the routing: status %d, %s", r.status, r.body)
	}
}

// Probe and resolver URLs are shown without userinfo, query and fragment, and
// with their scheme, host, port and path: those are blanked only when what is
// left still holds a secret.
func TestViewsStripProbeAndDNSURLs(t *testing.T) {
	for _, c := range []struct{ probe, dns, wantProbe, wantDNS string }{
		{"https://probe.example/generate_204?client=router", "https://dns.example/dns-query?key=dns-api-key",
			"https://probe.example/generate_204", "https://dns.example/dns-query"},
		{"https://user:password-fixture@probe.example/generate_204", "https://name:dns-password@dns.example:8443/q#frag",
			"https://probe.example/generate_204", "https://dns.example:8443/q"},
		{"http://probe.example:8080/204#private-fragment", "1.1.1.1",
			"http://probe.example:8080/204", "1.1.1.1"},
		// What is left holds the root bearer, or the account path of a
		// subscription.
		{"https://probe.example/" + testToken + "?key=private-query", "https://" + testToken + ".example/dns", "", ""},
		{"https://sub.example.com/feed/4f9a1c7e2b?probe=1", "https://sub.example.com/feed/4f9a1c7e2b?format=other", "", ""},
	} {
		f := newFake()
		f.state.Health = store.Health{ProbeURL: c.probe}
		f.state.DNS = store.DNS{Remote: c.dns}
		srv := serve(t, f)
		var h store.Health
		if err := json.Unmarshal(request(t, srv, "GET", "/v1/health", "", authed()).body, &h); err != nil {
			t.Fatal(err)
		}
		var st store.State
		if err := json.Unmarshal(request(t, srv, "GET", "/v1/state", "", authed()).body, &st); err != nil {
			t.Fatal(err)
		}
		var d store.DNS
		if err := json.Unmarshal(request(t, srv, "PUT", "/v1/dns", mustJSON(t, f.state.DNS), authed()).body, &d); err != nil {
			t.Fatal(err)
		}
		if h.ProbeURL != c.wantProbe || st.Health.ProbeURL != c.wantProbe {
			t.Errorf("probe_url of the health and the state views = %q, want %q", fixtureText(h.ProbeURL, st.Health.ProbeURL), c.wantProbe)
		}
		if st.DNS.Remote != c.wantDNS || d.Remote != c.wantDNS {
			t.Errorf("dns.remote of the state view and a PUT's = %q, want %q", fixtureText(st.DNS.Remote, d.Remote), c.wantDNS)
		}
	}
}

// fixtureText is values for a failure message, with the fixture's secrets
// shown by their names: a test that fails because a view leaked one must not
// print it.
func fixtureText(values ...string) []string {
	hide := strings.NewReplacer(testToken, "<root token>", secretID, "<VLESS id>", "4f9a1c7e2b", "<subscription path>")
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = hide.Replace(v)
	}
	return out
}
