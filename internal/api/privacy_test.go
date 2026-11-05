package api

import (
	"encoding/json"
	"strings"
	"testing"

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
