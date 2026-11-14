package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Arman2122/tikray/internal/artifacts"
	"github.com/Arman2122/tikray/internal/render"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/service"
	"github.com/Arman2122/tikray/internal/store"
	"github.com/Arman2122/tikray/internal/xrayver"
)

type networkTestRunner struct{ calls atomic.Int64 }

func (r *networkTestRunner) Status(context.Context) (runnerapi.Status, error) {
	r.calls.Add(1)
	return runnerapi.Status{}, errors.New("test: runner is offline")
}

func (r *networkTestRunner) Test(context.Context, []byte) (runnerapi.TestResult, error) {
	r.calls.Add(1)
	return runnerapi.TestResult{}, errors.New("test: runner is offline")
}

func TestLegacyNetworkRepairOverHTTPS(t *testing.T) {
	for _, tc := range []struct {
		name    string
		bridge  string
		restart bool
		remote  string
	}{
		{"reserved bridge", "169.254.0.0/29", true, ""},
		{"healthy bridge", "10.81.0.0/29", false, ""},
		{"new domestic resolver conflicts with plain remote", "169.254.0.0/29", true, "10.81.0.1"},
		{"new domestic resolver conflicts with DoH on port 53", "169.254.0.0/29", true, "https://[::ffff:10.81.0.1]:53/dns-query?access=fixture-dns-secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			old := testState()
			old.Network.Subnet = netip.MustParsePrefix(tc.bridge)
			if tc.remote != "" {
				old.DNS.Remote = tc.remote
			}
			old.Servers[0].Outbound = json.RawMessage(`{"protocol":"vless","streamSettings":{"security":"tls"}}`)
			for _, addr := range []string{"127.0.0.8/32", "224.0.2.0/24"} {
				old.Devices = append(old.Devices, store.Device{Address: netip.MustParsePrefix(addr), Policy: old.DefaultPolicy})
			}
			if tc.restart {
				old.Devices = append(old.Devices, store.Device{Address: netip.MustParsePrefix("10.81.0.3/32"), Policy: old.DefaultPolicy})
			}
			file := filepath.Join(dir, "state.v1.json")
			raw := []byte(`{"version":1,"revision":5,"state":` + mustJSON(t, old) + "}")
			if os.WriteFile(file, raw, 0600) != nil {
				t.Fatal("could not seed the legacy state")
			}
			s, err := store.Open(dir)
			if err != nil {
				t.Fatal("legacy state could not be opened")
			}
			runner := new(networkTestRunner)
			serviceConfig := service.Config{Store: s, Data: dir, Runner: runner,
				LocalBridge: func(n store.Network) bool { return n.Subnet == netip.MustParsePrefix("10.81.0.0/29") },
				Updaters: func(store.State, uint64) *artifacts.CoreUpdater {
					t.Error("unsafe runner operation reached the updater")
					return &artifacts.CoreUpdater{}
				}}
			svc, err := service.New(serviceConfig)
			if err != nil {
				t.Fatal("could not start the service")
			}
			web := httptest.NewTLSServer(newHandler(t, svc))
			defer web.Close()
			request := func(method, path, body, rev string, authenticated bool, want int) string {
				t.Helper()
				r, err := http.NewRequest(method, web.URL+path, strings.NewReader(body))
				if err != nil {
					t.Fatal("could not create request")
				}
				if authenticated {
					r.Header.Set("Authorization", "Bearer "+testToken)
				}
				r.Header.Set("If-Match", rev)
				res, err := web.Client().Do(r)
				if err != nil {
					t.Fatal("HTTPS request failed")
				}
				defer res.Body.Close()
				reply, err := io.ReadAll(res.Body)
				if err != nil || bytes.Contains(reply, []byte(secretID)) || bytes.Contains(reply, []byte(secretURL)) || bytes.Contains(reply, []byte(testToken)) || bytes.Contains(reply, []byte("fixture-dns-secret")) {
					t.Fatal("response was unreadable or disclosed private data")
				}
				if res.StatusCode != want {
					t.Fatalf("%s %s returned %d, want %d", method, path, res.StatusCode, want)
				}
				return string(reply)
			}
			const route = "/v1/network"
			const rev = `"5"`
			repair := `{"subnet":"10.81.0.0/29","remove_devices":["127.0.0.8/32","224.0.2.0/24"]}`
			if tc.restart {
				repair = strings.Replace(repair, "]", `,"10.81.0.3/32"]`, 1)
			}
			request("GET", "/v1/state", "", rev, true, 200)
			request("PUT", route, repair, rev, false, 401)
			request("PUT", route, repair, `"4"`, true, 409)
			withDNS := strings.Replace(repair, "{", `{"remote_dns":"https://9.9.9.9/dns-query?access=fixture-dns-secret",`, 1)
			request("PUT", route, strings.Replace(withDNS, "fixture-dns-secret", store.Masked, 1), rev, true, 400)
			if tc.remote != "" {
				request("PUT", route, repair, rev, true, 422)
				repair = withDNS
			} else {
				request("PUT", route, withDNS, rev, true, 422)
			}
			request("PUT", route, strings.Replace(repair, "{", `{"require_local_bridge":false,`, 1), rev, true, 400)
			for _, unrelated := range []string{"10.82.0.0", "8.8.8.0"} {
				request("PUT", route, strings.Replace(repair, "10.81.0.0", unrelated, 1), rev, true, 422)
			}
			if tc.restart && runner.calls.Load() != 0 {
				t.Fatal("an unverified repair contacted the runner")
			}
			request("PUT", route, strings.Replace(repair, "224.0.2.0/24", "192.168.88.10/32", 1), rev, true, 422)
			request("PUT", route, strings.Replace(repair, `,"224.0.2.0/24"`, "", 1), rev, true, 422)
			st, _ := s.State()
			if cfg, err := render.Render(render.Input{State: st, Core: xrayver.Version{Major: 26, Minor: 10, Patch: 21}}); err == nil || cfg != nil {
				t.Fatal("legacy overlap rendered an xray config")
			}
			if !bytes.Equal(raw, readFile(t, file)) {
				t.Fatal("a refused request changed the state")
			}
			reply := request("PUT", route, repair, rev, true, 200)
			var result struct {
				Restart *bool `json:"restart_required"`
			}
			if json.Unmarshal([]byte(reply), &result) != nil || result.Restart == nil || *result.Restart != tc.restart {
				t.Fatal("incorrect restart instruction")
			}
			request("PUT", route, repair, `"6"`, true, 422)
			if tc.restart {
				if _, err := svc.ApplyNow(context.Background()); err == nil || runner.calls.Load() != 0 {
					t.Fatal("applied to or contacted an unsafe startup runner")
				}
			}
			s, err = store.Open(dir)
			if err != nil {
				t.Fatal("could not reopen repaired state")
			}
			st, revision := s.State()
			old.Devices = old.Devices[:1]
			old.Network.Subnet = netip.MustParsePrefix("10.81.0.0/29")
			old.Network.RequireLocalBridge = tc.restart
			if tc.remote != "" {
				old.DNS.Remote = "https://9.9.9.9/dns-query?access=fixture-dns-secret"
			}
			if revision != 6 || st.Validate() != nil || mustJSON(t, st) != mustJSON(t, old) {
				t.Fatal("repair changed unrelated state or left it unusable")
			}
			if tc.restart {
				// A changed container namespace (or an unavailable verifier)
				// cannot send the token to a host reached by a new default route.
				for _, verify := range []func(store.Network) bool{nil, func(store.Network) bool { return false }} {
					serviceConfig.Store, serviceConfig.LocalBridge = s, verify
					again, err := service.New(serviceConfig)
					if err != nil {
						t.Fatal("namespace mismatch prevented local management")
					}
					if _, err := again.ApplyNow(context.Background()); err == nil || runner.calls.Load() != 0 {
						t.Fatal("restart with missing namespace evidence contacted a runner")
					}
					if _, _, err := again.RepairNetwork(context.Background(), 6, service.NetworkRepair{Subnet: old.Network.Subnet}); err == nil {
						t.Fatal("repair accepted unverified subnet after restart")
					}
				}
				serviceConfig.LocalBridge = func(n store.Network) bool { return n.Subnet == old.Network.Subnet }
				again, err := service.New(serviceConfig)
				if err != nil {
					t.Fatal("could not restart with verified local subnet")
				}
				again.Status(context.Background())
				if runner.calls.Load() != 1 {
					t.Fatal("verified restart did not restore runner access")
				}
			}
		})
	}
}
