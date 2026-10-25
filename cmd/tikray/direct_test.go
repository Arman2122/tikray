package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

// The id of the server withServer adds; it is in serverOutbound.
const serverSecret = "b831381d-6324-4d53-ad4f-8cda48b30811"

// An xray that rejects a config can quote the credentials it was given. On the
// direct paths, as in the daemon, what the commands print and what they record
// has the state's secrets redacted.
func TestDirectPathsRedactWhatXrayQuotes(t *testing.T) {
	quote := "bad outbound with id " + serverSecret

	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, data string)
		args  []string
		core  string // the runner's active core
	}{
		{"apply", func(t *testing.T, data string) {}, []string{"apply"}, "26.10.21"},
		{"core update", func(t *testing.T, data string) { installSlot(t, data, "26.10.21") }, []string{"core", "update", "26.10.21"}, "26.3.27"},
		{"core rollback", func(t *testing.T, data string) {
			installSlot(t, data, "26.3.27")
			installSlot(t, data, "26.10.21")
		}, []string{"core", "rollback"}, "26.3.27"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vars, data, runner := trialEnv(t, &runnerapi.Selection{Core: tc.core, Config: testConfigRel})
			tc.setup(t, data)
			if tc.name == "core rollback" {
				// A rollback needs a committed update behind it, made while
				// the state has no server, which a health probe would need.
				writeState(t, data, dnsRemote("9.9.9.9"))
				if code, stdout, stderr := runFast(t, vars, "core", "update", "26.10.21"); code != 0 {
					t.Fatalf("update: exit %d; stdout %q, stderr %q", code, stdout, stderr)
				}
			}
			writeState(t, data, withServer)
			runner.mu.Lock()
			runner.reject, runner.rejected = true, quote
			runner.mu.Unlock()

			code, stdout, stderr := runFast(t, vars, tc.args...)
			if code != 1 {
				t.Fatalf("exit %d, want 1; stdout %q, stderr %q", code, stdout, stderr)
			}
			if !strings.Contains(stdout, "bad outbound") {
				t.Fatalf("stdout %q does not show xray's rejection at all", stdout)
			}
			last, err := os.ReadFile(filepath.Join(data, "state", "last-result.json"))
			if err != nil {
				t.Fatal(err)
			}
			history, err := os.ReadFile(filepath.Join(data, "state", "core-history.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			for name, text := range map[string]string{"stdout": stdout, "stderr": stderr, "last-result.json": string(last), "core-history.jsonl": string(history)} {
				if strings.Contains(text, serverSecret) {
					t.Errorf("%s repeats the server's credential:\n%s", name, text)
				}
			}
			if !strings.Contains(stdout, "‹redacted›") {
				t.Errorf("stdout %q shows no redaction", stdout)
			}
		})
	}
}

// A server that this tikray refuses is disabled when the state is opened. A
// command that opens it says which, once, as the daemon does.
func TestDirectPathsNameTheServersOpenDisabled(t *testing.T) {
	vars, data, _ := trialEnv(t, &runnerapi.Selection{Core: "26.10.21", Config: testConfigRel})
	installSlot(t, data, "26.10.21")
	writeState(t, data, withServer)

	// Make the server one this tikray refuses: a protocol that is no proxy.
	file := filepath.Join(data, "state", "state.v1.json")
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`"protocol":\s*"vless"`)
	if !re.Match(b) {
		t.Fatalf("no protocol to change in\n%s", b)
	}
	if err := os.WriteFile(file, re.ReplaceAll(b, []byte(`"protocol": "freedom"`)), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(data, "state"))
	if err != nil {
		t.Fatal(err)
	}
	st, _ := s.State()
	if len(s.Degraded()) != 1 || st.Servers[0].Invalid == "" {
		t.Fatalf("the test state has no degraded server: %v", s.Degraded())
	}
	line := fmt.Sprintf("server a1b2c3d4 (lab-a) disabled: %s\n", st.Servers[0].Invalid)

	cfgFile, _ := configFile(t, `{"log":{}}`)
	for _, args := range [][]string{
		{"config", "render", "--core", "26.10.21"},
		{"core", "status"},
		{"apply"},
		{"core", "update", "26.10.21"},
		{"core", "update", "26.10.21", "--config", cfgFile},
		{"core", "rollback"},
	} {
		_, _, stderr := runFast(t, vars, args...)
		if n := strings.Count(stderr, line); n != 1 {
			t.Errorf("tikray %q: stderr has the degraded line %d times, want once:\n%s", args, n, stderr)
		}
	}

	// A command that does not open the state says nothing of it.
	if _, _, stderr := runFast(t, vars, "core", "list"); strings.Contains(stderr, "disabled") {
		t.Errorf("core list: stderr %q", stderr)
	}
}

// A config file given to core update is not in the state, so its credentials
// are not the state's. If xray quotes them, they are redacted all the same: the
// history and stdout must not hold them on this path either.
func TestConfigFileCredentialsAreRedactedToo(t *testing.T) {
	const fileSecret = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
	const filePassword = "tr0jan-passw0rd-of-the-file"
	body := `{
  "outbounds": [
    {"protocol": "vless", "settings": {"vnext": [{"address": "198.51.100.7", "port": 443, "users": [{"id": "` + fileSecret + `"}]}]}},
    {"protocol": "trojan", "settings": {"servers": [{"address": "198.51.100.8", "port": 443, "password": "` + filePassword + `"}]}}
  ]
}
`
	file, _ := configFile(t, body)

	for name, setup := range map[string]func(t *testing.T, data string){
		"a state with servers": func(t *testing.T, data string) { writeState(t, data, withServer) },
		"no state file":        func(t *testing.T, data string) {},
		"an unreadable state":  func(t *testing.T, data string) { writeBad(t, data, "state.v1.json", []byte("{not json")) },
	} {
		t.Run(name, func(t *testing.T) {
			vars, data, runner := trialEnv(t, &runnerapi.Selection{Core: "26.3.27", Config: testConfigRel})
			installSlot(t, data, "26.10.21")
			setup(t, data)
			runner.mu.Lock()
			runner.reject, runner.rejected = true, "bad outbounds: id "+fileSecret+", password "+filePassword
			runner.mu.Unlock()

			code, stdout, stderr := runFast(t, vars, "core", "update", "26.10.21", "--config", file)
			if code != 1 || !strings.Contains(stdout, "bad outbounds") {
				t.Fatalf("exit %d, stdout %q, stderr %q; want 1 and xray's rejection", code, stdout, stderr)
			}
			last, err := os.ReadFile(filepath.Join(data, "state", "last-result.json"))
			if err != nil {
				t.Fatal(err)
			}
			history, err := os.ReadFile(filepath.Join(data, "state", "core-history.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			for what, text := range map[string]string{"stdout": stdout, "stderr": stderr, "last-result.json": string(last), "core-history.jsonl": string(history)} {
				for _, secret := range []string{fileSecret, filePassword} {
					if strings.Contains(text, secret) {
						t.Errorf("%s repeats a credential of the config file:\n%s", what, text)
					}
				}
			}
			if !strings.Contains(stdout, "‹redacted›") {
				t.Errorf("stdout %q shows no redaction", stdout)
			}
		})
	}
}
