package routeros

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

func TestInstallProofReauthenticatesWithoutCachedSuccess(t *testing.T) {
	p, cfg := testPeer(t, true, func(c net.Conn, r *bufio.Reader) {
		for {
			q, e := readSentence(r)
			if e != nil {
				return
			}
			peerSend(c, "!done", tagWord(q))
		}
	})
	cfg.retryDelay = func(int) time.Duration { return time.Millisecond }
	c := connectTest(t, cfg)
	g := c.Generation()
	if err := c.reauthenticate(t.Context()); err != nil || p.logins.Load() != 2 || c.Generation() <= g {
		t.Fatal("cached session counted as current password proof")
	}
	p.reject.Store(true)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if err := c.reauthenticate(ctx); err == nil || c.Generation() != 0 {
		t.Fatal("previous authenticated session survived failed login")
	}
	p.reject.Store(false)
	recover, cancelRecovery := context.WithTimeout(t.Context(), time.Second)
	defer cancelRecovery()
	if err := c.reauthenticate(recover); err != nil || c.Generation() <= g {
		t.Fatal("restored credential failed fresh proof")
	}
}
func TestInstallVerifyDoesNotRepairOrIgnoreDrift(t *testing.T) {
	f := newDiffRouter()
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("fixture")
	}
	e := NewEngine(f, InstallScope{}, dir)
	e.observe = func(context.Context, Native, InstallScope) (Actual, error) { return f.actual(), nil }
	e.purge = func(context.Context, Native, Actual, []policyView) (int, error) { return 0, nil }
	e.finalPurge = e.purge
	e.check = func(context.Context, Native, Actual, []policyView) error { return nil }
	target := Target{Revision: 5, Policy: PolicyInput{Network: store.Default().Network, Default: store.Policy{Mode: store.ModeFull, KillSwitch: true}}, Selection: runnerapi.Selection{Core: "26.10.31", Config: "config/" + strings.Repeat("a", 64) + ".json"}, Verify: func(context.Context) error { return nil }}
	if _, err := e.Reconcile(t.Context(), target); err != nil {
		t.Fatal(err)
	}
	reauth := func(context.Context) error { return nil }
	if err := e.verifyInstallation(t.Context(), target, reauth); err != nil {
		t.Fatal("converged installation refused", err)
	}
	if err := e.verifyInstallation(t.Context(), target, func(context.Context) error { return errors.New("bad credential") }); err == nil {
		t.Fatal("authentication failure accepted")
	}
	f.insert("/system/script/job", "", map[string]string{"script": "tikray-emergency-off"})
	if err := e.verifyInstallation(t.Context(), target, func(context.Context) error { t.Fatal("retired a session during an emergency job"); return nil }); err == nil {
		t.Fatal("ignored emergency job")
	}
	f.rows = f.rows[:len(f.rows)-1]
	f.tag("tikray:jump-pre").Props["disabled"] = "yes"
	writes := len(f.writes)
	if err := e.verifyInstallation(t.Context(), target, reauth); err == nil || len(f.writes) != writes {
		t.Fatal("changed installed policy attested or repaired")
	}
}
