//go:build lab

package m0

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDeploy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Minute)
	defer cancel()
	l := Deploy(ctx, t)

	s, err := l.RunnerStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.XrayPID <= 0 || !s.RoutesOK || s.Ingress == "" {
		t.Errorf("runner status %+v, want xray running, routes ok, an ingress link", s)
	}
	if n, err := l.CHR.Get(ctx, `[:len [/ip/firewall/mangle/find where comment~"^tikray:"]]`); err != nil || n != "10" {
		t.Errorf("tikray mangle rules %q (%v), want 10", n, err)
	}
	out, err := l.CHR.Run(ctx, "/container/print")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tikray-runner", "tikray-ctl"} {
		running := false
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, name) && strings.Contains(line, " R ") {
				running = true
			}
		}
		if !running {
			t.Errorf("%s not running:\n%s", name, out)
		}
	}
}
