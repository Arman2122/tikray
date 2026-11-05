//go:build lab

package m3

import (
	"errors"
	"strings"
	"testing"

	ros "github.com/go-routeros/routeros/v3"
)

func probeAccount(t *testing.T, r *rig) {
	reply, err := r.admin.RunContext(r.ctx, "/user/active/print", "=.proplist=name,address,via", "?name=m3-cap-user")
	if err != nil || len(reply.Re) != 1 || reply.Re[0].Map["address"] != "172.31.255.2" || !strings.Contains(reply.Re[0].Map["via"], "api") {
		r.mark(t, "B.identity", "INCONCLUSIVE", "owner could not confirm the live restricted API account at the control IP")
	} else {
		r.mark(t, "B.identity", "PASS", "owner independently observed the restricted API account at the control IP")
	}
	// A known administrative write is a negative control for every successful
	// traffic-menu mutation. Try the identical sentence as the owner.
	cmd := []string{"/user/group/add", "=name=m3-negative", "=policy=read", "=comment=tikray:spike-negative"}
	_, denied := r.api.RunArgsContext(r.ctx, cmd)
	var trap *ros.DeviceError
	if !errors.As(denied, &trap) || !strings.Contains(strings.ToLower(trap.Error()), "permission") {
		r.mark(t, "B.negative-control", "INCONCLUSIVE", "restricted operation did not return the expected permission trap")
		return
	}
	created, err := r.admin.RunArgsContext(r.ctx, cmd)
	if err != nil || created.Done == nil || created.Done.Map["ret"] == "" {
		r.mark(t, "B.negative-control", "INCONCLUSIVE", "owner could not execute the identical administrative control")
		return
	}
	if _, err := r.admin.RunContext(r.ctx, "/user/group/remove", "=.id="+created.Done.Map["ret"]); err != nil {
		r.mark(t, "B.negative-control", "INCONCLUSIVE", "owner could not clean the administrative control")
		return
	}
	r.mark(t, "B.negative-control", "PASS", "restricted administrative write denied and identical owner operation succeeded")
}
