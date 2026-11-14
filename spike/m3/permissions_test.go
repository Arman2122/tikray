//go:build lab

package m3

import (
	"context"
	"strings"
	"testing"
	"time"

	ros "github.com/go-routeros/routeros/v3"
)

type permissionMenu struct {
	name, path string
	ordered    bool
	fields     []string
}

func probePermissions(t *testing.T, r *rig) {
	menus := []permissionMenu{
		{"mangle", "/ip/firewall/mangle", true, []string{"=chain=prerouting", "=action=passthrough", "=src-address=198.18.207.7", "=disabled=yes"}},
		{"filter", "/ip/firewall/filter", true, []string{"=chain=forward", "=action=accept", "=src-address=198.18.207.7", "=disabled=yes"}},
		{"nat", "/ip/firewall/nat", true, []string{"=chain=srcnat", "=action=accept", "=src-address=198.18.207.7", "=disabled=yes"}},
		{"address-list", "/ip/firewall/address-list", false, []string{"=list=tikray-spike-b", "=address=198.18.207.7"}},
		{"v6-filter", "/ipv6/firewall/filter", true, []string{"=chain=forward", "=action=accept", "=src-address=2001:db8:207::7", "=disabled=yes"}},
		{"v6-address-list", "/ipv6/firewall/address-list", false, []string{"=list=tikray-spike-b", "=address=2001:db8:207::7"}},
		{"table", "/routing/table", false, []string{"=fib=yes"}},
		{"route", "/ip/route", false, []string{"=dst-address=198.18.207.7/32", "=gateway=198.51.100.254", "=distance=16"}},
		{"netwatch", "/tool/netwatch", false, []string{"=type=simple", "=host=198.18.207.7", "=disabled=yes"}},
	}
	for _, m := range menus {
		m := m
		t.Run(m.name, func(t *testing.T) {
			restricted := exerciseMenu(r.ctx, r.api, r.admin, r.api, m, "limited")
			// Subscription rights and mutation rights are independent. If the
			// subject cannot complete the fixture, produce its events as owner.
			if !restricted.crud {
				witness := exerciseMenu(r.ctx, r.admin, r.admin, r.api, m, "producer")
				restricted.listen, restricted.listenStage = witness.listen, witness.listenStage
			}
			var owner permissionOutcome
			if !restricted.crud || !restricted.listen {
				owner = exerciseMenu(r.ctx, r.admin, r.admin, r.admin, m, "owner")
			}
			markPermission(t, r, "B-"+m.name+"-crud", restricted.crud, owner.crud, restricted.crudStage)
			if restricted.listenStage == "unsupported native listener command" && owner.listenStage == restricted.listenStage {
				r.mark(t, "B-"+m.name+"-listen", "FAIL", "listener command explicitly rejected on both native sessions")
			} else {
				markPermission(t, r, "B-"+m.name+"-listen", restricted.listen, owner.listen, restricted.listenStage)
			}
		})
	}
	probeConntrack(t, r)
}

func markPermission(t *testing.T, r *rig, key string, passed, control bool, stage string) {
	switch {
	case passed:
		r.mark(t, key, "PASS", stage)
	case control && strings.Contains(stage, "permission denied"):
		r.mark(t, key, "FAIL", stage+"; identical owner control passed")
	case control:
		r.mark(t, key, "INCONCLUSIVE", stage+"; observed with owner, not proof of a restricted permission denial")
	default:
		r.mark(t, key, "INCONCLUSIVE", stage+"; owner control did not establish capability")
	}
}

type permissionOutcome struct {
	crud, listen           bool
	crudStage, listenStage string
}

func exerciseMenu(ctx context.Context, c, admin, listenAs *ros.Client, m permissionMenu, role string) (out permissionOutcome) {
	out.crudStage = "fixture add did not complete"
	out.listenStage = "no correlated event"
	base := "tikray:m3-spike:perm-" + m.name + "-" + role
	fields := append([]string{}, m.fields...)
	if m.name == "table" {
		fields = append(fields, "=name=tikray-spike-b-"+role)
	}
	// Fixtures are inert; both identities get the same operations on distinct rows.
	add := func(comment string) string {
		cmd := append([]string{m.path + "/add", "=comment=" + comment}, fields...)
		reply, err := permissionRun(ctx, c, cmd...)
		if err != nil || reply.Done == nil {
			out.crudStage = permissionStage("add", err)
			return ""
		}
		return reply.Done.Map["ret"]
	}
	cleanup := func(id string) { _, _ = permissionRun(ctx, admin, m.path+"/remove", "=.id="+id) }
	var anchor string
	if m.ordered {
		anchor = add(base + "-anchor")
		if anchor == "" {
			return out
		}
		defer cleanup(anchor)
	}
	id := add(base)
	if id == "" {
		return out
	}
	defer cleanup(id)
	props := "=.proplist=.id,comment"
	if m.name == "netwatch" {
		props += ",up-script,down-script"
	}
	read := func(comment string) bool {
		reply, err := permissionRun(ctx, c, m.path+"/print", props, "?.id="+id)
		if err != nil || len(reply.Re) != 1 {
			return false
		}
		row := reply.Re[0].Map
		if row[".id"] != id || row["comment"] != comment {
			return false
		}
		return m.name != "netwatch" || comment == base || (row["up-script"] == ":local tikrayUp true" && row["down-script"] == ":local tikrayDown true")
	}
	if !read(base) {
		out.crudStage = "read by returned ID failed"
		return out
	}
	// Ending the context passed to Listen cancels this library's shared
	// socket reader. End just the subscription with the native cancellation.
	listener, listenErr := listenAs.ListenArgsQueueContext(ctx, []string{m.path + "/listen", "=.proplist=.id,comment,.dead"}, 256)
	if listenErr == nil {
		defer func() {
			cancelCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			_, _ = listener.CancelContext(cancelCtx)
		}()
	}
	// Only a baseline row followed by its changed value proves an edit
	// independently of initial enumeration. A tombstone proves a deletion.
	sawBase := false
	if listenErr == nil {
		wait := time.NewTimer(time.Second)
	initial:
		for {
			select {
			case <-wait.C:
				break initial
			case row, ok := <-listener.Chan():
				if !ok {
					break initial
				}
				if row.Map[".id"] == id && row.Map["comment"] == base {
					sawBase = true
					break initial
				}
			}
		}
		wait.Stop()
	}
	updated := base + "-edited"
	set := []string{m.path + "/set", "=.id=" + id, "=comment=" + updated}
	if m.name == "route" {
		set = append(set, "=distance=17")
	}
	if m.name == "netwatch" {
		set = append(set, "=up-script=:local tikrayUp true", "=down-script=:local tikrayDown true")
	}
	if _, err := permissionRun(ctx, c, set...); err != nil || !read(updated) {
		out.crudStage = permissionStage("set or readback", err)
		return out
	}
	// RouterOS may coalesce an edit and an immediate deletion. Observe the
	// edit before removing the row so these are two distinct experiments.
	match := func(wantEdit bool) bool {
		if listenErr != nil {
			return false
		}
		timer := time.NewTimer(8 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				return false
			case row, ok := <-listener.Chan():
				if !ok {
					if schemaTrap(listener.Err()) {
						out.listenStage = "unsupported native listener command"
					} else if de, ok := listener.Err().(*ros.DeviceError); ok && strings.Contains(strings.ToLower(de.Error()), "permission") {
						out.listenStage = "listener permission denied"
					}
					return false
				}
				if row.Map[".id"] != id {
					continue
				}
				if wantEdit && row.Map["comment"] == updated && row.Map[".dead"] != "true" && row.Map[".dead"] != "yes" {
					return true
				}
				if !wantEdit && (row.Map[".dead"] == "true" || row.Map[".dead"] == "yes") {
					return true
				}
			}
		}
	}
	edited := match(true) && sawBase
	if m.ordered {
		order := func(first, second string) bool {
			reply, err := permissionRun(ctx, c, m.path+"/print", "=.proplist=.id")
			if err != nil {
				return false
			}
			seen := false
			for _, row := range reply.Re {
				if row.Map[".id"] == second {
					return seen
				}
				if row.Map[".id"] == first {
					seen = true
				}
			}
			return false
		}
		if !order(anchor, id) {
			out.crudStage = "initial pair order not established"
			return out
		}
		if _, err := permissionRun(ctx, c, m.path+"/move", "=numbers="+id, "=destination="+anchor); err != nil || !order(id, anchor) {
			out.crudStage = permissionStage("move relative to anchor", err)
			return out
		}
	}
	if _, err := permissionRun(ctx, c, m.path+"/remove", "=.id="+id); err != nil {
		out.crudStage = permissionStage("remove by ID", err)
		return out
	}
	got, err := permissionRun(ctx, c, m.path+"/print", "=.proplist=.id", "?.id="+id)
	if err != nil || len(got.Re) != 0 {
		out.crudStage = "removed ID still visible or read failed"
		return out
	}
	out.crud, out.crudStage = true, "created, read, changed and removed own row"
	if m.ordered {
		out.crudStage += "; verified relative move"
	}
	if listenErr != nil {
		out.listenStage = "listen could not start"
		return out
	}
	deleted := match(false)
	if edited && deleted {
		out.listen = true
		out.listenStage = "matched separate edit and deletion for the same ID"
	} else if edited {
		out.listen = true
		out.listenStage = "matched post-baseline edit; no deletion observed for its ID"
	} else if deleted {
		out.listen = true
		out.listenStage = "matched post-subscription deletion; no separate edit proven"
	}
	return out
}

func permissionRun(ctx context.Context, c *ros.Client, args ...string) (*ros.Reply, error) {
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	return c.RunArgsContext(bounded, args)
}

func permissionStage(op string, err error) string {
	if de, ok := err.(*ros.DeviceError); ok && strings.Contains(strings.ToLower(de.Error()), "permission") {
		return op + ": permission denied"
	}
	if err == nil {
		return op + ": expected readback missing"
	}
	return op + ": operation unconfirmed"
}
