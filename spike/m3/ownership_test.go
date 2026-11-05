//go:build lab

package m3

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	routeros "github.com/go-routeros/routeros/v3"
)

// The admin client supplies a known-good positive control for each native
// sentence. Only IDs returned by adds made during this run may be removed.
type ownerFixture struct {
	role string
	menu string
	args []string
}

type createdOwnerFixture struct {
	ownerFixture
	id string
}

func probeOwnership(t *testing.T, r *rig) {
	t.Helper()
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		r.mark(t, "C.fixture.user", "INCONCLUSIVE", "fixture entropy unavailable")
		return
	}
	password := hex.EncodeToString(random[:])
	r.auditCanary(t, password)

	const name = "m3-own-"
	const bridge = name + "bridge"
	const veth = name + "veth"
	const table = name + "rt"
	const srcList = name + "ip"
	const group = name + "group"
	const env = name + "env"
	const mount = name + "mount"
	fixtures := []ownerFixture{
		{"bridge", "/interface/bridge", []string{"=name=" + bridge, "=protocol-mode=none"}},
		{"veth", "/interface/veth", []string{"=name=" + veth, "=address=198.18.253.2/29", "=gateway=198.18.253.1"}},
		{"bridge-port", "/interface/bridge/port", []string{"=bridge=" + bridge, "=interface=" + veth}},
		{"bridge-address", "/ip/address", []string{"=interface=" + bridge, "=address=198.18.253.1/29"}},
		{"table", "/routing/table", []string{"=name=" + table, "=fib=yes"}},
		{"route", "/ip/route", []string{"=dst-address=198.18.252.255/32", "=routing-table=" + table, "=blackhole=yes", "=disabled=yes"}},
		{"v4-list", "/ip/firewall/address-list", []string{"=list=" + srcList, "=address=198.18.252.255"}},
		{"v6-list", "/ipv6/firewall/address-list", []string{"=list=" + srcList, "=address=2001:db8:ffff::1"}},
		{"v4-filter", "/ip/firewall/filter", []string{"=chain=forward", "=src-address-list=" + srcList, "=action=drop", "=disabled=yes"}},
		{"v6-filter", "/ipv6/firewall/filter", []string{"=chain=forward", "=src-address-list=" + srcList, "=action=drop", "=disabled=yes"}},
		{"mangle", "/ip/firewall/mangle", []string{"=chain=prerouting", "=src-address-list=" + srcList, "=action=mark-routing", "=new-routing-mark=" + table, "=disabled=yes"}},
		{"nat", "/ip/firewall/nat", []string{"=chain=srcnat", "=src-address-list=" + srcList, "=action=masquerade", "=disabled=yes"}},
		{"group", "/user/group", []string{"=name=" + group, "=policy=read,api"}},
		{"user", "/user", []string{"=name=" + name + "user", "=group=" + group, "=password=" + password, "=disabled=yes"}},
		{"env", "/container/envs", []string{"=list=" + env, "=key=M3_OWNERSHIP_PROBE", "=value=fixture"}},
		{"mount", "/container/mounts", []string{"=list=" + mount, "=src=disk1/tikray/data/run", "=dst=/mnt/m3-own", "=mode=rw"}},
		{"script", "/system/script", []string{"=name=" + name + "script", "=source=:return true"}},
		{"scheduler", "/system/scheduler", []string{"=name=" + name + "scheduler", "=on-event=:return true", "=disabled=yes"}},
		{"netwatch", "/tool/netwatch", []string{"=host=198.18.252.255", "=disabled=yes"}},
	}
	const image = "disk1/m3-owner-fixture.tar"
	localImage, err := containerFixture(t.TempDir())
	if err != nil || r.chr.Push(r.ctx, localImage, image) != nil {
		r.mark(t, "C.tag.container", "INCONCLUSIVE", "could not stage stopped container fixture")
		r.mark(t, "B.remove.container", "INCONCLUSIVE", "no container fixture")
	} else {
		fixtures = append(fixtures, ownerFixture{"container", "/container", []string{
			"=name=m3-own-container", "=file=" + image, "=interface=" + veth, "=root-dir=disk1/m3-own-container", "=dns=172.27.0.1", "=start-on-boot=no",
		}})
	}

	var created []createdOwnerFixture
	for _, f := range fixtures {
		if row, ok := addOwnerFixture(t, r, f); ok {
			created = append(created, row)
		}
	}
	// Containers precede their interfaces; users precede their groups.
	for i := len(created) - 1; i >= 0; i-- {
		removeOwnerFixture(t, r, created[i])
	}
}

func ownerCall(ctx context.Context, c *routeros.Client, words ...string) (*routeros.Reply, error) {
	deadline, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	return c.RunContext(deadline, words...)
}

func ownerRow(ctx context.Context, c *routeros.Client, menu, id string) (string, bool, error) {
	rep, err := ownerCall(ctx, c, menu+"/print", "=.proplist=.id,comment", "?.id="+id)
	if err != nil {
		return "", false, err
	}
	for _, s := range rep.Re {
		if s.Map[".id"] == id {
			return s.Map["comment"], true, nil
		}
	}
	return "", false, nil
}

func ownerAddID(reply *routeros.Reply) string {
	if reply == nil || reply.Done == nil {
		return ""
	}
	return reply.Done.Map["ret"]
}

func ownerWait(ctx context.Context, limit time.Duration, check func(context.Context) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		ready, err := check(ctx)
		if ready || err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func ownerContainerID(ctx context.Context, c *routeros.Client, tag string) string {
	var id string
	_ = ownerWait(ctx, 30*time.Second, func(ctx context.Context) (bool, error) {
		reply, err := ownerCall(ctx, c, "/container/print", "=.proplist=.id,name,comment",
			"?name=m3-own-container", "?comment="+tag, "?#&")
		if err != nil {
			return false, err
		}
		if len(reply.Re) == 1 && reply.Re[0].Map["name"] == "m3-own-container" && reply.Re[0].Map["comment"] == tag {
			id = reply.Re[0].Map[".id"]
		}
		return id != "", nil
	})
	return id
}

func ownerContainerReady(ctx context.Context, r *rig, id string) error {
	return ownerWait(ctx, 90*time.Second, func(ctx context.Context) (bool, error) {
		reply, err := ownerCall(ctx, r.admin, "/container/print", "=.proplist=.id,arch", "?.id="+id)
		if err != nil || len(reply.Re) != 1 {
			return false, err
		}
		props := reply.Re[0].Map
		stopped, err := r.chr.RunPrivate(ctx, `:put [:len [/container/find where name="m3-own-container" and stopped]]`)
		return err == nil && props["arch"] == "amd64" && strings.TrimSpace(stopped) == "1", err
	})
}

func addOwnerFixture(t *testing.T, r *rig, f ownerFixture) (createdOwnerFixture, bool) {
	t.Helper()
	tag := "tikray:m3-owner-" + f.role
	key := "C.tag." + f.role
	add := append([]string{f.menu + "/add"}, f.args...)
	rep, err := ownerCall(r.ctx, r.admin, append(add, "=comment="+tag)...)
	if err != nil {
		var trap *routeros.DeviceError
		if !errors.As(err, &trap) {
			r.mark(t, key, "INCONCLUSIVE", "transport failed during tagged add")
			r.mark(t, "B.remove."+f.role, "INCONCLUSIVE", "no verified fixture ID")
			return createdOwnerFixture{}, false
		}
		schemaRejected := schemaTrap(err)
		rep, err = ownerCall(r.ctx, r.admin, add...)
		if err != nil || ownerAddID(rep) == "" {
			r.mark(t, key, "INCONCLUSIVE", "admin positive control without comment failed")
			r.mark(t, "B.remove."+f.role, "INCONCLUSIVE", "no verified fixture ID")
			return createdOwnerFixture{}, false
		}
		// Some menus may support commenting an existing row despite rejecting
		// comment during add. Report that distinction for installer atomicity.
		id := ownerAddID(rep)
		_, setErr := ownerCall(r.ctx, r.admin, f.menu+"/set", "=.id="+id, "=comment="+tag)
		schemaRejected = schemaRejected && schemaTrap(setErr)
		if errors.As(setErr, &trap) {
			_, setErr = ownerCall(r.ctx, r.admin, f.menu+"/comment", "=.id="+id, "=comment="+tag)
		}
		got, found, readErr := ownerRow(r.ctx, r.admin, f.menu, id)
		switch {
		case readErr != nil || !found:
			r.mark(t, key, "INCONCLUSIVE", "positive control readback failed")
		case got == tag:
			if f.role == "container" && ownerContainerReady(r.ctx, r, id) != nil {
				r.mark(t, key, "INCONCLUSIVE", "could not confirm completed stopped image import")
			} else {
				r.mark(t, key, "PASS", "exact tag supported only after add")
			}
		case setErr != nil && !(schemaRejected && schemaTrap(setErr)):
			r.mark(t, key, "INCONCLUSIVE", "no conclusive schema refusal for the tag property")
		default:
			r.mark(t, key, "FAIL", "admin add works but cannot persist exact tag")
		}
		return createdOwnerFixture{f, id}, true
	}
	id := ownerAddID(rep)
	if id == "" && f.role == "container" {
		id = ownerContainerID(r.ctx, r.admin, tag)
	}
	if id == "" {
		r.mark(t, key, "INCONCLUSIVE", "tagged add returned no fixture ID")
		r.mark(t, "B.remove."+f.role, "INCONCLUSIVE", "no verified fixture ID")
		return createdOwnerFixture{}, false
	}
	got, found, readErr := ownerRow(r.ctx, r.admin, f.menu, id)
	switch {
	case readErr != nil || !found:
		r.mark(t, key, "INCONCLUSIVE", "positive control readback failed")
	case got != tag:
		r.mark(t, key, "FAIL", "exact comment did not persist")
	case f.role == "container" && ownerContainerReady(r.ctx, r, id) != nil:
		r.mark(t, key, "INCONCLUSIVE", "could not confirm completed stopped image import")
	default:
		r.mark(t, key, "PASS", "admin add and exact tag readback")
	}
	return createdOwnerFixture{f, id}, true
}

func ownerWaitGone(ctx context.Context, c *routeros.Client, menu, id string) error {
	return ownerWait(ctx, 30*time.Second, func(ctx context.Context) (bool, error) {
		_, found, err := ownerRow(ctx, c, menu, id)
		return !found, err
	})
}

func removeOwnerFixture(t *testing.T, r *rig, row createdOwnerFixture) {
	t.Helper()
	key := "B.remove." + row.role
	tag, found, err := ownerRow(r.ctx, r.admin, row.menu, row.id)
	if err != nil || !found {
		r.mark(t, key, "INCONCLUSIVE", "admin could not verify fixture before removal")
		return
	}
	words := []string{row.menu + "/remove", "=.id=" + row.id}
	if tag != "tikray:m3-owner-"+row.role {
		// Untaggable admin-created controls can still support later probes,
		// but are not admissible evidence for restricted tagged teardown.
		_, _ = ownerCall(r.ctx, r.admin, words...)
		r.mark(t, key, "INCONCLUSIVE", "positive control had no exact ownership tag")
		return
	}
	_, restrictedErr := ownerCall(r.ctx, r.api, words...)
	if restrictedErr == nil && ownerWaitGone(r.ctx, r.admin, row.menu, row.id) == nil {
		r.mark(t, key, "PASS", "tagged row removed by restricted user")
		return
	}
	_, found, err = ownerRow(r.ctx, r.admin, row.menu, row.id)
	if err != nil {
		r.mark(t, key, "INCONCLUSIVE", "admin could not verify result of restricted removal")
		return
	}
	if !found && restrictedErr == nil {
		r.mark(t, key, "PASS", "tagged row removed by restricted user")
		return
	}
	if !found {
		r.mark(t, key, "INCONCLUSIVE", "row disappeared while restricted response failed")
		return
	}
	_, adminErr := ownerCall(r.ctx, r.admin, words...)
	if adminErr != nil || ownerWaitGone(r.ctx, r.admin, row.menu, row.id) != nil {
		r.mark(t, key, "INCONCLUSIVE", "admin removal positive control failed")
		return
	}
	var trap *routeros.DeviceError
	switch {
	case errors.As(restrictedErr, &trap):
		// Classify known policy traps internally. The router can put arbitrary
		// data in a trap, so no portion of that message goes into the result.
		message := strings.ToLower(trap.Error())
		if strings.Contains(message, "permission") || strings.Contains(message, "not permitted") || strings.Contains(message, "not allowed") {
			r.mark(t, key, "FAIL", "restricted policy denied removal that succeeded as admin")
		} else {
			r.mark(t, key, "FAIL", "router rejected restricted removal that succeeded as admin")
		}
	case restrictedErr == nil:
		r.mark(t, key, "FAIL", "restricted removal acknowledged but tagged row persisted")
	default:
		r.mark(t, key, "INCONCLUSIVE", "restricted transport failed before admin control")
	}
}
