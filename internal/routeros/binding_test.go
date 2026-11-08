package routeros

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"
)

var bindingSubnet = netip.MustParsePrefix("172.30.252.0/29")

func bindingRouter() *diffRouter {
	f := newDiffRouter()
	f.insert("/interface/bridge", "tikray:bridge", map[string]string{"name": "tikray", "arp": "reply-only", "protocol-mode": "none"})
	f.insert("/ip/address", "tikray:addr", map[string]string{"interface": "tikray", "address": "172.30.252.1/29"})
	for _, p := range []struct{ side, addr, mac string }{{"ctl", "172.30.252.2", "02:11:22:33:44:02"}, {"runner", "172.30.252.3", "02:11:22:33:44:03"}} {
		name := "tikray-" + p.side
		f.insert("/interface/veth", "tikray:veth-"+p.side, map[string]string{"name": name, "address": p.addr + "/29", "gateway": "172.30.252.1", "container-mac-address": p.mac})
		f.insert("/interface/bridge/port", "tikray:port-"+p.side, map[string]string{"bridge": "tikray", "interface": name, "learn": "no"})
	}
	return f
}

func TestManagedSessionChecksBindingsBeforePolicy(t *testing.T) {
	f := bindingRouter()
	f.tag("tikray:veth-ctl").Comment = "owner:control"
	d := t.TempDir()
	if os.Chmod(d, 0700) != nil {
		t.Fatal("journal fixture")
	}
	e := NewEngine(f, InstallScope{Subnet: bindingSubnet}, d)
	e.managedBindings = true
	e.observe = func(context.Context, Native, InstallScope) (Actual, error) {
		t.Fatal("policy observed before private link was proved")
		return Actual{}, nil
	}
	if err := e.Prepare(t.Context(), Target{}); !errors.Is(err, ErrPolicyConflict) || len(f.writes) != 0 {
		t.Fatal("unproved container path admitted", err)
	}
}

func TestBindingRecoverySkipsUncertainWritesAndFencesUninstall(t *testing.T) {
	f := bindingRouter()
	f.lose = true
	if err := ReconcileBindings(t.Context(), f, bindingSubnet, true); err == nil || len(f.writes) != 1 {
		t.Fatal("uncertain write replayed", err)
	}
	f.lose = false
	f.insert("/system/script", "tikray:uninstall-state {}", map[string]string{"name": "tikray-uninstall-state"})
	if err := ReconcileBindings(t.Context(), f, bindingSubnet, true); err == nil || len(f.writes) != 1 {
		t.Fatal("changed bindings during uninstall", err)
	}
}

func TestBindingRepairTracksConfiguredPeerMAC(t *testing.T) {
	f := bindingRouter()
	repair := func() error { return ReconcileBindings(t.Context(), f, bindingSubnet, true) }
	if err := repair(); err != nil {
		t.Fatal(err)
	}
	n := len(f.writes)
	if n < 2 {
		t.Fatal("missing address bindings")
	}
	if err := repair(); err != nil || len(f.writes) != n {
		t.Fatal("steady binding rewrote router")
	}
	old := f.tag("tikray:arp-ctl").ID
	f.tag("tikray:veth-ctl").Props["container-mac-address"] = "02:22:33:44:55:02"
	if err := ReconcileBindings(t.Context(), f, bindingSubnet, false); err == nil || len(f.writes) != n {
		t.Fatal("stale ARP passed read-only proof")
	}
	if err := repair(); err != nil {
		t.Fatal(err)
	}
	if got := f.tag("tikray:arp-ctl"); got.ID != old || got.Props["mac-address"] != "02:22:33:44:55:02" {
		t.Fatal("wrong replacement MAC or ARP row touched")
	}
}

func TestBindingConflictBeforeMutation(t *testing.T) {
	for _, conflict := range []string{"address", "veth", "port", "mac"} {
		t.Run(conflict, func(t *testing.T) {
			f := bindingRouter()
			switch conflict {
			case "address":
				f.insert("/ip/arp", "owner", map[string]string{"interface": "tikray", "address": "172.30.252.3", "mac-address": "02:ab:cd:ef:00:03"})
			case "veth":
				f.tag("tikray:veth-runner").Comment = "owner"
			case "port":
				f.insert("/interface/bridge/port", "owner", map[string]string{"interface": "ether2", "bridge": "tikray"})
			case "mac":
				f.tag("tikray:veth-runner").Props["container-mac-address"] = f.tag("tikray:veth-ctl").Props["container-mac-address"]
			}
			err := ReconcileBindings(t.Context(), f, bindingSubnet, true)
			if !errors.Is(err, ErrPolicyConflict) || len(f.writes) != 0 {
				t.Fatal("ambiguous binding admitted a write", err)
			}
		})
	}
}
