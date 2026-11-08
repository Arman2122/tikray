//go:build lab

package m3

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/routeros"
	"github.com/Arman2122/tikray/internal/store"
	routerosfiles "github.com/Arman2122/tikray/routeros"
)

func TestUninstallInventoryMatchesCompiler(t *testing.T) {
	r := newRig(t)
	template, e := routerosfiles.Sources.ReadFile("uninstall.rsc")
	if e != nil {
		t.Fatal(e)
	}
	_, s, ok := strings.Cut(string(template), "    :local role do={")
	classifier, _, end := strings.Cut(s, "    :local menus ")
	if !ok || !end {
		t.Fatal("uninstall classifier missing")
	}
	var script strings.Builder
	script.WriteString("{\n:local role do={" + classifier)
	seen := map[string]bool{}
	for _, mode := range []store.Mode{store.ModeSmart, store.ModeFull} {
		for _, closed := range []bool{false, true} {
			st := store.Default()
			st.Devices = []store.Device{{Address: netip.MustParsePrefix("192.168.88.22/32"), MAC: "02:00:00:00:00:22", Policy: store.Policy{Mode: mode, KillSwitch: closed}}}
			project, e := routeros.Project(st)
			if e != nil {
				t.Fatal(e)
			}
			top := routeros.Topology{Subnet: st.Network.Subnet, LANList: "LAN", LANMembers: []string{"ether2"}, LANs: []routeros.LAN{{Interface: "ether2", Prefix: netip.MustParsePrefix("192.168.88.0/24")}}, RouterIPs: []netip.Addr{netip.MustParseAddr("192.168.88.1")}, WAN: []routeros.WANPath{{Interface: "ether1", Gateway: netip.MustParseAddr("198.51.100.254"), Network: netip.MustParsePrefix("198.51.100.0/24")}}, ForeignRoutingMarks: []string{"owner-wan"}}
			want, e := routeros.Desired(project, top, []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")})
			if e != nil {
				t.Fatal(e)
			}
			for _, obj := range want {
				key := obj.Menu + " " + obj.Comment
				if seen[key] {
					continue
				}
				seen[key] = true
				fmt.Fprintf(&script, ":if (![$role %q %q]) do={ :error %q }\n", obj.Menu, obj.Comment, "missing "+key)
			}
		}
	}
	script.WriteString(`:if ([$role "/system/script" "owner:tikray:watchdog-script"] or [$role "/user" "tikray:user-extra"] or [$role "/ip/firewall/address-list" "tikray:my-list"]) do={:error "foreign tag accepted"}; :put "covered" }`)
	file := filepath.Join(t.TempDir(), "uninstall-inventory.rsc")
	if os.WriteFile(file, []byte(script.String()), 0600) != nil || r.chr.Push(r.ctx, file, "uninstall-inventory.rsc") != nil {
		t.Fatal("fixture transfer")
	}
	v, e := r.chr.RunPrivate(r.ctx, `:onerror err in={ /import uninstall-inventory.rsc } do={ :put $err }`)
	if e != nil || !strings.Contains(v, "covered") {
		for key := range seen {
			if strings.Contains(v, "missing "+key) {
				t.Fatal("uninstall cannot remove", key)
			}
		}
		t.Fatal("uninstall inventory check failed")
	}
}
