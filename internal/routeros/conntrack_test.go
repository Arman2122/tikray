package routeros

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/store"
)

const ct4 = "/ip/firewall/connection"
const ct6 = "/ipv6/firewall/connection"

type connectionRouter struct {
	*diffRouter
	reads      [][]string
	beforeRead func([]string)
}

func (f *connectionRouter) CommandAt(ctx context.Context, g uint64, words []string) ([]Row, error) {
	if strings.HasSuffix(words[0], "/print") {
		f.reads = append(f.reads, slices.Clone(words))
		if f.beforeRead != nil {
			f.beforeRead(words)
		}
	}
	return f.diffRouter.CommandAt(ctx, g, words)
}
func (f *connectionRouter) flow(menu, src, dst, port string) string {
	return f.insert(menu, "", map[string]string{"src-address": src, "dst-address": dst, "protocol": "tcp", "src-port": "4567", "dst-port": port})
}
func (f *connectionRouter) row(id string) *Observed {
	for i := range f.rows {
		if f.rows[i].ID == id {
			return &f.rows[i]
		}
	}
	return nil
}
func changedViews() []policyView {
	p := netip.MustParsePrefix
	v := policyView{Sources: []sourceClass{{p("10.12.0.8/29"), store.Policy{Mode: store.ModeFull}}}, Local: []netip.Prefix{p("10.0.0.0/8")}, RouterIPs: []netip.Addr{netip.MustParseAddr("198.18.0.1")}}
	return []policyView{{}, v, {}, v}
}
func TestPurgeConnectionsByOriginalSource(t *testing.T) {
	f := &connectionRouter{diffRouter: newDiffRouter()}
	const target = "10.12.0.9"
	const external = "8.8.8.8"
	var deleted []string
	for _, tc := range []struct{ dst, port, proto string }{{external, "443", "tcp"}, {"10.0.0.1", "53", "udp"}, {"198.18.0.1", "53", "tcp"}} {
		id := f.flow(ct4, target, tc.dst, tc.port)
		f.row(id).Props["protocol"] = tc.proto
		deleted = append(deleted, id)
	}
	f.row(deleted[0]).Props["fasttrack"] = "true"
	var kept []string
	for _, tc := range []struct{ src, dst, port string }{{"10.12.0.18", external, "443"}, {external, target, "443"}, {target, "10.0.0.2", "80"}, {target, "198.18.0.1", "22"}, {target, "198.18.5.6", "8291"}} {
		kept = append(kept, f.flow(ct4, tc.src, tc.dst, tc.port))
	}
	// A management loopback outside the install interfaces still belongs
	// to the router and the compiler's dst-address-type=local bypass.
	f.insert("/ip/address", "", map[string]string{"address": "198.18.5.6/32"})
	owner := f.flow(ct4, target, external, "8080")
	f.row(owner).Props["connection-mark"] = "owner-voip"
	kept = append(kept, owner)
	f.afterWrite = func() { id := f.flow(ct4, target, external, "8443"); kept = append(kept, id) }
	n, err := purgeFlows(context.Background(), f, f.actual(), changedViews())
	if err != nil || n != len(deleted) || len(f.writes) != len(deleted) {
		t.Fatalf("purge count=%d error=%v", n, err)
	}
	for _, id := range deleted {
		if f.row(id) != nil {
			t.Fatal("stale binding survived")
		}
	}
	for _, id := range kept {
		if f.row(id) == nil {
			t.Fatal("unaffected or newly opened connection removed")
		}
	}
	discoveries := 0
	for _, q := range f.reads {
		if q[0] != ct4+"/print" {
			continue
		}
		if slices.Contains(q, "?src-address="+target) {
			continue
		}
		if !slices.Contains(q, "?<src-address=10.12.0.8") || !slices.Contains(q, "?>src-address=10.12.0.15") {
			t.Fatal("unscoped conntrack query")
		}
		discoveries++
	}
	if discoveries != 1 {
		t.Fatal("repeated scope discovery")
	}
}
func TestPurgeRechecksIdentityAndNeverReplays(t *testing.T) {
	for _, change := range []string{"port", "reply tuple", "owner mark", "reconnected", "lost acknowledgement", "false acknowledgement", "snapshot lags removal"} {
		t.Run(change, func(t *testing.T) {
			f := &connectionRouter{diffRouter: newDiffRouter()}
			id := f.flow(ct4, "10.12.0.10", "1.1.1.1", "443")
			f.beforeRead = func(q []string) {
				if q[0] != ct4+"/print" || !slices.Contains(q, "?.id="+id) {
					return
				}
				switch change {
				case "port":
					f.row(id).Props["dst-port"] = "22"
				case "reply tuple":
					f.row(id).Props["reply-src-address"] = "198.51.100.190"
				case "owner mark":
					f.row(id).Props["connection-mark"] = "owner"
				case "reconnected":
					f.gen++
				}
				f.beforeRead = nil
			}
			f.lose = change == "lost acknowledgement"
			if change == "false acknowledgement" {
				r := *f.row(id)
				f.afterWrite = func() { f.rows = append(f.rows, r) }
			}
			if change == "snapshot lags removal" {
				r := *f.row(id)
				f.afterWrite = func() {
					f.rows = append(f.rows, r)
					checks := 0
					f.beforeRead = func(q []string) {
						if q[0] != ct4+"/print" || !slices.Contains(q, "?.id="+id) {
							return
						}
						checks++
						if checks == 2 {
							f.rows = slices.DeleteFunc(f.rows, func(r Observed) bool { return r.ID == id })
						}
					}
				}
			}
			ctx := context.Background()
			if change == "false acknowledgement" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 25*time.Millisecond)
				defer cancel()
			}
			n, e := purgeFlows(ctx, f, f.actual(), changedViews())
			switch change {
			case "port", "owner mark", "reply tuple":
				if len(f.writes) != 0 || n != 0 || f.row(id) == nil {
					t.Fatal("stale identity was removed")
				}
			case "reconnected":
				if !errors.Is(e, ErrStaleGeneration) || len(f.writes) != 0 {
					t.Fatal("used stale generation")
				}
			case "lost acknowledgement", "false acknowledgement":
				if e == nil || len(f.writes) != 1 || n != 0 {
					t.Fatal("mutation was replayed or treated as verified")
				}
			case "snapshot lags removal":
				if e != nil || n != 1 || len(f.writes) != 1 {
					t.Fatal("connection removal was not verified")
				}
			}
		})
	}
}

func TestIncompleteIPv6ProofStillClosesIPv4(t *testing.T) {
	f := &connectionRouter{diffRouter: newDiffRouter()}
	fastTrackSettings(f, "true", "200")
	view := changedViews()[1]
	view.V6 = []Object{v6Disposition("ether2", tapMAC, "reject")}
	view.Sources = append(view.Sources, sourceClass{netip.MustParsePrefix("10.12.0.18/32"), store.Policy{Mode: store.ModeFull, KillSwitch: true}})
	closed := f.flow(ct4, "10.12.0.18", "1.1.1.1", "443")
	f.row(closed).Props["fasttrack"] = "true"
	open := f.flow(ct4, "10.12.0.9", "1.1.1.1", "443")
	n, err := purgeFlows(context.Background(), f, f.actual(), []policyView{{}, view})
	if !errors.Is(err, ErrIPv6FlowScope) || n != 1 || f.row(closed) != nil || f.row(open) == nil {
		t.Fatal("incomplete IPv6 evidence did not isolate the closed IPv4 flow")
	}
}

func TestNestedPendingScopesShareOneConnectionRead(t *testing.T) {
	f := &connectionRouter{diffRouter: newDiffRouter()}
	host := changedViews()[1]
	host.Sources = []sourceClass{{netip.MustParsePrefix("10.12.0.9/32"), store.Policy{Mode: store.ModeFull, KillSwitch: true}}}
	victim := f.flow(ct4, "10.12.0.9", "1.1.1.1", "443")
	f.row(victim).Props["connection-mark"] = "owner"
	peer := f.flow(ct4, "10.12.0.10", "1.1.1.1", "443")
	f.row(peer).Props["connection-mark"] = "owner"
	n, e := purgeFlows(context.Background(), f, f.actual(), []policyView{{}, changedViews()[1], host})
	if e != nil || n != 1 || f.row(victim) != nil || f.row(peer) == nil {
		t.Fatal("nested closed transition included an unrelated owner binding")
	}
	reads := 0
	for _, q := range f.reads {
		if q[0] == ct4+"/print" && !slices.ContainsFunc(q, func(w string) bool { return strings.HasPrefix(w, "?.id=") }) {
			reads++
		}
	}
	if reads != 1 {
		t.Fatal("nested source scopes repeated conntrack discovery")
	}
}

const tapMAC = "02:00:00:00:00:28"

func v6Disposition(iface, mac, action string) Object {
	props := map[string]string{"chain": ipv6Chain, "in-interface": iface, "action": action}
	if mac != "" {
		props["src-mac-address"] = mac
	}
	return object(ipv6Filter, "ipv6:test", props)
}
func fastTrackSettings(f *connectionRouter, active, packets string) string {
	return f.insert("/ipv6/settings", "", map[string]string{"disable-ipv6": "false", "forward": "true", "ipv6-fasttrack-active": active, "ipv6-fasttrack-packets": packets})
}

func TestFlowScopePreflightRetainsPriorPolicy(t *testing.T) {
	f := &connectionRouter{diffRouter: newDiffRouter()}
	settings := fastTrackSettings(f, "false", "13")
	views := []policyView{{}, {V6: []Object{v6Disposition("ether2", tapMAC, "reject")}}}
	if err := checkFlowScope(context.Background(), f, f.actual(), views); !errors.Is(err, ErrIPv6FlowScope) || len(f.writes) != 0 {
		t.Fatal("unprovable change admitted")
	}
	for _, q := range f.reads {
		if q[0] != "/ipv6/settings/print" {
			t.Fatal("preflight read an unnecessary identity")
		}
	}
	f.row(settings).Props["ipv6-fasttrack-packets"] = "0"
	if err := checkFlowScope(context.Background(), f, f.actual(), views); err != nil || len(f.writes) != 0 {
		t.Fatal("fresh verified change refused")
	}
}

func TestFinalPurgeKeepsNewClassAndDNSAfterLostAck(t *testing.T) {
	f := &connectionRouter{diffRouter: newDiffRouter()}
	views := changedViews()[:2]
	const src = "10.12.0.9"
	old := f.flow(ct4, src, "8.8.8.8", "443")
	fresh := f.flow(ct4, src, "8.8.4.4", "443")
	f.row(fresh).Props["connection-mark"] = "tikray-open"
	ft := f.flow(ct4, src, "9.9.9.9", "443")
	f.row(ft).Props["connection-mark"] = "tikray-open"
	f.row(ft).Props["fasttrack"] = "true"
	f.insert(firewallNAT, "tikray:dns-full-open-tcp", map[string]string{"action": "dst-nat", "to-addresses": "172.31.255.3", "to-ports": "53"})
	dns := f.flow(ct4, src, "8.8.4.4", "53")
	f.row(dns).Props["reply-src-address"] = "172.31.255.3"
	f.row(dns).Props["reply-src-port"] = "53"
	f.row(dns).Props["dstnat"] = "true"
	badDNS := f.flow(ct4, src, "9.9.9.9", "53")
	f.row(badDNS).Props["reply-src-address"] = "9.9.9.9"
	f.row(badDNS).Props["reply-src-port"] = "53"
	f.lose = true
	if _, e := purgeAfterSwitch(t.Context(), f, f.actual(), views); !errors.Is(e, ErrOutcomeUnknown) {
		t.Fatal("lost final acknowledgement hidden")
	}
	newOpen := f.flow(ct4, src, "8.8.8.8", "443")
	f.row(newOpen).Props["connection-mark"] = "tikray-open"
	if _, e := purgeAfterSwitch(t.Context(), f, f.actual(), views); e != nil {
		t.Fatal(e)
	}
	if f.row(old) != nil || f.row(ft) != nil || f.row(badDNS) != nil || f.row(fresh) == nil || f.row(newOpen) == nil || f.row(dns) == nil {
		t.Fatal("retry removed a valid binding or left a stale path")
	}
}

func TestFinalPurgeVerifiesRedirectAndTrackingFlags(t *testing.T) {
	for _, tc := range []string{"fallback", "old runner", "unknown fasttrack", "unknown NAT", "direct DNS"} {
		t.Run(tc, func(t *testing.T) {
			f := &connectionRouter{diffRouter: newDiffRouter()}
			views := changedViews()[:2]
			id := f.flow(ct4, "10.12.0.9", "8.8.8.8", "53")
			f.row(id).Props["reply-src-address"] = "10.12.0.1"
			f.row(id).Props["reply-src-port"] = "53"
			f.row(id).Props["dstnat"] = "true"
			f.insert(firewallNAT, "tikray:dns-full-open-tcp", map[string]string{"action": "dst-nat", "to-addresses": "172.31.255.3", "to-ports": "53", "disabled": "true"})
			f.insert(firewallNAT, "tikray:dns-router-full-open-tcp", map[string]string{"action": "redirect", "to-ports": "53"})
			a := f.actual()
			a.Topology.RouterIPs = []netip.Addr{netip.MustParseAddr("10.12.0.1")}
			a.Topology.LANs = []LAN{{Interface: "ether2", Prefix: netip.MustParsePrefix("10.12.0.0/24")}}
			switch tc {
			case "old runner":
				f.row(id).Props["reply-src-address"] = "172.31.255.3"
			case "unknown fasttrack":
				f.row(id).Props["fasttrack"] = "unexpected"
			case "unknown NAT":
				f.row(id).Props["dstnat"] = "unexpected"
			case "direct DNS":
				slices.Reverse(views)
				f.row(id).Props["dstnat"] = "false"
				f.row(id).Props["reply-src-address"] = "8.8.8.8"
			}
			n, err := purgeAfterSwitch(t.Context(), f, a, views)
			protocolError := strings.HasPrefix(tc, "unknown")
			if errors.Is(err, ErrProtocol) != protocolError || !protocolError && err != nil || (n > 0) != (tc == "old runner") {
				t.Fatal("incorrect DNS binding proof")
			}
		})
	}
}

func TestRoutingWriterScopePreflight(t *testing.T) {
	for _, tc := range []string{"disjoint", "owner", "opaque", "missing predicates", "opaque but disjoint"} {
		t.Run(tc, func(t *testing.T) {
			f := &connectionRouter{diffRouter: newDiffRouter()}
			id := f.flow(ct4, "10.12.0.9", "8.8.8.8", "443")
			a := f.actual()
			a.Topology.LANs = []LAN{{Interface: "ether2", Prefix: netip.MustParsePrefix("10.12.0.0/24")}}
			a.Topology.LANMembers = []string{"ether2"}
			a.Topology.ForeignRoutingMarks = []string{"owner-vpn"}
			match := map[string]string{"in-interface": "ether2", "protocol": "tcp", "src-address": "10.12.0.8/29", "dst-port": "443"}
			if tc == "disjoint" || tc == "opaque but disjoint" {
				match["dst-port"] = "22"
			}
			if tc != "missing predicates" {
				a.Topology.RoutingMarkWriters = []RoutingMarkWriter{{Mark: "owner-vpn", Match: match, Opaque: strings.Contains(tc, "opaque")}}
			}
			views := changedViews()[:2]
			conflict := tc == "opaque" || tc == "missing predicates"
			if e := checkFlowScope(t.Context(), f, a, views); errors.Is(e, errConflict) != conflict || len(f.writes) != 0 {
				t.Fatal("incorrect preflight")
			}
			n, e := purgeFlows(t.Context(), f, a, views)
			removed := tc == "disjoint" || tc == "opaque but disjoint"
			if errors.Is(e, errConflict) != conflict || (f.row(id) == nil) != removed || n != len(f.writes) {
				t.Fatal("incorrect owner connection removal")
			}
		})
	}
}

func TestFinalPurgeKeepsForeignConnectionMarkOnLoosening(t *testing.T) {
	for _, to := range []store.Mode{store.ModeDirect, store.ModeFull} {
		f := &connectionRouter{diffRouter: newDiffRouter()}
		old := changedViews()[1]
		old.Sources[0].Policy.KillSwitch = true
		next := policyView{}
		if to == store.ModeFull {
			next = changedViews()[1]
		}
		id := f.flow(ct4, "10.12.0.9", "8.8.8.8", "443")
		f.row(id).Props["connection-mark"] = "owner-path"
		n, err := purgeAfterSwitch(t.Context(), f, f.actual(), []policyView{old, next})
		if err != nil || n != 0 || f.row(id) == nil {
			t.Fatal("verified target preserves this owner path")
		}
	}
}
func TestPurgeIPv6FastTrackScope(t *testing.T) {
	for _, tc := range []string{"rule removed", "missing neighbor", "no fasttrack", "disabled", "interface", "relaxation", "removed exception", "new exception", "unused old MAC", "unreadable counters"} {
		t.Run(tc, func(t *testing.T) {
			f := &connectionRouter{diffRouter: newDiffRouter()}
			settings := fastTrackSettings(f, "false", "19")
			tighten := v6Disposition("ether2", tapMAC, "reject")
			ingress := v6Disposition("ether2", "", "reject")
			direct := v6Disposition("ether2", tapMAC, "return")
			other := v6Disposition("ether2", "02:00:00:00:00:45", "reject")
			views := []policyView{{}, {V6: []Object{tighten}}}
			a := f.actual()
			deleteKnown := false
			refuse := true
			switch tc {
			case "rule removed":
				deleteKnown = true
			case "missing neighbor":
				a.IPv6FastTrack = true
			case "no fasttrack":
				f.row(settings).Props["ipv6-fasttrack-packets"] = "0"
				refuse = false
			case "disabled":
				f.row(settings).Props["disable-ipv6"] = "true"
				refuse = false
			case "interface":
				views[1].V6 = []Object{direct, ingress}
			case "relaxation":
				slices.Reverse(views)
				refuse = false
			case "removed exception":
				views = []policyView{{V6: []Object{direct, ingress}}, {V6: []Object{ingress}}}
				deleteKnown = true
			case "new exception":
				views = []policyView{{V6: []Object{ingress}}, {V6: []Object{direct, ingress}}}
				refuse = false
			case "unused old MAC":
				views = []policyView{{V6: []Object{other}}, {V6: []Object{tighten}}}
				deleteKnown = true
			case "unreadable counters":
				delete(f.row(settings).Props, "ipv6-fasttrack-packets")
			}
			const ip = "2001:db8:1::10"
			if tc != "missing neighbor" {
				f.insert("/ipv6/neighbor", "", map[string]string{"address": ip, "mac-address": tapMAC, "interface": "ether2", "status": "reachable"})
			}
			victim := f.flow(ct6, ip, "2001:db8:2::1", "443")
			f.row(victim).Props["fasttrack"] = "true"
			keep := f.flow(ct6, ip, "2001:db8:2::1", "8443")
			peer := f.flow(ct6, "2001:db8:1::99", "2001:db8:2::1", "443")
			f.row(peer).Props["fasttrack"] = "true"
			n, e := purgeFlows(context.Background(), f, a, views)
			if refuse != errors.Is(e, ErrIPv6FlowScope) || (!refuse && e != nil) {
				t.Fatalf("coverage failure=%v", e)
			}
			if (deleteKnown && n != 1) || (!deleteKnown && n != 0) || (f.row(victim) == nil) != deleteKnown || f.row(keep) == nil || f.row(peer) == nil {
				t.Fatal("incorrect IPv6 invalidation")
			}
			for _, q := range f.reads {
				switch q[0] {
				case "/ipv6/neighbor/print":
					if !slices.Contains(q, "?address="+ip) && !(slices.Contains(q, "?interface=ether2") && slices.Contains(q, "?mac-address="+tapMAC)) {
						t.Fatal("foreign neighbor scope")
					}
				case ct6 + "/print":
					if !slices.Contains(q, "?src-address="+ip) {
						t.Fatal("unrelated IPv6 conntrack scope")
					}
				}
			}
		})
	}
}
