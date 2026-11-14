package routeros

import (
	"context"
	"net/netip"
	"reflect"
	"strings"

	"github.com/Arman2122/tikray/internal/store"
)

const (
	privateBridge = "/interface/bridge"
	privatePort   = "/interface/bridge/port"
	privateHost   = "/interface/bridge/host"
	privateVeth   = "/interface/veth"
	privateARP    = "/ip/arp"
)

type bindingPlan struct {
	first      []string
	identities []string // include the backing veth IDs, even if a name/MAC is reused
}

func (p *bindingPlan) change(cmd ...string) {
	if len(p.first) == 0 {
		p.first = cmd
	}
}

func bindingID(id string) bool {
	if len(id) < 2 || id[0] != '*' {
		return false
	}
	for _, r := range id[1:] {
		if !strings.ContainsRune("0123456789ABCDEFabcdef", r) {
			return false
		}
	}
	return true
}

// Checking the tag as well as the natural key catches an untagged collision
// even if the expected tagged row still exists elsewhere.
func (p *bindingPlan) row(o observation, menu, fields, tag string, keys ...string) (Row, error) {
	q := anyQuery([]string{"?comment=" + tag}, keys)
	rows, err := o.read(menu, ".id,comment,disabled,dynamic,"+fields, q...)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	if len(rows) != 1 {
		return nil, ErrPolicyConflict
	}
	r := rows[0]
	if r["comment"] != tag || !bindingID(r[".id"]) || onBit(r["disabled"]) || onBit(r["dynamic"]) {
		return nil, ErrPolicyConflict
	}
	p.identities = append(p.identities, menu+r[".id"])
	return r, nil
}

// The static ARP entry binds IP to the configured container-side MAC. The
// static forwarding entry then binds that MAC to the correct port. Turning
// off learning and unknown-unicast flooding closes the forwarding gap while
// a stopped or recreated port has no usable forwarding entry.
func observeBindings(o observation, subnet netip.Prefix) (bindingPlan, error) {
	var plan bindingPlan
	n := store.Network{Subnet: subnet}
	if store.ValidateRouterNetwork(n, nil) != nil {
		return plan, ErrPolicyConflict
	}
	br, err := plan.row(o, privateBridge, "name,protocol-mode,arp,vlan-filtering", "tikray:bridge", "?name=tikray")
	if err != nil {
		return plan, err
	}
	if br["name"] != "tikray" || br["protocol-mode"] != "none" || onBit(br["vlan-filtering"]) {
		return plan, ErrPolicyConflict
	}
	addr, err := plan.row(o, "/ip/address", "address,interface", "tikray:addr", "?interface=tikray")
	if err != nil {
		return plan, err
	}
	if addr["interface"] != "tikray" || addr["address"] != netip.PrefixFrom(n.Router(), subnet.Bits()).String() {
		return plan, ErrPolicyConflict
	}
	ports, err := o.read(privatePort, ".id,interface,comment", "?bridge=tikray")
	if err != nil {
		return plan, err
	}
	for _, r := range ports {
		if r["comment"] != "tikray:port-ctl" && r["comment"] != "tikray:port-runner" {
			return plan, ErrPolicyConflict
		}
	}

	var previousMAC string
	for _, side := range []string{"ctl", "runner"} {
		iface := "tikray-" + side
		ip := n.Tikray()
		if side == "runner" {
			ip = n.Runner()
		}
		v, err := plan.row(o, privateVeth, "name,address,gateway,mac-address,container-mac-address", "tikray:veth-"+side, "?name="+iface)
		if err != nil {
			return plan, err
		}
		mac, ok := guardMAC(v["container-mac-address"])
		if v["container-mac-address"] == "00:00:00:00:00:00" {
			// An unused veth can expose an all-zero peer MAC. Assign a
			// local address derived from its verified router-side MAC before
			// the container starts; never learn an identity from packets.
			host, valid := guardMAC(v["mac-address"])
			if !valid {
				return plan, ErrPolicyConflict
			}
			name := "tikray"
			tag := "tikray:tikray"
			prefix := "02:74:02:"
			if side == "runner" {
				name = "tikray-runner"
				tag = "tikray:runner"
				prefix = "02:74:03:"
			}
			cs, err := o.read("/container", "name,comment,interface,stopped", anyQuery([]string{"?interface=" + iface}, []string{"?name=" + name}, []string{"?comment=" + tag})...)
			if err != nil {
				return plan, err
			}
			if len(cs) > 1 || len(cs) == 1 && (cs[0]["name"] != name || cs[0]["comment"] != tag || cs[0]["interface"] != iface || !onBit(cs[0]["stopped"])) {
				return plan, ErrPolicyConflict
			}
			mac, ok = prefix+host[9:], true
			if mac == host {
				return plan, ErrPolicyConflict
			}
			plan.change(privateVeth+"/set", "=.id="+v[".id"], "=container-mac-address="+mac)
		}
		if !ok || mac == previousMAC || v["name"] != iface || v["address"] != netip.PrefixFrom(ip, subnet.Bits()).String() || v["gateway"] != n.Router().String() {
			return plan, ErrPolicyConflict
		}
		previousMAC = mac
		plan.identities = append(plan.identities, mac)
		portTag := "tikray:port-" + side
		port, err := plan.row(o, privatePort, "interface,bridge,learn,unknown-unicast-flood", portTag, "?interface="+iface)
		if err != nil {
			return plan, err
		}
		if port == nil {
			plan.change(privatePort+"/add", "=comment="+portTag, "=bridge=tikray", "=interface="+iface, "=learn=no", "=unknown-unicast-flood=no")
		} else {
			if port["bridge"] != "tikray" || port["interface"] != iface && !bindingID(port["interface"]) {
				return plan, ErrPolicyConflict
			}
			if port["interface"] != iface || !bindingOff(port["learn"]) || !bindingOff(port["unknown-unicast-flood"]) {
				plan.change(privatePort+"/set", "=.id="+port[".id"], "=interface="+iface, "=learn=no", "=unknown-unicast-flood=no")
			}
		}
		hostTag := "tikray:fdb-" + side
		host, err := plan.row(o, privateHost, "bridge,interface,on-interface,mac-address,local,vid", hostTag, "?bridge=tikray", "?mac-address="+mac, "?#&")
		if err != nil {
			return plan, err
		}
		if host == nil {
			plan.change(privateHost+"/add", "=comment="+hostTag, "=bridge=tikray", "=interface="+iface, "=mac-address="+mac)
		} else {
			if host["bridge"] != "tikray" || onBit(host["local"]) || host["interface"] != iface && !bindingID(host["interface"]) || host["vid"] != "" && host["vid"] != "0" {
				return plan, ErrPolicyConflict
			}
			if host["interface"] != iface || !strings.EqualFold(host["mac-address"], mac) {
				plan.change(privateHost+"/set", "=.id="+host[".id"], "=interface="+iface, "=mac-address="+mac)
			}
		}
		arpTag := "tikray:arp-" + side
		arp, err := plan.row(o, privateARP, "interface,address,mac-address,published,dhcp", arpTag, "?interface=tikray", "?address="+ip.String(), "?#&")
		if err != nil {
			return plan, err
		}
		if arp == nil {
			plan.change(privateARP+"/add", "=comment="+arpTag, "=interface=tikray", "=address="+ip.String(), "=mac-address="+mac)
		} else {
			if arp["interface"] != "tikray" || arp["address"] != ip.String() || onBit(arp["published"]) || onBit(arp["dhcp"]) {
				return plan, ErrPolicyConflict
			}
			if !strings.EqualFold(arp["mac-address"], mac) {
				plan.change(privateARP+"/set", "=.id="+arp[".id"], "=mac-address="+mac)
			}
		}
	}
	if br["arp"] != "reply-only" {
		plan.change(privateBridge+"/set", "=.id="+br[".id"], "=arp=reply-only")
	}
	return plan, nil
}

func bindingOff(v string) bool { return v == "no" || v == "false" }

// ReconcileBindings proves the current peer bindings. When repair is enabled,
// recreate or repair only after a complete observation of both peers. Never
// replay a write after a reconnect. On the next sweep we observe the result.
func ReconcileBindings(ctx context.Context, c Native, subnet netip.Prefix, repair bool) error {
	o := observation{ctx: ctx, c: c, gen: c.Generation()}
	if o.gen == 0 {
		return ErrUnavailable
	}
	for range 12 {
		plan, err := observeBindings(o, subnet)
		if err != nil {
			return err
		}
		if len(plan.first) == 0 {
			return nil
		}
		if !repair {
			return ErrPolicyConflict
		}
		next, err := observeBindings(o, subnet)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(plan, next) {
			return ErrPolicyConflict
		}
		markers, err := o.read("/system/script", ".id", anyQuery([]string{"?name=tikray-install-lock"}, []string{"?name=tikray-uninstall-state"}, []string{"?comment=tikray:uninstall-state"})...)
		if err != nil {
			return err
		}
		if len(markers) > 0 {
			return ErrUnavailable
		}
		if _, err = c.CommandAt(ctx, o.gen, plan.first); err != nil {
			return err
		}
	}
	return ErrPolicyConflict
}
