package routeros

import (
	"context"
	"net/netip"
	"slices"

	"github.com/Arman2122/tikray/internal/auth"
)

// MakeStaticLease converts a single bound dynamic DHCP lease on a managed LAN
// into a static reservation so a device's IP stays fixed for policy routing.
// It is strictly scoped to bound leases inside the verified LAN topology and
// reads back the converted lease on the same session generation before
// succeeding. An already-static lease is returned without writing.
func (e *Engine) MakeStaticLease(ctx context.Context, addr netip.Addr) (LeaseInfo, error) {
	if !addr.IsValid() || !addr.Is4() {
		return LeaseInfo{}, ErrLeaseNotFound
	}
	if err := e.lock(ctx); err != nil {
		return LeaseInfo{}, err
	}
	defer func() { <-e.gate }()

	a, err := e.Snapshot(ctx)
	if err != nil {
		return LeaseInfo{}, err
	}
	if slices.Contains(a.Topology.RouterIPs, addr) {
		return LeaseInfo{}, ErrLeaseNotFound
	}
	var ifaces []string
	for _, lan := range a.Topology.LANs {
		if usableHost(lan.Prefix, addr) && !slices.Contains(ifaces, lan.Interface) {
			ifaces = append(ifaces, lan.Interface)
		}
	}
	if len(ifaces) == 0 {
		return LeaseInfo{}, ErrLeaseNotFound
	}

	o := observation{ctx: ctx, c: e.c, gen: a.Generation}
	type match struct {
		id, server string
		info       LeaseInfo
	}
	var matches []match
	for _, iface := range ifaces {
		servers, err := o.read("/ip/dhcp-server", "name,interface,relay,invalid,disabled", "?interface="+iface)
		if err != nil {
			return LeaseInfo{}, publicEngineError(err)
		}
		for _, s := range servers {
			if unavailableRow(s) {
				continue
			}
			if !interfaceName(s["name"]) || s["interface"] != iface || s["relay"] != "" && s["relay"] != "0.0.0.0" {
				return LeaseInfo{}, ErrPolicyConflict
			}
			rows, err := o.read("/ip/dhcp-server/lease", ".id,active-address,active-mac-address,host-name,dynamic",
				"?active-server="+s["name"], "?status=bound", "?active-address="+addr.String())
			if err != nil {
				return LeaseInfo{}, publicEngineError(err)
			}
			for _, r := range rows {
				gotAddr, err := netip.ParseAddr(r["active-address"])
				mac, valid := guardMAC(r["active-mac-address"])
				if err != nil || !valid || gotAddr != addr {
					return LeaseInfo{}, ErrPolicyConflict
				}
				name := r["host-name"]
				if !leaseLabel.MatchString(name) || uuidLabel.MatchString(name) || auth.PublicName(name) != name {
					name = ""
				}
				static := r["dynamic"] == "false" || r["dynamic"] == "no"
				matches = append(matches, match{
					id:     r[".id"],
					server: s["name"],
					info:   LeaseInfo{Address: gotAddr, MAC: mac, Interface: iface, Name: name, Static: static},
				})
			}
		}
	}
	if len(matches) == 0 {
		return LeaseInfo{}, ErrLeaseNotFound
	}
	if len(matches) > 1 {
		return LeaseInfo{}, ErrPolicyConflict
	}
	m := matches[0]
	if m.info.Static {
		return m.info, nil
	}
	if m.id == "" {
		return LeaseInfo{}, ErrPolicyConflict
	}
	if _, err := e.c.CommandAt(ctx, a.Generation, []string{"/ip/dhcp-server/lease/make-static", "=numbers=" + m.id}); err != nil {
		return LeaseInfo{}, publicEngineError(err)
	}
	rows, err := o.read("/ip/dhcp-server/lease", ".id,active-address,active-mac-address,host-name,dynamic",
		"?active-server="+m.server, "?status=bound", "?active-address="+addr.String())
	if err != nil {
		return LeaseInfo{}, publicEngineError(err)
	}
	if len(rows) != 1 || (rows[0]["dynamic"] != "false" && rows[0]["dynamic"] != "no") {
		return LeaseInfo{}, ErrUnavailable
	}
	m.info.Static = true
	return m.info, nil
}
