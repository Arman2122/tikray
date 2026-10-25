package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Arman2122/tikray/internal/xraypolicy"
)

const (
	// maxNameRunes bounds a server's or a subscription's name.
	maxNameRunes = 128
	// minInterval is the shortest time between two fetches of a subscription.
	minInterval = time.Hour
	// maxSubnetBits is the longest prefix that still holds .1 to .3 and a
	// network address: a /29.
	maxSubnetBits = 29
)

var idRE = regexp.MustCompile(`^[0-9a-f]{8}$`)

// notProxies are the outbound protocols that are not proxies: freedom sends
// traffic out direct, blackhole drops it, dns answers it and loopback hands it
// back to xray's routing. A server using one would let kill-switch traffic
// out direct, so none may be a server.
var notProxies = map[string]bool{"freedom": true, "blackhole": true, "dns": true, "loopback": true}

// domainPrefixes are the matcher prefixes xray's router reads. A matcher
// without a prefix is a substring match.
var domainPrefixes = []string{"domain", "full", "keyword", "regexp", "geosite", "ext"}

// problems collects what is wrong with a state.
type problems []error

// add records a problem at path. Messages never repeat a URL or an outbound:
// those carry credentials, and errors end up in logs.
func (p *problems) add(path, format string, args ...any) {
	*p = append(*p, errors.New(path+": "+fmt.Sprintf(format, args...)))
}

// Validate reports everything wrong with the state, as one error that joins a
// problem per fault (see errors.Join), or nil if there is nothing wrong. Each
// problem starts with the path of the field at fault, such as
// "devices[1].address: ".
func (s State) Validate() error {
	var p problems
	subscriptions := p.subscriptions(s.Subscriptions)
	servers := p.servers(s.Servers, subscriptions)
	p.devices(s.Devices)
	p.policy("default_policy", s.DefaultPolicy)
	p.routing(s.Routing, servers)
	p.dns(s.DNS, s.DomesticResolver())
	p.network(s.Network)
	if !httpURL(s.Health.ProbeURL) {
		p.add("health.probe_url", "must be an absolute http or https URL")
	}
	return errors.Join(p...)
}

// ids checks the IDs of the entries of a list found at prefix, such as
// "servers", and returns the ones that are fine.
func (p *problems) ids(prefix string, ids []string) map[string]bool {
	first := make(map[string]int, len(ids))
	held := make(map[string]bool, len(ids))
	for i, id := range ids {
		path := fmt.Sprintf("%s[%d].id", prefix, i)
		if !idRE.MatchString(id) {
			p.add(path, "must be 8 lowercase hex digits")
		} else if j, dup := first[id]; dup {
			p.add(path, "duplicates %s[%d]", prefix, j)
		} else {
			first[id] = i
			held[id] = true
		}
	}
	return held
}

// name checks a name that every server and subscription needs.
func (p *problems) name(path, name string) {
	switch {
	case strings.TrimSpace(name) == "":
		p.add(path, "must not be empty")
	case utf8.RuneCountInString(name) > maxNameRunes:
		p.add(path, "must be at most %d characters", maxNameRunes)
	}
}

func (p *problems) subscriptions(subs []Subscription) map[string]bool {
	ids := make([]string, len(subs))
	for i, sub := range subs {
		ids[i] = sub.ID
	}
	held := p.ids("subscriptions", ids)
	for i, sub := range subs {
		path := fmt.Sprintf("subscriptions[%d]", i)
		p.name(path+".name", sub.Name)
		if !httpURL(sub.URL) {
			p.add(path+".url", "must be an absolute http or https URL")
		}
		if d := time.Duration(sub.Interval); d < minInterval {
			p.add(path+".interval", "is %s, want at least %s", d, minInterval)
		}
	}
	return held
}

func (p *problems) servers(servers []Server, subscriptions map[string]bool) map[string]bool {
	ids := make([]string, len(servers))
	for i, sv := range servers {
		ids[i] = sv.ID
	}
	held := p.ids("servers", ids)
	for i, sv := range servers {
		path := fmt.Sprintf("servers[%d]", i)
		p.name(path+".name", sv.Name)
		if sv.Subscription != "" && !subscriptions[sv.Subscription] {
			p.add(path+".subscription", "names no subscription: %q", sv.Subscription)
		}
		p.outbound(path+".outbound", sv.Outbound)
	}
	return held
}

// outbound checks that raw is the outbound object of a proxy and carries no
// tag, which tikray assigns, and that it is not one the newest xray-core
// refuses (see xraypolicy): one such server would make every config that holds
// it fail to load. Xray reads keys without regard to case, so the checks do
// the same.
func (p *problems) outbound(path string, raw json.RawMessage) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		p.add(path, "must be a JSON object")
		return
	}
	hasProtocol := false
	for _, key := range slices.Sorted(maps.Keys(obj)) {
		switch {
		case strings.EqualFold(key, "tag"):
			p.add(path+".tag", "must not be set: tikray tags the outbound itself")
		case strings.EqualFold(key, "protocol"):
			hasProtocol = true
			var protocol string
			if err := json.Unmarshal(obj[key], &protocol); err != nil || protocol == "" {
				p.add(path+".protocol", "must be a non-empty string")
			} else if notProxies[strings.ToLower(protocol)] {
				p.add(path+".protocol", "%q is not a proxy protocol", protocol)
			}
		}
	}
	if !hasProtocol {
		p.add(path+".protocol", "is required")
	}
	if err := xraypolicy.Check(raw); err != nil {
		reason := err.Error()
		var refusal *xraypolicy.Refusal
		if errors.As(err, &refusal) {
			reason = refusal.Reason
		}
		p.add(path, "%s", reason)
	}
}

func (p *problems) devices(devices []Device) {
	ok := make([]bool, len(devices))
	for i, d := range devices {
		path := fmt.Sprintf("devices[%d]", i)
		switch a := d.Address; {
		case !a.IsValid() || !a.Addr().Is4():
			p.add(path+".address", "must be an IPv4 address with a prefix length, such as 192.168.1.5/32")
		case a != a.Masked():
			p.add(path+".address", "has host bits set: want %s", a.Masked())
		default:
			ok[i] = true
			for j := range i {
				if ok[j] && a.Overlaps(devices[j].Address) {
					p.add(path+".address", "overlaps devices[%d] (%s)", j, devices[j].Address)
					break
				}
			}
		}
		p.policy(path+".policy", d.Policy)
	}
}

func (p *problems) policy(path string, pol Policy) {
	switch pol.Mode {
	case ModeSmart, ModeFull:
	case ModeDirect:
		if pol.KillSwitch {
			p.add(path+".kill_switch", "cannot be on in mode direct: direct traffic is never proxied")
		}
	default:
		p.add(path+".mode", "is %q, want direct, smart or full", pol.Mode)
	}
}

func (p *problems) routing(r Routing, servers map[string]bool) {
	if r.Pinned != "" && !servers[r.Pinned] {
		p.add("routing.pinned", "names no server: %q", r.Pinned)
	}
	for i, m := range r.BlockList {
		if msg := checkDomain(m); msg != "" {
			p.add(fmt.Sprintf("routing.block_list[%d]", i), "%s", msg)
		}
	}
	p.matchers("routing.domestic", r.Domestic.Domains, r.Domestic.IPs)
	for i, rule := range r.Rules {
		path := fmt.Sprintf("routing.rules[%d]", i)
		if len(rule.Domains) == 0 && len(rule.IPs) == 0 {
			p.add(path, "needs domains or ips")
		}
		p.matchers(path, rule.Domains, rule.IPs)
		switch rule.Action {
		case ActionServer:
			if rule.Server == "" {
				p.add(path+".server", "is required when the action is server")
			} else if !servers[rule.Server] {
				p.add(path+".server", "names no server: %q", rule.Server)
			}
		case ActionDirect, ActionProxy, ActionBlock:
			if rule.Server != "" {
				p.add(path+".server", "is only for the server action, not %s", rule.Action)
			}
		default:
			p.add(path+".action", "is %q, want direct, proxy, block or server", rule.Action)
		}
	}
}

// matchers checks a pair of domain and IP lists found at path.
func (p *problems) matchers(path string, domains, ips []string) {
	for i, m := range domains {
		if msg := checkDomain(m); msg != "" {
			p.add(fmt.Sprintf("%s.domains[%d]", path, i), "%s", msg)
		}
	}
	for i, ip := range ips {
		if msg := checkIP(ip); msg != "" {
			p.add(fmt.Sprintf("%s.ips[%d]", path, i), "%s", msg)
		}
	}
}

// dns checks the resolvers, where domestic is the domestic resolver's
// address (State.DomesticResolver).
func (p *problems) dns(d DNS, domestic netip.Addr) {
	if d.Domestic.IsValid() && !d.Domestic.Is4() {
		p.add("dns.domestic", "must be an IPv4 address")
	}
	switch a, err := netip.ParseAddr(d.Remote); {
	case !dnsRemote(d.Remote):
		p.add("dns.remote", "must be an https:// URL or an IPv4 address")
	case err == nil && a == domestic:
		// The plain queries to the domestic resolver go out direct, so the
		// remote resolver's would too, every name with them.
		p.add("dns.remote", "is %s, the domestic resolver: the remote resolver must be another one, or every lookup goes out without the proxy", a)
	}
}

func (p *problems) network(n Network) {
	switch sn := n.Subnet; {
	case !sn.IsValid() || !sn.Addr().Is4():
		p.add("network.subnet", "must be an IPv4 prefix, such as 172.31.255.0/29")
	case sn.Bits() > maxSubnetBits:
		p.add("network.subnet", "is too small: the router, tikray and the runner need .1 to .3 (use /%d or larger)", maxSubnetBits)
	case sn != sn.Masked():
		p.add("network.subnet", "has host bits set: want %s", sn.Masked())
	}
}

// checkDomain returns what is wrong with a domain matcher, or "" if it is
// fine.
func checkDomain(m string) string {
	if m == "" {
		return "must not be empty"
	}
	if strings.ContainsFunc(m, unicode.IsSpace) {
		return "must not contain whitespace"
	}
	prefix, value, prefixed := strings.Cut(m, ":")
	if !prefixed {
		return ""
	}
	if !slices.Contains(domainPrefixes, prefix) {
		return fmt.Sprintf("has unknown prefix %q: want one of domain:, full:, keyword:, regexp:, geosite:, ext: or none", prefix+":")
	}
	if value == "" {
		return fmt.Sprintf("needs a value after %s:", prefix)
	}
	if prefix == "regexp" {
		if _, err := regexp.Compile(value); err != nil {
			return "is not a valid regexp: " + err.Error()
		}
	}
	return ""
}

// checkIP returns what is wrong with an IP matcher, or "" if it is fine: a
// CIDR prefix or an address of either family, or geoip:<code>.
func checkIP(m string) string {
	if m == "" {
		return "must not be empty"
	}
	if strings.ContainsFunc(m, unicode.IsSpace) {
		return "must not contain whitespace"
	}
	if code, ok := strings.CutPrefix(m, "geoip:"); ok {
		if code == "" {
			return "needs a code after geoip:"
		}
		return ""
	}
	if _, err := netip.ParsePrefix(m); err == nil {
		return ""
	}
	if a, err := netip.ParseAddr(m); err == nil && a.Zone() == "" {
		return ""
	}
	return fmt.Sprintf("%q is not an address, a CIDR prefix or geoip:<code>", m)
}

// httpURL reports whether s is an absolute http or https URL.
func httpURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != ""
}

// dnsRemote reports whether s is an https:// DNS URL or a plain IPv4 address.
func dnsRemote(s string) bool {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Is4()
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Hostname() != ""
}
