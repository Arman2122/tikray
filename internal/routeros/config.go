package routeros

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Arman2122/tikray/internal/atomicfile"
	"github.com/Arman2122/tikray/internal/store"
)

// Installation is the installer's private 0600 handoff under the 0700 state
// directory. Only the public topology hints can enter a router snapshot.
type Installation struct {
	Version     int          `json:"version"`
	Address     string       `json:"address"`
	Username    string       `json:"username"`
	Password    string       `json:"password"`
	Fingerprint string       `json:"fingerprint"`
	Scope       InstallScope `json:"scope"`
}

func (Installation) String() string     { return "routeros: private installation" }
func (i Installation) GoString() string { return i.String() }

var errPrivate = errors.New("routeros: unreadable private installation or policy record")

func readPrivate(path string, out any, limit int64) (bool, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errPrivate
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > limit {
		return false, errPrivate
	}
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil || !dir.IsDir() || dir.Mode().Perm()&0077 != 0 {
		return false, errPrivate
	}
	b, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(b)) > limit {
		return false, errPrivate
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(out) != nil || dec.Decode(new(any)) != io.EOF {
		return false, errPrivate
	}
	return true, nil
}
func encodePrivate(v any, limit int) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil || len(b) > limit {
		return nil, errPrivate
	}
	return b, nil
}

func validView(v policyView) bool {
	if !v.RepairOnly && len(v.Repairs) > 0 {
		return false
	}
	if len(v.Sources) > 0 && !interfaceName(v.LANList) {
		return false
	}
	for i, s := range v.Sources {
		if !validPrefix(s.Prefix) || !validPolicy(s.Policy) || s.Policy.Mode == store.ModeDirect {
			return false
		}
		if i > 0 && (comparePrefix(v.Sources[i-1].Prefix, s.Prefix) >= 0 || v.Sources[i-1].Prefix.Overlaps(s.Prefix)) {
			return false
		}
	}
	for _, r := range v.Repairs {
		if !validPrefix(r.Source) || !validPolicy(r.From) || !validPolicy(r.To) || (r.DNSProtocol != "" && r.DNSProtocol != "tcp" && r.DNSProtocol != "udp") || r.DataOnly && r.DNSProtocol != "" {
			return false
		}
		if r.StraySource {
			if r.From != directPolicy || r.To != directPolicy || r.DataOnly {
				return false
			}
			i, _ := slices.BinarySearchFunc(v.Sources, r.Source.Addr(), func(s sourceClass, a netip.Addr) int { return s.Prefix.Addr().Compare(a) })
			if i < len(v.Sources) && v.Sources[i].Prefix.Overlaps(r.Source) || i > 0 && v.Sources[i-1].Prefix.Overlaps(r.Source) {
				return false
			}
			continue
		}
		// A repair is derived from one existing target class. A damaged
		// checkpoint must not authorize a broader temporary guard or purge.
		s, ok := sourceAt(v, number(r.Source.Addr()))
		if !ok || s.Policy != r.To || s.Prefix.Bits() > r.Source.Bits() {
			return false
		}
	}
	for _, ps := range [][]netip.Prefix{v.Local, v.Domestic} {
		for _, p := range ps {
			if !validPrefix(p) {
				return false
			}
		}
	}
	for _, a := range v.RouterIPs {
		if !a.Is4() {
			return false
		}
	}
	for _, r := range v.V6 {
		if r.Menu != ipv6Filter || !ownedRole(r.Menu, r.Comment) {
			return false
		}
		m := r.Props
		if r.Comment == "tikray:ipv6:jump" {
			if len(m) != 4 || m["action"] != "jump" || m["chain"] != "forward" || m["in-interface-list"] != v.LANList || m["jump-target"] != ipv6Chain {
				return false
			}
			continue
		}
		if m["chain"] != ipv6Chain || !interfaceName(m["in-interface"]) {
			return false
		}
		if m["action"] != "return" && (m["action"] != "reject" || m["reject-with"] != "icmp-admin-prohibited") {
			return false
		}
		if mac, ok := m["src-mac-address"]; ok {
			if _, valid := guardMAC(mac); !valid {
				return false
			}
		} else if m["action"] == "return" {
			return false
		}
		for k := range m {
			switch k {
			case "chain", "in-interface", "action", "reject-with", "src-mac-address":
			default:
				return false
			}
		}
	}
	return true
}

// A restored journal may describe a different installation. It cannot
// authorize probing its former clients or staging rules on another ingress.
func (s InstallScope) containsView(v policyView) bool {
	if len(s.LANs) == 0 {
		return true // No installer scope on an injected, offline engine.
	}
	if v.LANList != "" && v.LANList != s.LANList {
		return false
	}
	// A compiler can merge adjacent LAN prefixes in one source class.
	var networks []netip.Prefix
	for _, lan := range s.LANs {
		networks = append(networks, lan.Prefix)
	}
	ranges := prefixRanges(networks)
	for _, r := range v.Repairs {
		if r.StraySource && !rangeCovers(ranges, r.Source) {
			return false
		}
	}
	for _, src := range v.Sources {
		lo, hi := span(src.Prefix)
		if !slices.ContainsFunc(ranges, func(r addrRange) bool { return r.lo <= lo && hi <= r.hi }) {
			return false
		}
	}
	for _, r := range v.V6 {
		if iface := r.Props["in-interface"]; iface != "" && !slices.ContainsFunc(s.LANs, func(l LAN) bool { return l.Interface == iface }) {
			return false
		}
	}
	return true
}

// A missing file selects standalone mode. A configured installation with a
// bad credential, pin or scope fails before HTTPS starts. Network availability
// is determined asynchronously by Watch.
func OpenManaged(data string) (*Managed, error) {
	dir := filepath.Join(data, "state")
	var in Installation
	exists, err := readPrivate(filepath.Join(dir, "routeros.json"), &in, 1<<20)
	if err != nil {
		return nil, err
	}
	if !exists {
		if _, err := os.Lstat(filepath.Join(dir, "router-policy.json")); !errors.Is(err, os.ErrNotExist) {
			return nil, errPrivate
		}
		return nil, nil
	}
	return managedInstallation(dir, in)
}

func managedInstallation(dir string, in Installation) (*Managed, error) {
	h, port, e := net.SplitHostPort(in.Address)
	a, e2 := netip.ParseAddr(h)
	n, e3 := strconv.ParseUint(port, 10, 16)
	pin, e4 := hex.DecodeString(strings.ReplaceAll(in.Fingerprint, ":", ""))
	network := store.Network{Subnet: in.Scope.Subnet}
	if in.Version != 1 || e != nil || e2 != nil || e3 != nil || n == 0 || e4 != nil || len(pin) != 32 || in.Username != "tikray" || len(in.Password) == 0 || len(in.Password) > 4096 || store.ValidateRouterNetwork(network, nil) != nil || network.Router() != a || !interfaceName(in.Scope.LANList) || len(in.Scope.LANs) == 0 || !interfaceName(in.Scope.WAN.Interface) {
		return nil, errPrivate
	}
	switch strings.ToLower(in.Scope.LANList) {
	case "all", "none", "static", "dynamic":
		return nil, errPrivate
	}
	if len(in.Scope.LANs) > 128 || len(in.Scope.LocalLANs) > 128 || installInterface(in.Scope.WAN.Interface) {
		return nil, errPrivate
	}
	for i, l := range in.Scope.LANs {
		if !unicastNetwork(l.Prefix) || l.Prefix.Overlaps(network.Subnet) || !interfaceName(l.Interface) || installInterface(l.Interface) || l.Interface == in.Scope.WAN.Interface {
			return nil, errPrivate
		}
		for _, other := range in.Scope.LANs[:i] {
			if l.Prefix.Overlaps(other.Prefix) {
				return nil, errPrivate
			}
		}
	}
	for _, p := range in.Scope.LocalLANs {
		if !unicastNetwork(p) || p.Overlaps(network.Subnet) {
			return nil, errPrivate
		}
	}
	m := &Managed{cfg: ConnConfig{Address: in.Address, Username: in.Username, Password: in.Password, Fingerprint: in.Fingerprint}, scope: in.Scope, dir: dir}
	return m, nil
}

// InitInstallation is called under serve.lock. A repeat preserves the
// credential. A different router or topology must never inherit it.
func InitInstallation(data string, proposed Installation, recordIntent func() error) error {
	dir := filepath.Join(data, "state")
	path := filepath.Join(dir, "routeros.json")
	var previous Installation
	found, err := readPrivate(path, &previous, 1<<20)
	if err != nil {
		return errPrivate
	}
	if found {
		proposed.Password = previous.Password
		if !reflect.DeepEqual(previous, proposed) {
			return errPrivate
		}
		if _, err := managedInstallation(dir, previous); err != nil {
			return err
		}
		return recordIntent()
	}
	if _, err := os.Lstat(filepath.Join(dir, "router-policy.json")); !errors.Is(err, os.ErrNotExist) {
		return errPrivate
	}
	var entropy [32]byte
	rand.Read(entropy[:])
	proposed.Password = hex.EncodeToString(entropy[:])
	if _, err := managedInstallation(dir, proposed); err != nil {
		return err
	}
	// A crash after credential publication must never start the ordinary
	// managed service without its install gate.
	if err := recordIntent(); err != nil {
		return err
	}
	body, err := encodePrivate(proposed, 1<<20)
	if err != nil || atomicfile.WriteFile(path, body, 0600) != nil {
		return errPrivate
	}
	return nil
}

type Managed struct {
	cfg    ConnConfig
	scope  InstallScope
	dir    string
	mu     sync.RWMutex
	engine *Engine
	client *Client
}

func (m *Managed) Watch(ctx context.Context, notify func()) error {
	for ctx.Err() == nil {
		client, err := Dial(ctx, m.cfg)
		if err == nil {
			e := NewEngine(client, m.scope, m.dir)
			e.managedBindings = true
			m.mu.Lock()
			m.engine = e
			m.client = client
			m.mu.Unlock()
			notify()
			// Individual streams are hints. The service sweep is independent.
			for ctx.Err() == nil && client.ctx.Err() == nil {
				_ = e.Watch(ctx, notify)
				select {
				case <-ctx.Done():
				case <-client.ctx.Done():
				case <-time.After(30 * time.Second):
					notify()
				}
			}
			m.mu.Lock()
			m.engine = nil
			m.client = nil
			m.mu.Unlock()
			client.Close()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return ctx.Err()
}
func (m *Managed) current() *Engine { m.mu.RLock(); defer m.mu.RUnlock(); return m.engine }
func (m *Managed) Prepare(ctx context.Context, t Target) error {
	if e := m.current(); e != nil {
		return e.Prepare(ctx, t)
	}
	return ErrUnavailable
}
func (m *Managed) Reconcile(ctx context.Context, t Target) (Report, error) {
	if e := m.current(); e != nil {
		return e.Reconcile(ctx, t)
	}
	return Report{}, ErrUnavailable
}
func (m *Managed) Leases(ctx context.Context) ([]LeaseInfo, error) {
	e := m.current()
	if e == nil {
		return nil, ErrUnavailable
	}
	ls, err := e.Leases(ctx)
	if err != nil {
		return nil, err
	}
	for i := range ls {
		if strings.Contains(ls[i].Name, m.cfg.Password) {
			ls[i].Name = ""
		}
	}
	return ls, nil
}
