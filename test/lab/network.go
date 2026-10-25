package lab

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// QEMU tap devices for CHR ether1 (WAN) and ether2 (LAN).
const (
	TapWAN = "tklab-tapw"
	TapLAN = "tklab-tapl"
)

const (
	brWAN    = "tklab-wan"
	brLAN    = "tklab-lan"
	nsInet   = "tklab-inet"
	nsClient = "tklab-client"
)

var hostRoutes = [][]string{
	{"172.31.255.0/29", "via", "198.51.100.2"},
	{"203.0.113.0/24", "via", "198.51.100.254"},
}

// Network is the host side of the lab: a WAN bridge shared by the host, the
// fake internet (netns tklab-inet) and CHR ether1, and a LAN bridge shared by
// the test client (netns tklab-client) and CHR ether2.
type Network struct{}

// SetupNetwork builds the lab address plan, removing leftovers from a crashed
// run first.
func SetupNetwork(ctx context.Context) (*Network, error) {
	n := &Network{}
	n.Teardown()
	steps := [][]string{
		{"ip", "link", "add", brWAN, "type", "bridge"},
		{"ip", "addr", "add", "198.51.100.1/24", "dev", brWAN},
		{"ip", "link", "set", brWAN, "up"},
		{"ip", "link", "add", brLAN, "type", "bridge"},
		{"ip", "link", "set", brLAN, "up"},

		{"ip", "tuntap", "add", "dev", TapWAN, "mode", "tap"},
		{"ip", "link", "set", TapWAN, "master", brWAN, "up"},
		{"ip", "tuntap", "add", "dev", TapLAN, "mode", "tap"},
		{"ip", "link", "set", TapLAN, "master", brLAN, "up"},

		{"ip", "netns", "add", nsInet},
		{"ip", "link", "add", "tklab-inet-h", "type", "veth", "peer", "name", "wan0", "netns", nsInet},
		{"ip", "link", "set", "tklab-inet-h", "master", brWAN, "up"},
		{"ip", "-n", nsInet, "addr", "add", "198.51.100.254/24", "dev", "wan0"},
		{"ip", "-n", nsInet, "link", "set", "wan0", "up"},
		{"ip", "-n", nsInet, "link", "set", "lo", "up"},
		{"ip", "netns", "exec", nsInet, "sysctl", "-qw", "net.ipv4.ip_forward=1"},

		{"ip", "netns", "add", nsClient},
		{"ip", "link", "add", "tklab-cli-h", "type", "veth", "peer", "name", "eth0", "netns", nsClient},
		{"ip", "link", "set", "tklab-cli-h", "master", brLAN, "up"},
		{"ip", "-n", nsClient, "addr", "add", "192.168.88.10/24", "dev", "eth0"},
		{"ip", "-n", nsClient, "link", "set", "eth0", "up"},
		{"ip", "-n", nsClient, "link", "set", "lo", "up"},
		{"ip", "-n", nsClient, "route", "add", "default", "via", "192.168.88.1"},
	}
	for _, a := range []string{"203.0.113.10", "203.0.113.20", "203.0.113.30", "203.0.113.40", "203.0.113.41", "203.0.113.53", "203.0.113.54"} {
		steps = append(steps, []string{"ip", "-n", nsInet, "addr", "add", a + "/32", "dev", "lo"})
	}
	for _, r := range hostRoutes {
		steps = append(steps, append([]string{"ip", "route", "add"}, r...))
	}
	// Docker sets the FORWARD policy to DROP, and bridged frames pass through
	// iptables when br_netfilter is loaded; let lab bridge traffic through.
	if _, err := exec.LookPath("iptables"); err == nil {
		for _, br := range []string{brWAN, brLAN} {
			steps = append(steps,
				[]string{"iptables", "-I", "FORWARD", "-i", br, "-j", "ACCEPT"},
				[]string{"iptables", "-I", "FORWARD", "-o", br, "-j", "ACCEPT"})
		}
	}
	for _, s := range steps {
		if err := run(ctx, s...); err != nil {
			n.Teardown()
			return nil, err
		}
	}
	return n, nil
}

// Teardown removes everything SetupNetwork creates. It is safe to call more
// than once.
func (n *Network) Teardown() error {
	ctx := context.Background()
	for _, r := range hostRoutes {
		run(ctx, append([]string{"ip", "route", "del"}, r...)...)
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		for _, br := range []string{brWAN, brLAN} {
			for _, dir := range []string{"-i", "-o"} {
				for run(ctx, "iptables", "-D", "FORWARD", dir, br, "-j", "ACCEPT") == nil {
				}
			}
		}
	}
	for _, l := range []string{TapWAN, TapLAN, "tklab-inet-h", "tklab-cli-h", brWAN, brLAN} {
		run(ctx, "ip", "link", "del", l)
	}
	for _, ns := range []string{nsInet, nsClient} {
		run(ctx, "ip", "netns", "del", ns)
	}

	var left []string
	if b, err := exec.Command("ip", "-o", "link", "show").Output(); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "tklab-") {
				left = append(left, line)
			}
		}
	}
	if b, err := exec.Command("ip", "netns", "list").Output(); err == nil && strings.Contains(string(b), "tklab-") {
		left = append(left, string(b))
	}
	if len(left) > 0 {
		return fmt.Errorf("teardown left: %s", strings.Join(left, "; "))
	}
	return nil
}

// Inet returns a command that runs in the fake-internet namespace.
func (n *Network) Inet(ctx context.Context, name string, args ...string) *exec.Cmd {
	return inNetns(ctx, nsInet, name, args)
}

// Client returns a command that runs in the LAN client namespace.
func (n *Network) Client(ctx context.Context, name string, args ...string) *exec.Cmd {
	return inNetns(ctx, nsClient, name, args)
}

// inNetns runs name in a lab namespace without the host's proxy settings:
// lab traffic must never be sent to a proxy outside the lab.
func inNetns(ctx context.Context, ns, name string, args []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "ip", append([]string{"netns", "exec", ns, name}, args...)...)
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch strings.ToLower(k) {
		case "http_proxy", "https_proxy", "all_proxy", "no_proxy":
			continue
		}
		cmd.Env = append(cmd.Env, kv)
	}
	return cmd
}

func run(ctx context.Context, args ...string) error {
	b, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(b)))
	}
	return nil
}
