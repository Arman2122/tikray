// Package adapters describes the RouterOS capabilities verified by the lab.
package adapters

import (
	"errors"
	"strconv"
	"strings"
)

// Profile is immutable after Select. Its zero value permits no capabilities.
type Profile struct {
	version string
	goarch  string
	chr     bool
}

// Installed selects from the installed release catalog, without consulting the
// mutable upgrade preference. A long-term install may select stable upgrades.
func Installed(version, arch, board string) (Profile, error) {
	channel := ""
	switch releaseVersion(version) {
	case "7.23.8":
		channel = "long-term"
	case "7.25":
		channel = "stable"
	default:
		return Profile{}, errors.New("routeros: unsupported version")
	}
	return Select(version, channel, arch, board)
}

// Select accepts only the measured releases, stable or long-term channels,
// ARM64 devices, and x86_64 CHR. A resource version may include a supported
// release label, independent of the selected upgrade channel. Unknown releases
// need evidence before writes.
func Select(version, channel, arch, board string) (Profile, error) {
	if channel != "stable" && channel != "long-term" {
		return Profile{}, errors.New("routeros: unsupported channel")
	}
	if len(version) > 64 {
		return Profile{}, errors.New("routeros: unsupported version")
	}
	release := releaseVersion(version)
	parts := strings.Split(release, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return Profile{}, errors.New("routeros: unsupported version")
	}
	var numbers [3]uint64
	for i, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return Profile{}, errors.New("routeros: unsupported version")
		}
		for j := range part {
			if part[j] < '0' || part[j] > '9' {
				return Profile{}, errors.New("routeros: unsupported version")
			}
		}
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return Profile{}, errors.New("routeros: unsupported version")
		}
		numbers[i] = n
	}
	if numbers[0] != 7 || !((numbers[1] == 25 && len(parts) == 2) ||
		(numbers[1] == 23 && numbers[2] == 8 && len(parts) == 3)) {
		return Profile{}, errors.New("routeros: unsupported version")
	}
	if !validBoard(board) {
		return Profile{}, errors.New("routeros: unsupported platform")
	}
	chr := board == "CHR" || strings.HasPrefix(board, "CHR ") && len(board) > 4 && board[4] != ' '
	goarch := ""
	switch arch {
	case "arm64":
		goarch = "arm64"
	case "x86_64":
		if chr {
			goarch = "amd64"
		}
	}
	if goarch == "" {
		return Profile{}, errors.New("routeros: unsupported platform")
	}
	// Raw board names are not needed after the platform check.
	return Profile{version: release, goarch: goarch, chr: chr}, nil
}

func releaseVersion(version string) string {
	for _, suffix := range []string{" (stable)", " (long-term)"} {
		if strings.HasSuffix(version, suffix) {
			return strings.TrimSuffix(version, suffix)
		}
	}
	return version
}

func validBoard(board string) bool {
	if len(board) == 0 || len(board) > 128 || board[0] == ' ' || board[len(board)-1] == ' ' {
		return false
	}
	for i := range board {
		if board[i] < 0x20 || board[i] > 0x7e {
			return false
		}
	}
	return true
}

func (p Profile) Version() string { return p.version }
func (p Profile) GOARCH() string  { return p.goarch }
func (p Profile) IsCHR() bool     { return p.chr }

// UsesIngressRouting selects the post-7.20.7 container networking model: the
// runner discovers its ingress from the default route and routes ingress to TUN.
func (p Profile) UsesIngressRouting() bool { return p.version != "" }

// MountSyntax returns the mount list, container list reference and mode fields.
// Both measured releases enforce mode=ro for the runner's read-only mounts.
func (p Profile) MountSyntax() (list, containerLists, mode string) {
	if p.version == "" {
		return "", "", ""
	}
	return "list", "mountlists", "mode"
}

// MemoryFields returns the measured container memory fields. Empty values mean
// unproven, not absent; installation must preflight any required unknown field.
func (p Profile) MemoryFields() (high, max string) {
	if p.version == "7.25" || p.version == "7.23.8" {
		return "memory-high", "memory-max"
	}
	return "", ""
}

// RestartPolicyField follows the same evidence boundary as MemoryFields.
func (p Profile) RestartPolicyField() string {
	if p.version == "7.25" || p.version == "7.23.8" {
		return "restart-policy"
	}
	return ""
}

// DiskFormatCommand records the lab's command vocabulary. It grants no right
// to format storage: installation must never format or repartition owner disks.
func (p Profile) DiskFormatCommand() string {
	if p.version == "" {
		return ""
	}
	return "/disk/format"
}

// ObservedNotifications reports only menus with witnessed deletion events.
// Notifications are hints, not proof of every edit; all reads need router-side
// scope filters. Route and conntrack notifications remain unproven.
// A filtered stream may omit tombstones whose old properties no longer match.
// Polling the scoped collection is still necessary for deletion repair.
func (p Profile) ObservedNotifications(menu string) bool {
	if p.version == "" {
		return false
	}
	switch menu {
	case "/ip/firewall/mangle", "/ip/firewall/filter", "/ipv6/firewall/filter",
		"/ip/firewall/nat", "/ip/firewall/address-list", "/ipv6/firewall/address-list",
		"/routing/table", "/tool/netwatch":
		return true
	}
	return false
}

// AcceptsComment reports measured storage of an exact ownership comment.
// A matching name or a known menu alone never proves that a row is owned.
func (p Profile) AcceptsComment(menu string) bool {
	if p.version == "" {
		return false
	}
	switch menu {
	case "/interface/bridge", "/interface/veth", "/interface/bridge/port", "/ip/address",
		"/routing/table", "/ip/route", "/ip/firewall/address-list", "/ipv6/firewall/address-list",
		"/ip/firewall/filter", "/ipv6/firewall/filter", "/ip/firewall/mangle", "/ip/firewall/nat",
		"/user/group", "/user", "/container/envs", "/container/mounts", "/container",
		"/system/script", "/system/scheduler", "/tool/netwatch":
		return true
	}
	return false
}

// UsesCertificateReceipt requires the approved tagged receipt for an installer
// certificate. A reused certificate remains unowned and must never be deleted.
func (p Profile) UsesCertificateReceipt() bool { return p.version != "" }

// CanRemoveRestricted reports measured removals under exactly read,write,api.
// The owner-run uninstaller removes tagged users/groups and receipt-verified
// certificates. Connection IDs are ephemeral, require affected-client filters,
// and confer no ownership over other rows in the connection table.
func (p Profile) CanRemoveRestricted(menu string) bool {
	if p.version == "" || menu == "/user" || menu == "/user/group" {
		return false
	}
	return p.AcceptsComment(menu) || menu == "/ip/firewall/connection"
}
