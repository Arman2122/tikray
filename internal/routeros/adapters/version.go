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
	minor   uint64
	patch   uint64
	channel string
	goarch  string
	chr     bool
}

// SupportedVersion reports whether version names a supported stable or
// long-term RouterOS v7 release (with or without its release label).
func SupportedVersion(version string) bool {
	_, _, _, _, ok := parseSupportedRelease(version)
	return ok
}

// Installed selects from the installed release catalog, without consulting the
// mutable upgrade preference. A long-term install may select stable upgrades.
func Installed(version, arch, board string) (Profile, error) {
	_, _, _, channel, ok := parseSupportedRelease(version)
	if !ok {
		return Profile{}, errors.New("routeros: unsupported version")
	}
	return Select(version, channel, arch, board)
}

// Select accepts verified RouterOS v7 release lines (7.25.x stable, 7.24.6+
// long-term, and legacy 7.23.8+ long-term), stable or long-term channels,
// ARM64 devices, and x86_64 CHR. A resource version may include a supported
// release label, independent of the selected upgrade channel. RouterOS 7.25+
// omits the channel suffix from /system/resource version strings. Unknown
// minor branches need evidence before writes.
func Select(version, channel, arch, board string) (Profile, error) {
	if channel != "stable" && channel != "long-term" {
		return Profile{}, errors.New("routeros: unsupported channel")
	}
	release, minor, patch, defaultChannel, ok := parseSupportedRelease(version)
	if !ok {
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
	return Profile{
		version: release,
		minor:   minor,
		patch:   patch,
		channel: defaultChannel,
		goarch:  goarch,
		chr:     chr,
	}, nil
}

func parseSupportedRelease(version string) (release string, minor, patch uint64, channel string, ok bool) {
	if len(version) > 64 {
		return "", 0, 0, "", false
	}
	release = releaseVersion(version)
	parts := strings.Split(release, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return "", 0, 0, "", false
	}
	var numbers [3]uint64
	for i, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return "", 0, 0, "", false
		}
		for j := range part {
			if part[j] < '0' || part[j] > '9' {
				return "", 0, 0, "", false
			}
		}
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return "", 0, 0, "", false
		}
		numbers[i] = n
	}
	if numbers[0] != 7 {
		return "", 0, 0, "", false
	}
	// Non-canonical zero patch (e.g. 7.25.0) is never issued by RouterOS.
	if len(parts) == 3 && numbers[2] == 0 {
		return "", 0, 0, "", false
	}
	switch numbers[1] {
	case 25:
		// 7.25 and 7.25.x stable releases (e.g. 7.25.1).
		return release, numbers[1], numbers[2], "stable", true
	case 24:
		// 7.24.6+ long-term branch.
		if len(parts) == 3 && numbers[2] >= 6 {
			return release, numbers[1], numbers[2], "long-term", true
		}
	case 23:
		// 7.23.8+ legacy long-term compatibility for in-place upgrades.
		if len(parts) == 3 && numbers[2] >= 8 {
			return release, numbers[1], numbers[2], "long-term", true
		}
	}
	return "", 0, 0, "", false
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

// Channel returns the release line's channel ("stable" or "long-term").
func (p Profile) Channel() string { return p.channel }

// ReleaseLine returns the verified major.minor branch ("7.25", "7.24", "7.23").
func (p Profile) ReleaseLine() string {
	if p.version == "" {
		return ""
	}
	return "7." + strconv.FormatUint(p.minor, 10)
}

// SupportsVethIPPreserve reports whether RouterOS preserves container VETH IPs
// across stop/start cycles (introduced in RouterOS 7.24).
func (p Profile) SupportsVethIPPreserve() bool { return p.version != "" && p.minor >= 24 }

// SupportsDynamicARPInspection reports whether the bridge subsystem includes
// RouterOS 7.25+ Dynamic ARP Inspection and IP Source Guard support.
func (p Profile) SupportsDynamicARPInspection() bool { return p.version != "" && p.minor >= 25 }

// InstallerVersionPattern returns a POSIX ERE matching compatible RouterOS
// patch releases on the same verified release line.
func (p Profile) InstallerVersionPattern() string {
	if p.version == "" {
		return ""
	}
	switch p.minor {
	case 25:
		return `^7\.25(\.[1-9][0-9]*)?$`
	case 24:
		return `^7\.24\.([6-9]|[1-9][0-9]+)$`
	case 23:
		return `^7\.23\.([8-9]|[1-9][0-9]+)$`
	default:
		return ""
	}
}

// UsesIngressRouting selects the post-7.20.7 container networking model: the
// runner discovers its ingress from the default route and routes ingress to TUN.
func (p Profile) UsesIngressRouting() bool { return p.version != "" }

// MountSyntax returns the mount list, container list reference and mode fields.
// All supported v7 releases enforce mode=ro for the runner's read-only mounts.
func (p Profile) MountSyntax() (list, containerLists, mode string) {
	if p.version == "" {
		return "", "", ""
	}
	return "list", "mountlists", "mode"
}

// MemoryFields returns the measured container memory fields. Empty values mean
// unproven, not absent; installation must preflight any required unknown field.
func (p Profile) MemoryFields() (high, max string) {
	if p.version != "" {
		return "memory-high", "memory-max"
	}
	return "", ""
}

// RestartPolicyField follows the same evidence boundary as MemoryFields.
func (p Profile) RestartPolicyField() string {
	if p.version != "" {
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
		"/ip/arp", "/interface/bridge/host", "/ip/firewall/raw",
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
	if p.version == "" {
		return false
	}
	// These comments were proven during owner-run installation and teardown.
	// Comment support alone does not establish restricted deletion rights.
	switch menu {
	case "/user", "/user/group", "/ip/arp", "/interface/bridge/host", "/ip/firewall/raw":
		return false
	}
	return p.AcceptsComment(menu) || menu == "/ip/firewall/connection"
}
