package adapters_test

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/routeros/adapters"
)

func TestSelectRouterOSProfile(t *testing.T) {
	raw, err := os.ReadFile("testdata/profiles.json")
	if err != nil {
		t.Fatal("could not read shared profile examples")
	}
	var cases []struct {
		Name, Version, Channel, Arch, Board, WantVersion, WantArch, WantError string
		CHR                                                                   bool
	}
	if err := json.Unmarshal(raw, &cases); err != nil || len(cases) == 0 {
		t.Fatal("invalid shared profile examples")
	}
	for _, tt := range cases {
		t.Run(tt.Name, func(t *testing.T) {
			p, err := adapters.Select(tt.Version, tt.Channel, tt.Arch, tt.Board)
			if tt.WantError != "" {
				if err == nil || err.Error() != tt.WantError {
					t.Fatal("selection did not return the expected fixed error category")
				}
				assertUnsupportedProfile(t, p)
				return
			}
			if err != nil {
				t.Fatal("supported profile refused")
			}
			if p.Version() != tt.WantVersion || p.GOARCH() != tt.WantArch || p.IsCHR() != tt.CHR {
				t.Fatal("selected profile has incorrect release or platform")
			}
			if !p.UsesIngressRouting() {
				t.Error("profile lacks the measured ingress routing model")
			}
			list, lists, mode := p.MountSyntax()
			if list != "list" || lists != "mountlists" || mode != "mode" {
				t.Error("profile has incorrect mount syntax")
			}
			high, max := p.MemoryFields()
			if high != "memory-high" || max != "memory-max" || p.RestartPolicyField() != "restart-policy" {
				t.Error("installed-release container field vocabulary is incomplete")
			}
			if p.DiskFormatCommand() != "/disk/format" {
				t.Error("profile has incorrect disk command vocabulary")
			}
			assertMenuCapabilities(t, p)
		})
	}
	t.Run("zero value", func(t *testing.T) { assertUnsupportedProfile(t, adapters.Profile{}) })
	t.Run("metadata is not retained", func(t *testing.T) {
		canary := rand.Text()
		for i := range 4 {
			values := [4]string{"7.25", "stable", "arm64", "RB5009"}
			values[i] = canary
			p, err := adapters.Select(values[0], values[1], values[2], values[3])
			if strings.Contains(fmt.Sprintf("%#v", p), canary) || err != nil && strings.Contains(err.Error(), canary) {
				t.Fatal("selection retained private router metadata")
			}
		}
		p, err := adapters.Select("7.25", "stable", "x86_64", "CHR "+canary)
		if err != nil || !p.IsCHR() || strings.Contains(fmt.Sprintf("%#v", p), canary) {
			t.Fatal("selection mishandled a private hypervisor label")
		}
	})
}

func TestInstalledRouterOSProfile(t *testing.T) {
	for _, tt := range []struct {
		name, version, want string
	}{
		{"long term bare", "7.23.8", "7.23.8"},
		{"long term label", "7.23.8 (long-term)", "7.23.8"},
		{"stable bare", "7.25", "7.25"},
		{"stable label", "7.25 (stable)", "7.25"},
		{"testing label", "7.25 (testing)", ""},
		{"development label", "7.25 (development)", ""},
		{"unknown release", "7.25.1", ""},
		{"noncanonical zero patch", "7.25.0", ""},
		{"multiple labels", "7.25 (stable) (long-term)", ""},
		{"empty", "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, err := adapters.Installed(tt.version, "x86_64", "CHR QEMU Ubuntu 26.04 PC (i440FX + PIIX, 1996)")
			if tt.want == "" {
				if err == nil || err.Error() != "routeros: unsupported version" {
					t.Fatal("installed release did not return the expected fixed error category")
				}
				assertUnsupportedProfile(t, p)
				return
			}
			if err != nil || p.Version() != tt.want || p.GOARCH() != "amd64" || !p.IsCHR() {
				t.Fatal("installed release selection failed")
			}
		})
	}
	for _, metadata := range [][2]string{{"amd64", "CHR"}, {"x86_64", "x86"}, {"arm64", ""}} {
		p, err := adapters.Installed("7.25", metadata[0], metadata[1])
		if err == nil || err.Error() != "routeros: unsupported platform" {
			t.Fatal("installed release accepted unsupported platform")
		}
		assertUnsupportedProfile(t, p)
	}
}

func assertMenuCapabilities(t *testing.T, p adapters.Profile) {
	t.Helper()
	for _, tt := range []struct {
		menu                    string
		comment, notify, remove bool
	}{
		{"/interface/bridge", true, false, true},
		{"/interface/veth", true, false, true},
		{"/interface/bridge/port", true, false, true},
		{"/ip/address", true, false, true},
		{"/routing/table", true, true, true},
		{"/ip/route", true, false, true},
		{"/ip/firewall/address-list", true, true, true},
		{"/ipv6/firewall/address-list", true, true, true},
		{"/ip/firewall/filter", true, true, true},
		{"/ipv6/firewall/filter", true, true, true},
		{"/ip/firewall/mangle", true, true, true},
		{"/ip/firewall/nat", true, true, true},
		{"/user/group", true, false, false},
		{"/user", true, false, false},
		{"/container/envs", true, false, true},
		{"/container/mounts", true, false, true},
		{"/container", true, false, true},
		{"/system/script", true, false, true},
		{"/system/scheduler", true, false, true},
		{"/tool/netwatch", true, true, true},
		{"/certificate", false, false, false},
		{"/ip/firewall/connection", false, false, true},
		{"/ip/service", false, false, false},
		{"/ip/firewall/filter/", false, false, false},
		{"/unknown", false, false, false},
		{"", false, false, false},
	} {
		if p.AcceptsComment(tt.menu) != tt.comment || p.ObservedNotifications(tt.menu) != tt.notify || p.CanRemoveRestricted(tt.menu) != tt.remove {
			t.Errorf("incorrect capability for public menu %s", tt.menu)
		}
	}
	if !p.UsesCertificateReceipt() {
		t.Error("profile lacks the approved certificate ownership mechanism")
	}
}

func assertUnsupportedProfile(t *testing.T, p adapters.Profile) {
	t.Helper()
	list, lists, mode := p.MountSyntax()
	high, max := p.MemoryFields()
	if p.Version() != "" || p.GOARCH() != "" || p.IsCHR() || p.UsesIngressRouting() || list != "" || lists != "" || mode != "" || high != "" || max != "" || p.RestartPolicyField() != "" || p.DiskFormatCommand() != "" || p.UsesCertificateReceipt() {
		t.Error("unsupported profile exposes capability vocabulary")
	}
	for _, menu := range []string{"/ip/firewall/filter", "/certificate", "/user", "/ip/firewall/connection"} {
		if p.AcceptsComment(menu) || p.ObservedNotifications(menu) || p.CanRemoveRestricted(menu) {
			t.Error("unsupported profile permits a menu capability")
		}
	}
}
