//go:build lab

package m3

import (
	"strings"
	"testing"
)

// The installed CA can acquire Wi-Fi clients after bootstrap. Selecting it
// as a manager's CA is a live dependency even before it issues a child.
func TestUninstallRefusesWirelessCertificates(t *testing.T) {
	_, cmd, remove := uninstallFixture(t)
	cmd("/interface/bridge/add name=tikray protocol-mode=none comment=tikray:bridge")
	before := cmd(`:put [/certificate/get [find where name="tikray-api"] fingerprint]`)
	if len(before) != 64 {
		t.Fatal("missing original certificate witness")
	}
	cmd("/certificate/add name=owner-wifi common-name=owner-wifi key-size=prime256v1 key-usage=key-cert-sign,digital-signature,tls-server,tls-client; /certificate/sign owner-wifi")
	check := func(field string) {
		t.Helper()
		if got := remove(); !strings.Contains(got, "wifi certificate dependency") {
			t.Fatal("uninstall did not refuse certificate reference before teardown", field, got)
		}
		if cmd(`:put [/certificate/get [find where name="tikray-api"] fingerprint]`) != before ||
			cmd(`:put [:len [/interface/bridge/find where name=tikray and comment="tikray:bridge"]]`) != "1" ||
			cmd(`:put [:len [/system/script/find where name="tikray-uninstall-state"]]`) != "0" {
			t.Fatal("refused uninstall changed certificate or installation", field)
		}
	}
	type consumer struct{ menu, field string }
	singles := []consumer{{"/interface/wifi/capsman", "ca-certificate"}, {"/interface/wifi/capsman", "certificate"}, {"/interface/wifi/cap", "certificate"}}
	profiles := []consumer{{"/interface/wifi/security", "eap-tls-certificate"}, {"/interface/wifi/configuration", "security.eap-tls-certificate"}, {"/interface/wifi", "security.eap-tls-certificate"}}
	if cmd(`:put [:len [/system/package/find where name=wireless and !disabled]]`) == "1" {
		singles = append(singles, consumer{"/caps-man/manager", "ca-certificate"}, consumer{"/caps-man/manager", "certificate"}, consumer{"/interface/wireless/cap", "certificate"})
		profiles = append(profiles, consumer{"/interface/wireless/security-profiles", "tls-certificate"})
	}
	if cmd(`:put [:len [/system/package/find where name=user-manager and !disabled]]`) == "1" {
		singles = append(singles, consumer{"/user-manager", "certificate"})
	}
	for _, ref := range singles {
		t.Log("checking singleton", ref.menu, ref.field)
		cmd(ref.menu + "/set " + ref.field + "=tikray-api")
		if cmd(":put ["+ref.menu+"/get "+ref.field+"]") != "tikray-api" {
			t.Fatal("certificate selection unavailable", ref.menu, ref.field)
		}
		check(ref.menu + " " + ref.field)
		if cmd(":put ["+ref.menu+"/get "+ref.field+"]") != "tikray-api" {
			t.Fatal("refusal changed certificate selection", ref.menu, ref.field)
		}
		cmd(ref.menu + "/set " + ref.field + "=owner-wifi")
	}
	for _, ref := range profiles {
		t.Log("checking profile", ref.menu, ref.field)
		extra := ""
		if ref.menu == "/interface/wifi" {
			// CHR hosts the CAP manager. A statically provisioned remote radio
			// exercises interface overrides without requiring radio hardware.
			extra = " radio-mac=02:74:00:00:4A:11 disabled=yes"
		}
		cmd(ref.menu + "/add name=m3-owner-eap " + ref.field + "=tikray-api" + extra)
		if cmd(":put ["+ref.menu+"/get [find where name=m3-owner-eap] "+ref.field+"]") != "tikray-api" {
			t.Fatal("profile has no certificate witness", ref.menu)
		}
		check(ref.menu + " " + ref.field)
		if cmd(":put ["+ref.menu+"/get [find where name=m3-owner-eap] "+ref.field+"]") != "tikray-api" {
			t.Fatal("refusal changed profile certificate", ref.menu)
		}
		cmd(ref.menu + "/remove [find where name=m3-owner-eap]")
	}
	if got := remove(); got != "" {
		t.Fatal("uninstall after owner released certificate", got)
	}
}
