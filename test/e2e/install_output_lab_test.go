//go:build lab

package e2e

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestInstallerRetryCategoryRetainsNativeInstruction(t *testing.T) {
	const category = "tikray: retry bootstrap"
	const native = category + "; check the core source and rerun install"
	wire := "m3-import-error=" + base64.StdEncoding.EncodeToString([]byte(native))
	_, err := installOutput(wire)
	if err == nil || err.Error() != native || !expectedRefusal(err, category) {
		t.Fatal("native retry instruction did not match its refusal category")
	}
	for _, unrelated := range []error{nil, errors.New("tikray: retry bootstrapper"), errors.New("installer refused")} {
		if expectedRefusal(unrelated, category) {
			t.Fatal("unrelated refusal satisfied the retry witness")
		}
	}
}

func TestPrivateImportFailureHidesOutput(t *testing.T) {
	const hidden = "private-witness"
	for _, tc := range []struct{ diagnostic, want string }{
		{"tikray: object conflict at " + hidden, "tikray: object conflict"},
		{"tikray: peer MAC collides with veth " + hidden, "tikray: peer MAC collides with veth"},
		{"syntax error (line 51 column 7) " + hidden, "installer syntax at line 51 column 7"},
		{"unexpected " + hidden, "installer refused"},
	} {
		wire := hidden + "\nm3-import-error=" + base64.StdEncoding.EncodeToString([]byte(tc.diagnostic))
		out, err := installOutput(wire)
		if err == nil || out != "" || err.Error() != tc.want || strings.Contains(err.Error(), hidden) {
			t.Fatal("private import failure had unsafe or missing category")
		}
	}
	if out, err := installOutput("malformed response " + hidden); err == nil || out != "" || strings.Contains(err.Error(), hidden) {
		t.Fatal("missing import acknowledgement exposed terminal contents")
	}
	if out, err := installOutput("successful terminal text\nm3-import-ok"); err != nil || out != "successful terminal text" {
		t.Fatal("success acknowledgement lost terminal output")
	}
}

func TestInstallProbeEvidenceIsFramed(t *testing.T) {
	const marker = "m3-witness-control-start=35471|end"
	if v, ok := installProbeValue("terminal notice\r\n"+marker+"\r\nconsole closed", "control-start"); !ok || v != "35471" {
		t.Fatal("a framed PID-start sample was lost")
	}
	for _, raw := range []string{"35471", marker + marker, "m3-witness-runner=35471|end", "m3-witness-control-start=35471|partial"} {
		if _, ok := installProbeValue(raw, "control-start"); ok {
			t.Fatal("incomplete or ambiguous control-start sample accepted")
		}
	}
}

func TestPrivateInstallerFileRequiresWholeFrame(t *testing.T) {
	const good = "m3-file|4|YQ0KYg==|end-file"
	if v, ok := installFileValue("console notice\n" + good + "\nup"); !ok || string(v) != "a\r\nb" {
		t.Fatal("exact private bytes lost")
	}
	for _, s := range []string{good + good, "m3-file|3|YQ0KYg==|end-file", "m3-file|4|YQ0K|end-file", "YQ0KYg=="} {
		if _, ok := installFileValue(s); ok {
			t.Fatal("ambiguous, truncated or unframed file accepted")
		}
	}
}
