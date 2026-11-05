package runnerapi

import (
	"encoding/json"
	"errors"
	"io/fs"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestSelectionValidate(t *testing.T) {
	ok := Selection{Core: "26.10.21", Config: "config/" + strings.Repeat("a", 64) + ".json"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []Selection{
		{Core: "v26.10.21", Config: ok.Config}, {Core: "../26.10.21", Config: ok.Config},
		{Core: "26.10.21", Config: "../active.json"}, {Core: "26.10.21", Config: "config/x.json"},
		{Core: "26.10.21", Geo: "..", Config: ok.Config}, {Core: "26.10.21", Geo: "a/b", Config: ok.Config},
	}
	for _, s := range bad {
		if s.Validate() == nil {
			t.Errorf("%+v accepted", s)
		}
	}
}

func TestSelectionValidateGeo(t *testing.T) {
	cfg := "config/" + strings.Repeat("0", 64) + ".json"
	for _, geo := range []string{"", "26.10.21", "2026-10-21", "custom_1.v2", strings.Repeat("a", 64)} {
		if err := (Selection{Core: "26.10.21", Geo: geo, Config: cfg}).Validate(); err != nil {
			t.Errorf("geo %q refused: %v", geo, err)
		}
	}
	for _, geo := range []string{".", "a..b", ".hidden", "-x", "a b", "a\n", strings.Repeat("a", 65)} {
		if (Selection{Core: "26.10.21", Geo: geo, Config: cfg}).Validate() == nil {
			t.Errorf("geo %q accepted", geo)
		}
	}
}

func TestSelectionValidateConfig(t *testing.T) {
	good := strings.Repeat("f", 64)
	for _, cfg := range []string{
		"", "config/" + good, "config/" + good + ".json\n", "/config/" + good + ".json",
		"config/" + strings.Repeat("A", 64) + ".json", "config/" + strings.Repeat("a", 63) + ".json",
		"config/" + strings.Repeat("a", 65) + ".json", "config/../" + good + ".json",
	} {
		if (Selection{Core: "26.10.21", Config: cfg}).Validate() == nil {
			t.Errorf("config %q accepted", cfg)
		}
	}
	if (Selection{Config: "config/" + good + ".json"}).Validate() == nil {
		t.Error("empty core accepted")
	}
}

// ValidateConfig is what Selection.Config must satisfy, by itself: Adopt names
// a config with no selection around it.
func TestValidateConfig(t *testing.T) {
	good := strings.Repeat("0123456789abcdef", 4)
	if err := ValidateConfig("config/" + good + ".json"); err != nil {
		t.Errorf("a good name refused: %v", err)
	}
	for _, cfg := range []string{
		"", "config/" + good, "config/" + good + ".json\n", "/config/" + good + ".json", "config/" + good + ".json/",
		"config/" + strings.ToUpper(good) + ".json", "config/" + good[1:] + ".json", "config/" + good + "0.json",
		"config/../" + good + ".json", "config//" + good + ".json", "run/config/" + good + ".json",
	} {
		err := ValidateConfig(cfg)
		if err == nil {
			t.Errorf("config %q accepted", cfg)
		} else if !strings.HasPrefix(err.Error(), "runnerapi: invalid config") {
			t.Errorf("config %q: error %q, want the runnerapi prefix and \"invalid config\"", cfg, err)
		}
	}
}

func TestInvalidConfigDoesNotEchoInput(t *testing.T) {
	const value = "sensitive-input"
	err := ValidateConfig(value)
	if err == nil || strings.Contains(err.Error(), value) {
		t.Error("a rejected config name was echoed or accepted")
	}
}

func TestAdoptRequestWireName(t *testing.T) {
	b, err := json.Marshal(AdoptRequest{Config: "config/x.json"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"config":"config/x.json"}`; string(b) != want {
		t.Errorf("AdoptRequest JSON = %s, want %s", b, want)
	}
}

// The causes a runner may name are the texts Linux's errnos have in Go.
func TestTestCause(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the errno texts are Linux's")
	}
	for _, errno := range []syscall.Errno{
		syscall.ENOSPC, syscall.EDQUOT, syscall.EROFS, syscall.EIO, syscall.ENOENT, syscall.EACCES, syscall.EPERM,
		syscall.ENOMEM, syscall.EMFILE, syscall.ENFILE, syscall.ENOEXEC, syscall.ETXTBSY, syscall.EAGAIN,
	} {
		err := &fs.PathError{Op: "open", Path: "/data/cores/26.10.21/xray", Err: errno}
		if got := TestCause(err); got != errno.Error() {
			t.Errorf("TestCause(%v) = %q, want %q", err, got, errno.Error())
		}
	}
	for _, err := range []error{nil, errors.New("no space left on device"), syscall.EBADMSG} {
		if got := TestCause(err); got != "" {
			t.Errorf("TestCause(%v) = %q, want none", err, got)
		}
	}
	if len(testCauses) != 13 {
		t.Errorf("%d causes; the list above checks 13", len(testCauses))
	}
}
