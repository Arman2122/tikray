package runnerapi

import (
	"strings"
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
