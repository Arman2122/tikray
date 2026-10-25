package render

import (
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/xrayver"
)

func version(major, minor, patch int) xrayver.Version {
	return xrayver.Version{Major: major, Minor: minor, Patch: patch}
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name    string
		v       xrayver.Version
		wantErr string // a substring of the error; "" means no error
	}{
		{"one release before the TUN inbound", version(26, 1, 17), "TUN inbound"},
		{"zero version", xrayver.Version{}, "TUN inbound"},
		{"first release with the TUN inbound", version(26, 1, 18), ""},
		{"a newer major", version(27, 0, 0), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Check(tt.v)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("Check(%s) = %v, want nil", tt.v, err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("Check(%s) = nil, want an error naming %q", tt.v, tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("Check(%s) = %q, want it to name %q", tt.v, err, tt.wantErr)
			case err != nil && !strings.HasPrefix(err.Error(), "render: "):
				t.Fatalf("Check(%s) = %q, want the render: prefix", tt.v, err)
			}
		})
	}
}

// TestCheckNamesNewestFeature checks that, of several features a core lacks,
// Check names the one that needs the newest release.
func TestCheckNamesNewestFeature(t *testing.T) {
	saved := Features
	t.Cleanup(func() { Features = saved })
	Features = []Feature{
		{"older feature", version(26, 1, 18)},
		{"newest feature", version(26, 10, 21)},
		{"middle feature", version(26, 3, 27)},
	}
	err := Check(version(26, 1, 1))
	if err == nil || !strings.Contains(err.Error(), "newest feature") {
		t.Fatalf("Check = %v, want it to name the newest feature", err)
	}
	if err := Check(version(26, 10, 21)); err != nil {
		t.Fatalf("Check(26.10.21) = %v, want nil", err)
	}
}

func TestIsTested(t *testing.T) {
	tests := []struct {
		v    xrayver.Version
		want bool
	}{
		{version(26, 1, 17), false},
		{version(26, 1, 18), true},
		{version(26, 3, 27), true},
		{version(26, 10, 21), true},
		{version(26, 10, 22), false},
	}
	for _, tt := range tests {
		t.Run(tt.v.String(), func(t *testing.T) {
			if got := IsTested(tt.v); got != tt.want {
				t.Fatalf("IsTested(%s) = %v, want %v", tt.v, got, tt.want)
			}
		})
	}
}
