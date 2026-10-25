//go:build linux

package main

import "testing"

func TestMemLimit(t *testing.T) {
	tests := map[string]string{
		"":      "128MiB", // unset: the default
		"off":   "",       // leave GOMEMLIMIT unset
		"64MiB": "64MiB",
		"1GiB":  "1GiB",
	}
	for in, want := range tests {
		if got := memLimit(in); got != want {
			t.Errorf("memLimit(%q) = %q, want %q", in, got, want)
		}
	}
}
