package lab

import (
	"errors"
	"strings"
	"testing"
)

// RouterOS can print part of a file before reporting an error. Neither the
// caller nor the SSH failure log should get that output for a private read.
func TestPrivateCommandOutput(t *testing.T) {
	const sentinel = "private-fixture-value"
	for _, tc := range []struct {
		output string
		err    error
	}{
		{"failure: " + sentinel, nil},
		{sentinel, errors.New("SSH exit: " + sentinel)},
	} {
		out, err := commandOutput("private "+sentinel, []byte(tc.output), tc.err, true)
		if err == nil || out != "" || strings.Contains(err.Error(), sentinel) {
			t.Error("a failed private command included its command or output")
		}
	}
	out, err := commandOutput("private", []byte(sentinel+"\r\n"), nil, true)
	if err != nil || out != sentinel+"\n" {
		t.Error("a successful private read did not return the value")
	}
}
