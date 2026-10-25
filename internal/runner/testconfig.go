package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// testTunPrefix names the TUN devices of a config under xray run -test:
// xray-test0, xray-test1 and so on, well within Linux's 15-byte limit.
const testTunPrefix = "xray-test"

// testConfig returns an xray config for xray run -test: config with the
// device of every TUN inbound renamed to testTunPrefix<n>, and true. xray
// before 26.10 creates and opens an inbound's TUN device while it tests a
// config (26.1.18 and 26.3.27 did in the M1 lab), and a TUN device cannot be
// opened twice: with the active xray holding xray0, the test of such a
// candidate failed with "device or resource busy". Only the device name
// differs from the config the candidate then runs with.
//
// Keys and the protocol are matched without regard to case, as xray reads
// them, and numbers keep their text. A config with no TUN inbound, or one
// this does not understand (not a single JSON object, comments, an inbound
// or its settings of another type), is returned as it is, with false, for
// xray to judge.
func testConfig(config []byte) ([]byte, bool) {
	d := json.NewDecoder(bytes.NewReader(config))
	d.UseNumber()
	var root map[string]any
	if err := d.Decode(&root); err != nil || root == nil {
		return config, false
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) { // more than one value
		return config, false
	}
	inbounds, ok := field(root, "inbounds")
	if !ok {
		return config, false
	}
	list, ok := inbounds.([]any)
	if !ok {
		return config, false
	}
	n := 0
	for _, in := range list {
		ib, ok := in.(map[string]any)
		if !ok {
			return config, false
		}
		proto, _ := field(ib, "protocol")
		if p, ok := proto.(string); !ok || !strings.EqualFold(p, "tun") {
			continue
		}
		var settings map[string]any
		switch s, _ := field(ib, "settings"); s := s.(type) {
		case nil: // absent or null: xray would use its default device name
			settings = map[string]any{}
			setField(ib, "settings", settings)
		case map[string]any:
			settings = s
		default:
			return config, false
		}
		setField(settings, "name", fmt.Sprintf("%s%d", testTunPrefix, n))
		n++
	}
	if n == 0 {
		return config, false
	}
	out, err := json.Marshal(root)
	if err != nil {
		return config, false
	}
	return out, true
}

// field returns m's value for key, which is matched without regard to case
// when m has no exact match.
func field(m map[string]any, key string) (any, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

// setField sets key in m and removes every other key that matches it without
// regard to case.
func setField(m map[string]any, key string, v any) {
	for k := range m {
		if strings.EqualFold(k, key) {
			delete(m, k)
		}
	}
	m[key] = v
}
