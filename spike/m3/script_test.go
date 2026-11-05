//go:build lab

package m3

import (
	"archive/tar"
	"bytes"
	"crypto/sha512"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The fixture is a tar archive with NULs and every byte value. Distinct chunks
// matter: swapping two equal chunks would make the order control meaningless.
func probeHash(t *testing.T, r *rig) {
	const key = "A.sha512"
	const chunk = 16 * 1024
	const remote = "m3-spike-sha512.tar"
	payload := make([]byte, 6*chunk+713)
	for i := range payload {
		payload[i] = byte(i + i/chunk)
	}
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	if w.WriteHeader(&tar.Header{Name: "layer.bin", Mode: 0600, Size: int64(len(payload))}) != nil {
		r.mark(t, key, "INCONCLUSIVE", "could not create archive header")
		return
	}
	if _, err := w.Write(payload); err != nil || w.Close() != nil {
		r.mark(t, key, "INCONCLUSIVE", "could not create archive fixture")
		return
	}
	original := buf.Bytes()
	if len(original)%chunk == 0 {
		r.mark(t, key, "INCONCLUSIVE", "fixture lacks a short final chunk")
		return
	}
	// Validate the exact byte length before reading. An extra byte after a
	// valid archive must also fail; /file/read need not report EOF as data.
	var script strings.Builder
	fmt.Fprintf(&script, `:local f "%s"; :local verdict "ACCEPT"; :if ([/file/get [/file/find where name=$f] size] != %d) do={:set verdict "LENGTH"}; `, remote, len(original))
	for off := 0; off < len(original); off += chunk {
		n := min(chunk, len(original)-off)
		sum := sha512.Sum512(original[off : off+n])
		fmt.Fprintf(&script, `:if ($verdict = "ACCEPT") do={:local b; :do {:set b ([/file/read file=$f offset=%d chunk-size=%d as-value]->"data")} on-error={:set verdict "READ-%d"}; :if ([:len $b] != %d) do={:set verdict "READ-%d"}; :if ($verdict = "ACCEPT") do={:local h; :do {:set h [:convert $b from=raw transform=sha512 to=hex]} on-error={:set verdict "TRANSFORM-%d"}; :if ([:len $h] != 128) do={:set verdict "TRANSFORM-%d"} else={:if ([:convert $h transform=lc] != "%x") do={:set verdict "DIGEST-%d"}}}}; `, off, n, off, n, off, off, off, sum, off)
	}
	script.WriteString(`:put ("M3-HASH-" . $verdict)`)
	damaged := bytes.Clone(original)
	damaged[chunk+37] ^= 0x40
	swapped := bytes.Clone(original)
	copy(swapped[chunk:2*chunk], original[2*chunk:3*chunk])
	copy(swapped[2*chunk:3*chunk], original[chunk:2*chunk])
	if bytes.Equal(swapped, original) {
		r.mark(t, key, "INCONCLUSIVE", "archive order control is ineffective")
		return
	}
	path := filepath.Join(t.TempDir(), remote)
	defer func() {
		_, _ = r.chr.RunPrivate(r.ctx, `/file/remove [/file/find where name="`+remote+`"]`)
	}()
	for _, sample := range []struct {
		data []byte
		want string
	}{
		{original, "M3-HASH-ACCEPT"}, {damaged, "M3-HASH-DIGEST-" + strconv.Itoa(chunk)},
		{original[:len(original)-1], "M3-HASH-LENGTH"}, {swapped, "M3-HASH-DIGEST-" + strconv.Itoa(chunk)},
	} {
		if err := os.WriteFile(path, sample.data, 0600); err != nil || r.chr.Push(r.ctx, path, remote) != nil {
			r.mark(t, key, "INCONCLUSIVE", "archive upload failed")
			return
		}
		out, err := r.chr.RunPrivate(r.ctx, script.String())
		got := strings.TrimSpace(out)
		if err != nil || got != sample.want {
			reason := "router script or transport returned no recognized verdict"
			if got == "M3-HASH-ACCEPT" || got == "M3-HASH-LENGTH" {
				reason = "unexpected accept or length verdict on archive control"
			}
			for off := 0; off < len(original); off += chunk {
				for _, stage := range []string{"READ", "TRANSFORM", "DIGEST"} {
					if got == fmt.Sprintf("M3-HASH-%s-%d", stage, off) {
						reason = fmt.Sprintf("unexpected archive %s verdict at offset %d", stage, off)
					}
				}
			}
			verdict := "FAIL"
			if err != nil || reason == "router script or transport returned no recognized verdict" {
				verdict = "INCONCLUSIVE"
			}
			r.mark(t, key, verdict, reason)
			return
		}
	}
	r.mark(t, key, "PASS", "router verified ordered binary chunks and rejected corruption, truncation and reordering")
}

// Exercise Netwatch itself: withdrawing the address in the WAN namespace
// makes CHR lose a live peer without interrupting its management connection.
func probeNetwatch(t *testing.T, r *rig) {
	const key = "D.netwatch"
	const peer = "203.0.113.249"
	const peerCIDR = peer + "/32"
	const name = "m3-probe-netwatch"
	const routeTag = "m3-probe-peer-route"
	open := []string{"tikray:m3-probe:dns-open-udp", "tikray:m3-probe:dns-open-tcp"}
	closed := []string{"tikray:m3-probe:dns-closed-udp", "tikray:m3-probe:dns-closed-tcp"}
	// One decoy starts enabled and one disabled, so a broad enable as well
	// as a broad disable can be detected.
	foreign := []string{"owner:" + open[0], "owner:" + open[1]}
	all := []string{open[0], open[1], closed[0], closed[1], foreign[0], foreign[1]}
	check := func(cmd string) bool {
		out, err := r.chr.RunPrivate(r.ctx, cmd+`; :put "M3-FIXTURE-OK"`)
		return err == nil && strings.TrimSpace(out) == "M3-FIXTURE-OK"
	}
	peerCmd := func(op string) bool {
		return r.net.Inet(r.ctx, "ip", "address", op, peerCIDR, "dev", "lo").Run() == nil
	}
	if !peerCmd("add") {
		r.mark(t, key, "INCONCLUSIVE", "could not add isolated peer address")
		return
	}
	peerUp := true
	defer func() {
		if peerUp {
			peerCmd("del")
		}
	}()
	if !check(`/ip/route/add dst-address=` + peerCIDR + ` gateway=198.51.100.254 comment="` + routeTag + `"`) {
		r.mark(t, key, "INCONCLUSIVE", "could not route to isolated peer")
		return
	}
	defer check(`/ip/route/remove [/ip/route/find where comment="` + routeTag + `"]`)
	for i, tag := range all {
		proto := []string{"udp", "tcp"}[i%2]
		disabled := "no"
		if i < 2 || i == 5 {
			disabled = "yes"
		}
		// Constrain all fixtures to a dedicated address even if the router is
		// reused for another capability in this run.
		if !check(`/ip/firewall/nat/add chain=dstnat action=dst-nat dst-address=192.0.2.249 protocol=` + proto + ` dst-port=53 to-addresses=192.0.2.248 to-ports=53 disabled=` + disabled + ` comment="` + tag + `"`) {
			r.mark(t, key, "INCONCLUSIVE", "could not add isolated DNS rule")
			return
		}
		defer check(`/ip/firewall/nat/remove [/ip/firewall/nat/find where comment="` + tag + `"]`)
	}
	ids := func() string {
		reply, err := r.admin.RunContext(r.ctx, "/ip/firewall/nat/print", "=.proplist=.id")
		if err != nil || len(reply.Re) < len(all) {
			return ""
		}
		var values []string
		for _, item := range reply.Re {
			if item.Map[".id"] == "" {
				return ""
			}
			values = append(values, item.Map[".id"])
		}
		return strings.Join(values, ",")
	}
	initial := ids()
	if initial == "" {
		r.mark(t, key, "INCONCLUSIVE", "could not read the baseline NAT rule IDs and order")
		return
	}
	action := func(verb string) string {
		var s strings.Builder
		for _, tag := range open {
			fmt.Fprintf(&s, `/ip/firewall/nat/%s [/ip/firewall/nat/find where comment="%s"]; `, verb, tag)
		}
		return s.String()
	}
	if !check(`/tool/netwatch/add host=` + peer + ` type=simple interval=1s timeout=600ms startup-delay=0s start-delay=0s comment="` + name + `" up-script={` + action("enable") + `} down-script={` + action("disable") + `}`) {
		r.mark(t, key, "INCONCLUSIVE", "netwatch fixture could not be installed")
		return
	}
	defer check(`/tool/netwatch/remove [/tool/netwatch/find where comment="` + name + `"]`)
	await := func(up bool) string {
		status := "down"
		if up {
			status = "up"
		}
		var cmd strings.Builder
		fmt.Fprintf(&cmd, `:local observed ([/tool/netwatch/get [/tool/netwatch/find where comment="%s"] status] = "%s"); :local ok true; `, name, status)
		for i, tag := range all {
			disabled := i == 5 || (i < 2 && !up)
			fmt.Fprintf(&cmd, `:if ([/ip/firewall/nat/get [/ip/firewall/nat/find where comment="%s"] disabled] != %t) do={:set ok false}; `, tag, disabled)
		}
		cmd.WriteString(`:if ($observed) do={:if ($ok) do={:put "M3-NETWATCH-READY"} else={:put "M3-NETWATCH-WRONG"}} else={:put "M3-NETWATCH-WAIT"}`)
		verdict := "INCONCLUSIVE"
		deadline := time.Now().Add(time.Minute)
		for time.Now().Before(deadline) {
			out, err := r.chr.RunPrivate(r.ctx, cmd.String())
			if err == nil {
				switch strings.TrimSpace(out) {
				case "M3-NETWATCH-READY":
					after := ids()
					if after == "" {
						return "INCONCLUSIVE"
					}
					if after != initial {
						return "FAIL"
					}
					return "PASS"
				case "M3-NETWATCH-WRONG":
					verdict = "FAIL"
				}
			}
			select {
			case <-r.ctx.Done():
				return "INCONCLUSIVE"
			case <-time.After(time.Second):
			}
		}
		return verdict
	}
	if verdict := await(true); verdict != "PASS" {
		r.mark(t, key, verdict, "live peer did not reach initial up state with intact DNS rules")
		return
	}
	if !peerCmd("del") {
		r.mark(t, key, "INCONCLUSIVE", "could not withdraw peer address")
		return
	}
	peerUp = false
	if verdict := await(false); verdict != "PASS" {
		r.mark(t, key, verdict, "lost peer did not disable only the open UDP and TCP rules")
		return
	}
	if !peerCmd("add") {
		r.mark(t, key, "INCONCLUSIVE", "could not restore peer address")
		return
	}
	peerUp = true
	if verdict := await(true); verdict != "PASS" {
		r.mark(t, key, verdict, "restored peer did not enable only the open UDP and TCP rules")
		return
	}
	r.mark(t, key, "PASS", "live peer down and recovery toggled only open DNS rules and preserved closed and foreign rules")
}
