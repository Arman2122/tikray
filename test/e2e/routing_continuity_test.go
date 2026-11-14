package e2e

import (
	"maps"
	"net/netip"
	"strconv"
	"testing"

	"github.com/Arman2122/tikray/internal/routeros"
)

func TestRoutingPeerNeedsFreshBidirectionalAccounting(t *testing.T) {
	row := routeros.Row{
		".id": "*A", "protocol": "tcp", "tcp-state": "established", "assured": "true", "seen-reply": "true",
		"src-address": "192.168.88.110", "src-port": "31369", "dst-address": "93.184.216.248", "dst-port": "31945",
		"reply-src-address": "93.184.216.248", "reply-src-port": "31945", "reply-dst-address": "198.51.100.2", "reply-dst-port": "31369",
		"orig-packets": "130", "repl-packets": "130", "orig-bytes": "7500", "repl-bytes": "8100",
	}
	before, ok := establishedBinding(row, 7)
	if !ok || !before.warmed() {
		t.Fatal("expected a warmed assured TCP binding")
	}
	for _, tc := range []struct {
		name       string
		changes    routeros.Row
		generation uint64
		want       bool
	}{
		{"same handle", nil, 7, true},
		{"rotated handle with same flow", routeros.Row{".id": "*B"}, 7, true},
		{"wrong generation", nil, 8, false},
		{"missing handle", routeros.Row{".id": ""}, 7, false},
		{"different original port", routeros.Row{"src-port": "31379"}, 7, false},
		{"different reply port", routeros.Row{"reply-dst-port": "31379"}, 7, false},
		{"unassured", routeros.Row{"assured": "false"}, 7, false},
		{"not established", routeros.Row{"tcp-state": "syn-received"}, 7, false},
		{"one-way refresh", routeros.Row{"repl-packets": "130"}, 7, false},
		{"stale projection", routeros.Row{"orig-packets": "130", "repl-packets": "130", "orig-bytes": "7500", "repl-bytes": "8100"}, 7, false},
		{"same handle with lower counters", routeros.Row{"orig-packets": "2", "repl-packets": "1", "orig-bytes": "110", "repl-bytes": "65"}, 7, false},
		{"malformed counter", routeros.Row{"orig-bytes": "unavailable"}, 7, false},
	} {
		next := maps.Clone(row)
		maps.Copy(next, routeros.Row{"orig-packets": "194", "repl-packets": "194", "orig-bytes": "11400", "repl-bytes": "12400"})
		maps.Copy(next, tc.changes)
		after, parsed := establishedBinding(next, tc.generation)
		if got := parsed && after.freshSince(before); got != tc.want {
			t.Errorf("%s: got %t", tc.name, got)
		}
	}
}

// Conntrack can return a new native handle for the same live socket. A deliberately
// removed row can conversely resume forwarding that socket with fresh counters.
type tcpBinding struct {
	id                            string
	generation                    uint64
	endpoints                     [4]netip.AddrPort // origin source/destination, then reply source/destination
	originalPackets, replyPackets uint64
	originalBytes, replyBytes     uint64
}

func establishedBinding(row routeros.Row, generation uint64) (tcpBinding, bool) {
	b := tcpBinding{id: row[".id"], generation: generation}
	if b.id == "" || row["protocol"] != "tcp" || row["tcp-state"] != "established" || row["assured"] != "true" || row["seen-reply"] != "true" {
		return b, false
	}
	for i, field := range []string{"src", "dst", "reply-src", "reply-dst"} {
		ip, err := netip.ParseAddr(row[field+"-address"])
		port, e := strconv.ParseUint(row[field+"-port"], 10, 16)
		if err != nil || !ip.Is4() || e != nil || port == 0 {
			return b, false
		}
		b.endpoints[i] = netip.AddrPortFrom(ip, uint16(port))
	}
	valid := b.readCounters(row)
	return b, valid
}

func (b *tcpBinding) readCounters(row routeros.Row) bool {
	var e1, e2, e3, e4 error
	b.originalPackets, e1 = strconv.ParseUint(row["orig-packets"], 10, 64)
	b.replyPackets, e2 = strconv.ParseUint(row["repl-packets"], 10, 64)
	b.originalBytes, e3 = strconv.ParseUint(row["orig-bytes"], 10, 64)
	b.replyBytes, e4 = strconv.ParseUint(row["repl-bytes"], 10, 64)
	return e1 == nil && e2 == nil && e3 == nil && e4 == nil
}

// The 128 baseline exchanges dwarf the 64 probes used at each later boundary.
// A replaced entry cannot reach the saved watermark with the challenge alone.
func (b tcpBinding) warmed() bool {
	return b.originalPackets >= 112 && b.replyPackets >= 112 && b.originalBytes >= 6000 && b.replyBytes >= 6000
}

func (b tcpBinding) retains(p tcpBinding) bool {
	return b.generation == p.generation && b.endpoints == p.endpoints && b.originalPackets >= p.originalPackets && b.replyPackets >= p.replyPackets &&
		b.originalBytes >= p.originalBytes && b.replyBytes >= p.replyBytes
}

// Require progress from the projection taken after the tested change. This catches
// a stale pre-deletion print even when the old socket still returns direct echoes.
func (b tcpBinding) freshSince(p tcpBinding) bool {
	if !b.retains(p) {
		return false
	}
	return b.originalPackets-p.originalPackets >= 48 && b.replyPackets-p.replyPackets >= 48 &&
		b.originalBytes-p.originalBytes >= 48*6 && b.replyBytes-p.replyBytes >= 48*6
}

func TestRoutingOldSocketNeedsEvictionBeyondHandleChange(t *testing.T) {
	prior := tcpBinding{generation: 5, originalPackets: 140, replyPackets: 142, originalBytes: 8000, replyBytes: 8200}
	row := routeros.Row{".id": "*B", "connection-mark": "tikray-closed", "fasttrack": "false", "orig-packets": "2", "repl-packets": "1", "orig-bytes": "110", "repl-bytes": "65"}
	for _, tc := range []struct {
		name string
		row  routeros.Row
		gen  uint64
		want bool
	}{
		{"absent", nil, 5, true}, {"other session", nil, 6, false}, {"new closed tuple", row, 5, true},
		{"still accelerated", copyFields(row, routeros.Row{"fasttrack": "true"}), 5, false},
		{"only ID changed", copyFields(row, routeros.Row{"connection-mark": "no-mark", "orig-bytes": "8000", "repl-bytes": "8200"}), 5, false},
		{"old watermark survived", copyFields(row, routeros.Row{"orig-packets": "141"}), 5, false},
		{"missing counter", copyFields(row, routeros.Row{"orig-bytes": ""}), 5, false},
	} {
		if got := oldDirectEvicted(tc.row, prior, tc.gen); got != tc.want {
			t.Errorf("%s: got %t", tc.name, got)
		}
	}
}

func copyFields(row, change routeros.Row) routeros.Row {
	result := maps.Clone(row)
	maps.Copy(result, change)
	return result
}

// A native handle change alone is not eviction. The caller also challenges
// the original socket and requires its old WAN egress to be gone.
func oldDirectEvicted(row routeros.Row, prior tcpBinding, generation uint64) bool {
	if generation != prior.generation {
		return false
	}
	if len(row) == 0 {
		return true
	}
	var now tcpBinding
	return row[".id"] != "" && row["connection-mark"] == "tikray-closed" && row["fasttrack"] == "false" && now.readCounters(row) &&
		now.originalPackets < prior.originalPackets && now.replyPackets < prior.replyPackets && now.originalBytes < prior.originalBytes && now.replyBytes < prior.replyBytes
}
