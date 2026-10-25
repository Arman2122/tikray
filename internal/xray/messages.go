package xray

import (
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// The messages of the xray API calls the Client makes, encoded by hand: only
// the fields tikray uses. Every field number is from xray-core v26.10.21's
// protos; the comment beside it names the proto file and line (paths are
// relative to the xray-core repository). Fields not named here are skipped.

// Service and method names, as the gRPC path /<service>/<method> gives them:
// the proto's package, a dot, and the service. The observatory's package has
// "core" in it, unlike the other two.
const (
	statsService       = "xray.app.stats.command.StatsService"                  // app/stats/command/command.proto:3,85
	observatoryService = "xray.core.app.observatory.command.ObservatoryService" // app/observatory/command/command.proto:3,18
	routingService     = "xray.app.router.command.RoutingService"               // app/router/command/command.proto:3,118

	methodQueryStats        = "QueryStats"        // app/stats/command/command.proto:88
	methodGetSysStats       = "GetSysStats"       // app/stats/command/command.proto:89
	methodGetOutboundStatus = "GetOutboundStatus" // app/observatory/command/command.proto:19
	methodGetBalancerInfo   = "GetBalancerInfo"   // app/router/command/command.proto:123
)

// Fields of the requests.
const (
	fieldQueryStatsPattern protowire.Number = 1 // app/stats/command/command.proto:26, QueryStatsRequest.pattern (string)
	fieldQueryStatsReset   protowire.Number = 2 // app/stats/command/command.proto:27, QueryStatsRequest.reset (bool)
	// SysStatsRequest (app/stats/command/command.proto:34) and GetOutboundStatusRequest
	// (app/observatory/command/command.proto:11) have no fields.
	fieldBalancerInfoTag protowire.Number = 1 // app/router/command/command.proto:81, GetBalancerInfoRequest.tag (string)
)

// Fields of the answers.
const (
	// QueryStatsResponse and Stat.
	fieldQueryStatsStat protowire.Number = 1 // app/stats/command/command.proto:31, QueryStatsResponse.stat (repeated Stat)
	fieldStatName       protowire.Number = 1 // app/stats/command/command.proto:17, Stat.name (string)
	fieldStatValue      protowire.Number = 2 // app/stats/command/command.proto:18, Stat.value (int64, a varint)

	// SysStatsResponse.
	fieldSysNumGoroutine protowire.Number = 1  // app/stats/command/command.proto:37, NumGoroutine (uint32)
	fieldSysAlloc        protowire.Number = 3  // app/stats/command/command.proto:39, Alloc (uint64)
	fieldSysUptime       protowire.Number = 10 // app/stats/command/command.proto:46, Uptime (uint32, seconds)

	// GetOutboundStatusResponse, ObservationResult and OutboundStatus. The
	// times are Unix seconds (app/observatory/observer.go:214), the delay
	// milliseconds (:218, :223).
	fieldOutboundStatusResult protowire.Number = 1 // app/observatory/command/command.proto:15, GetOutboundStatusResponse.status (ObservationResult)
	fieldResultStatus         protowire.Number = 1 // app/observatory/config.proto:10, ObservationResult.status (repeated OutboundStatus)
	fieldStatusAlive          protowire.Number = 1 // app/observatory/config.proto:26, OutboundStatus.alive (bool)
	fieldStatusDelay          protowire.Number = 2 // app/observatory/config.proto:31, OutboundStatus.delay (int64, ms)
	fieldStatusLastError      protowire.Number = 3 // app/observatory/config.proto:35, OutboundStatus.last_error_reason (string)
	fieldStatusTag            protowire.Number = 4 // app/observatory/config.proto:39, OutboundStatus.outbound_tag (string)
	fieldStatusLastSeen       protowire.Number = 5 // app/observatory/config.proto:43, OutboundStatus.last_seen_time (int64, Unix s)
	fieldStatusLastTry        protowire.Number = 6 // app/observatory/config.proto:47, OutboundStatus.last_try_time (int64, Unix s)

	// GetBalancerInfoResponse, BalancerMsg, OverrideInfo and
	// PrincipleTargetInfo.
	fieldBalancerInfoBalancer protowire.Number = 1 // app/router/command/command.proto:85, GetBalancerInfoResponse.balancer (BalancerMsg)
	fieldBalancerOverride     protowire.Number = 5 // app/router/command/command.proto:76, BalancerMsg.override (OverrideInfo)
	fieldBalancerPrinciple    protowire.Number = 6 // app/router/command/command.proto:77, BalancerMsg.principle_target (PrincipleTargetInfo)
	fieldOverrideTarget       protowire.Number = 2 // app/router/command/command.proto:72, OverrideInfo.target (string)
	fieldPrincipleTag         protowire.Number = 1 // app/router/command/command.proto:68, PrincipleTargetInfo.tag (repeated string)
)

// Stat is one of xray's traffic counters, such as
// "outbound>>>srv-ab12cd34>>>traffic>>>uplink".
type Stat struct {
	Name  string
	Value int64
}

// SysStats is xray's own resource use.
type SysStats struct {
	Uptime       uint32 // seconds
	NumGoroutine uint32
	Alloc        uint64 // bytes
}

// OutboundStatus is what xray's observatory knows of one outbound. xray
// reports Delay in milliseconds, and for a dead outbound as 99999999 ms.
// LastSeen is when the outbound last answered the probe and LastTry when it
// was last probed; each is the zero time while it never happened.
type OutboundStatus struct {
	Tag       string
	Alive     bool
	Delay     time.Duration
	LastError string
	LastSeen  time.Time
	LastTry   time.Time
}

// field is one field of a protobuf message, as walk reads it. Only the wire
// types that the messages above use are decoded: the value of a varint is in
// varint, that of a length-delimited field in bytes.
type field struct {
	num    protowire.Number
	typ    protowire.Type
	varint uint64
	bytes  []byte
}

func (f field) isVarint(num protowire.Number) bool {
	return f.num == num && f.typ == protowire.VarintType
}
func (f field) isBytes(num protowire.Number) bool {
	return f.num == num && f.typ == protowire.BytesType
}

// walk calls f for each field of the message b that has the wire type varint
// or length-delimited, and skips the others. A field f does not look at is
// unknown to it and is skipped by f returning nil. The first error stops the
// walk.
func walk(b []byte, f func(field) error) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		fl := field{num: num, typ: typ}
		switch typ {
		case protowire.VarintType:
			fl.varint, n = protowire.ConsumeVarint(b)
		case protowire.BytesType:
			fl.bytes, n = protowire.ConsumeBytes(b)
		default:
			n = protowire.ConsumeFieldValue(num, typ, b)
		}
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		if typ == protowire.VarintType || typ == protowire.BytesType {
			if err := f(fl); err != nil {
				return err
			}
		}
	}
	return nil
}

func appendString(b []byte, num protowire.Number, s string) []byte {
	if s == "" {
		return b // proto3 leaves a default value off the wire
	}
	return protowire.AppendString(protowire.AppendTag(b, num, protowire.BytesType), s)
}

func appendBool(b []byte, num protowire.Number, v bool) []byte {
	if !v {
		return b
	}
	return protowire.AppendVarint(protowire.AppendTag(b, num, protowire.VarintType), 1)
}

func encodeQueryStats(pattern string, reset bool) []byte {
	b := appendString(nil, fieldQueryStatsPattern, pattern)
	return appendBool(b, fieldQueryStatsReset, reset)
}

func encodeBalancerInfo(tag string) []byte {
	return appendString(nil, fieldBalancerInfoTag, tag)
}

func decodeQueryStats(b []byte) ([]Stat, error) {
	var stats []Stat
	err := walk(b, func(f field) error {
		if !f.isBytes(fieldQueryStatsStat) {
			return nil
		}
		s, err := decodeStat(f.bytes)
		stats = append(stats, s)
		return err
	})
	return stats, err
}

func decodeStat(b []byte) (Stat, error) {
	var s Stat
	err := walk(b, func(f field) error {
		switch {
		case f.isBytes(fieldStatName):
			s.Name = string(f.bytes)
		case f.isVarint(fieldStatValue):
			s.Value = int64(f.varint)
		}
		return nil
	})
	return s, err
}

func decodeSysStats(b []byte) (SysStats, error) {
	var s SysStats
	err := walk(b, func(f field) error {
		switch {
		case f.isVarint(fieldSysNumGoroutine):
			s.NumGoroutine = uint32(f.varint)
		case f.isVarint(fieldSysAlloc):
			s.Alloc = f.varint
		case f.isVarint(fieldSysUptime):
			s.Uptime = uint32(f.varint)
		}
		return nil
	})
	return s, err
}

func decodeOutboundStatus(b []byte) ([]OutboundStatus, error) {
	var out []OutboundStatus
	err := walk(b, func(f field) error {
		if !f.isBytes(fieldOutboundStatusResult) {
			return nil
		}
		return walk(f.bytes, func(f field) error {
			if !f.isBytes(fieldResultStatus) {
				return nil
			}
			s, err := decodeOneOutbound(f.bytes)
			out = append(out, s)
			return err
		})
	})
	return out, err
}

func decodeOneOutbound(b []byte) (OutboundStatus, error) {
	var s OutboundStatus
	err := walk(b, func(f field) error {
		switch {
		case f.isVarint(fieldStatusAlive):
			s.Alive = f.varint != 0
		case f.isVarint(fieldStatusDelay):
			s.Delay = time.Duration(int64(f.varint)) * time.Millisecond
		case f.isBytes(fieldStatusLastError):
			s.LastError = string(f.bytes)
		case f.isBytes(fieldStatusTag):
			s.Tag = string(f.bytes)
		case f.isVarint(fieldStatusLastSeen):
			s.LastSeen = unixTime(int64(f.varint))
		case f.isVarint(fieldStatusLastTry):
			s.LastTry = unixTime(int64(f.varint))
		}
		return nil
	})
	return s, err
}

// unixTime is the time sec seconds after the epoch, or the zero time for 0,
// which is how xray says a time never happened.
func unixTime(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

// decodeBalancerInfo returns the override target and the principle targets
// of a GetBalancerInfoResponse, with the empty tags left out.
func decodeBalancerInfo(b []byte) (override string, targets []string, err error) {
	err = walk(b, func(f field) error {
		if !f.isBytes(fieldBalancerInfoBalancer) {
			return nil
		}
		return walk(f.bytes, func(f field) error {
			switch {
			case f.isBytes(fieldBalancerOverride):
				return walk(f.bytes, func(f field) error {
					if f.isBytes(fieldOverrideTarget) {
						override = string(f.bytes)
					}
					return nil
				})
			case f.isBytes(fieldBalancerPrinciple):
				return walk(f.bytes, func(f field) error {
					// leastPing answers with an empty tag while no outbound is
					// alive; that is no target.
					if f.isBytes(fieldPrincipleTag) && len(f.bytes) > 0 {
						targets = append(targets, string(f.bytes))
					}
					return nil
				})
			}
			return nil
		})
	})
	return override, targets, err
}
