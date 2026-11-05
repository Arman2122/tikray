package runnerapi

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// PublicXrayResult exposes only the diagnostics tikray consumes. A listing
// can contain entire outbounds, a user counter can contain an account name,
// and any command can echo its arguments on stderr.
func PublicXrayResult(command string, raw XrayAPIResponse) XrayAPIResponse {
	res := XrayAPIResponse{ExitCode: raw.ExitCode}
	if raw.ExitCode != 0 {
		if command == "stats" && strings.Contains(raw.Stdout+raw.Stderr, "not found") {
			res.Stderr = "counter not found"
		}
		return res
	}
	var value any
	switch command {
	case "lso":
		type entry struct {
			Tag string `json:"tag"`
		}
		var body struct {
			Outbounds []entry `json:"outbounds"`
		}
		if json.Unmarshal([]byte(raw.Stdout), &body) != nil {
			return res
		}
		tags := []entry{}
		for _, out := range body.Outbounds {
			if diagnosticTag.MatchString(out.Tag) {
				tags = append(tags, out)
			}
		}
		body.Outbounds = tags
		value = body
	case "stats", "statsquery":
		value = publicStats(command, raw.Stdout)
	case "statssys":
		var all map[string]json.RawMessage
		if json.Unmarshal([]byte(raw.Stdout), &all) != nil {
			return res
		}
		fields := make(map[string]json.RawMessage)
		for _, key := range []string{"Uptime", "NumGoroutine", "NumGC", "Alloc", "TotalAlloc", "Sys", "Mallocs", "Frees", "LiveObjects", "PauseTotalNs"} {
			if unsignedStat(all[key]) {
				fields[key] = all[key]
			}
		}
		value = fields
	}
	if value != nil {
		b, err := json.MarshalIndent(value, "", "  ")
		if err == nil {
			res.Stdout = string(b)
		}
	}
	return res
}

// The renderer assigns these tags. Hand-written tags can be credentials.
var diagnosticTag = regexp.MustCompile(`^(?:srv-[0-9a-f]{8}|direct|block|dns-out|tun-in|socks-in|dns-in|api-in)$`)

func unsignedStat(raw json.RawMessage) bool {
	var n json.Number
	if len(raw) == 0 || json.Unmarshal(raw, &n) != nil {
		return false
	}
	_, err := strconv.ParseUint(n.String(), 10, 64)
	return err == nil
}

type trafficStat struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value,omitempty"`
}

func (s trafficStat) safe() bool {
	parts := strings.Split(s.Name, ">>>")
	return len(parts) == 4 && (parts[0] == "outbound" || parts[0] == "inbound") &&
		diagnosticTag.MatchString(parts[1]) && parts[2] == "traffic" &&
		(parts[3] == "uplink" || parts[3] == "downlink") && (len(s.Value) == 0 || unsignedStat(s.Value))
}

func publicStats(command, output string) any {
	if command == "stats" {
		var body struct {
			Stat trafficStat `json:"stat"`
		}
		if json.Unmarshal([]byte(output), &body) != nil || !body.Stat.safe() {
			return nil
		}
		return body
	}
	var body struct {
		Stat []trafficStat `json:"stat"`
	}
	if json.Unmarshal([]byte(output), &body) != nil {
		return nil
	}
	safe := []trafficStat{}
	for _, counter := range body.Stat {
		if counter.safe() {
			safe = append(safe, counter)
		}
	}
	body.Stat = safe
	return body
}
