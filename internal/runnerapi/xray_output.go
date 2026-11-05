package runnerapi

import (
	"cmp"
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// PublicXrayResult exposes only the diagnostics tikray consumes. A listing
// can contain entire outbounds, a user counter can contain an account name,
// and any command can echo its arguments on stderr. A failed command keeps
// only why it failed in fixed words (see xrayAPICause).
func PublicXrayResult(command string, raw XrayAPIResponse) XrayAPIResponse {
	res := XrayAPIResponse{ExitCode: raw.ExitCode}
	if raw.ExitCode != 0 {
		res.Stderr = xrayAPICause(command, raw.Stdout+raw.Stderr)
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

// xrayAPICause is why an "xray api" call failed, as one of a few fixed texts
// that each name themselves again, so that the client can reduce what the
// runner reduced: a counter that is not there, an API xray did not let it
// dial, the gRPC status code name, or the runner's own words for a call it
// cut off or could not make. "" when output says none of these.
func xrayAPICause(command, output string) string {
	switch {
	case command == "stats" && strings.Contains(output, "not found"):
		return "counter not found"
	case strings.Contains(output, "failed to dial"):
		return "failed to dial xray's API"
	}
	if m := grpcCode.FindStringSubmatch(output); m != nil && slices.Contains(grpcCodes, m[1]) {
		return "rpc error: code = " + m[1]
	}
	for _, s := range []string{"context deadline exceeded", "no xray is running"} {
		if strings.Contains(output, s) {
			return s
		}
	}
	return ""
}

var grpcCode = regexp.MustCompile(`rpc error: code = ([A-Za-z]+)`)

// grpcCodes are the names of gRPC's status codes but OK.
var grpcCodes = []string{
	"Canceled", "Unknown", "InvalidArgument", "DeadlineExceeded", "NotFound", "AlreadyExists",
	"PermissionDenied", "ResourceExhausted", "FailedPrecondition", "Aborted", "OutOfRange",
	"Unimplemented", "Internal", "Unavailable", "DataLoss", "Unauthenticated",
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

// Categories of xray's refusal of a config. A refusal names one, the first
// of refusalRules that fits, after the srv- tags of the outbounds xray names.
const (
	refusalInvalidJSON   = "invalid JSON"
	refusalFlow          = "unsupported flow"
	refusalPlaintext     = "transport needs TLS or encryption"
	refusalInsecure      = "allowInsecure refused"
	refusalTLS           = "invalid TLS or REALITY settings"
	refusalTransport     = "unsupported transport or security"
	refusalProtocol      = "unknown protocol"
	refusalCipher        = "unsupported cipher"
	refusalPassword      = "missing or invalid password"
	refusalEncryption    = "unsupported VLESS encryption"
	refusalAddress       = "invalid port or address"
	refusalUnknownUser   = "unknown user"
	refusalInvalidUser   = "invalid user"
	refusalInvalidConfig = "invalid config"
	// refusalLegacy is what the client makes of an older runner's output in
	// which xray refused the config for a reason no category fits.
	refusalLegacy = "xray failed to load config"
)

// refusalRules match the lowercased text of xray's "Failed to start:" line, in
// order: a later rule's words can appear in an earlier one's message. The
// words are xray's own, as releases 26.1.18 to 26.10.31 print them; the user
// rules also keep the categories the client gave older runners' output.
var refusalRules = []struct {
	category string
	match    func(s string) bool
}{
	{refusalInvalidJSON, anyOf("failed to read config file", "failed to parse json config", "failed to decode config")},
	{refusalFlow, anyOf(`"flow" doesn't support`, `support vless "flow"`)},
	{refusalPlaintext, anyOf("without tls", `transport needs vless "encryption"`)},
	{refusalInsecure, anyOf(`"allowinsecure"`)},
	{refusalTLS, anyOf("failed to build tls config", "failed to build reality config")},
	{refusalTransport, anyOf("unknown transport protocol", "unknown security")},
	{refusalProtocol, anyOf("unknown config id", "unknown protocol")},
	{refusalCipher, anyOf("cipher method")},
	{refusalPassword, anyOf("password is not specified", "invalid key", "bad key", "decode key")},
	{refusalEncryption, anyOf(`unsupported "encryption"`, `"encryption":"none"`)},
	{refusalAddress, func(s string) bool {
		return anyOf("invalid address", "address is not set", `"address" is not set`, "port of type")(s) || invalidPort.MatchString(s)
	}},
	{refusalUnknownUser, anyOf("unknown user")},
	{refusalInvalidUser, func(s string) bool {
		return anyOf("invalid uuid", "bad user", "invalid user", "invalid vmess user")(s) ||
			strings.Contains(s, "user") && (strings.Contains(s, "not valid") || strings.Contains(s, "invalid"))
	}},
}

var invalidPort = regexp.MustCompile(`invalid (?:[a-z]+ )?port`)

func anyOf(words ...string) func(string) bool {
	return func(s string) bool {
		for _, w := range words {
			if strings.Contains(s, w) {
				return true
			}
		}
		return false
	}
}

// maxRefusalTags bounds the tags a refusal names. xray stops at the first
// outbound it cannot build.
const maxRefusalTags = 4

// refusalTag finds the tag of an outbound xray could not build. Only a tag the
// renderer gives a server, srv- and 8 hex digits, is public.
var refusalTag = regexp.MustCompile(`failed to build outbound config with tag (srv-[0-9a-f]{8})(?:[\s>]|$)`)

// classifyRefusal reduces what xray printed when it refused a config to the
// public tags of the outbounds it named and the first category that fits,
// "" when none does. Only xray's "Failed to start:" line, the last thing it
// prints, is read when there is one: the warnings before it name features,
// such as a flow, that are not why it refused.
func classifyRefusal(output string) (tags []string, category string) {
	if i := strings.LastIndex(output, "Failed to start:"); i >= 0 {
		output = output[i:]
	}
	for _, m := range refusalTag.FindAllStringSubmatch(output, -1) {
		if !slices.Contains(tags, m[1]) && len(tags) < maxRefusalTags {
			tags = append(tags, m[1])
		}
	}
	s := strings.ToLower(output)
	for _, r := range refusalRules {
		if r.match(s) {
			return tags, r.category
		}
	}
	return tags, ""
}

// refusalText is a refusal's public text: the tags, if any, then category.
func refusalText(tags []string, category string) string {
	if len(tags) == 0 {
		return category
	}
	return "outbound " + strings.Join(tags, ", ") + ": " + category
}

// refusalPrefix starts a runner's refusal of a config.
const refusalPrefix = "xray rejected the config: "

// ConfigRefusal is the public reason for xray's refusal of a config, made of
// output, what "xray run -test" printed when it exited with
// ExitConfigRefused: "xray rejected the config: ", the srv- tags of the
// outbounds xray names, then one category, such as "xray rejected the
// config: outbound srv-deadbeef: unsupported flow". Nothing else of output
// is kept: xray quotes the config it refuses, credentials and all.
func ConfigRefusal(output string) string {
	tags, category := classifyRefusal(output)
	return refusalPrefix + refusalText(tags, cmp.Or(category, refusalInvalidConfig))
}

// publicRefusalRE matches the refusals ConfigRefusal makes and those
// publicRefusal makes of an older runner's xray output, and nothing else.
var publicRefusalRE = func() *regexp.Regexp {
	var categories []string
	for _, c := range []string{refusalInvalidConfig, refusalLegacy} {
		categories = append(categories, regexp.QuoteMeta(c))
	}
	for _, r := range refusalRules {
		categories = append(categories, regexp.QuoteMeta(r.category))
	}
	return regexp.MustCompile(`^(?:` + regexp.QuoteMeta(refusalPrefix) + `)?` +
		`(?:outbound srv-[0-9a-f]{8}(?:, srv-[0-9a-f]{8}){0,3}: )?` +
		`(?:` + strings.Join(categories, "|") + `)$`)
}()
