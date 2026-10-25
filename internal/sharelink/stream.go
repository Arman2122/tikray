package sharelink

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// stream is the transport and security a share link asks for. Its fields are
// the link's own strings, not yet checked: settings checks them and builds
// the xray streamSettings. An empty field means the link did not set it.
type stream struct {
	// Network is the transport: tcp (also raw), ws, grpc, httpupgrade or xhttp
	// (also splithttp).
	Network string
	// Security is none, tls or reality.
	Security string
	// SNI is the TLS server name. When a tls link leaves it empty, settings
	// uses the first name in Host instead.
	SNI string
	// Fingerprint is the uTLS client fingerprint.
	Fingerprint string
	// ALPN is the TLS ALPN protocols, separated by commas.
	ALPN string
	// PublicKey, ShortID and SpiderX are the REALITY public key, short ID and
	// spider path.
	PublicKey, ShortID, SpiderX string
	// Host and Path are the HTTP host and path of the ws, httpupgrade and
	// xhttp transports and of a tcp http header.
	Host, Path string
	// ServiceName and Authority are the gRPC service name and authority.
	ServiceName, Authority string
	// Mode is the gRPC mode (multi, or anything else for a single stream) or
	// the xhttp mode.
	Mode string
	// HeaderType is the tcp header: none or http.
	HeaderType string
	// AllowInsecure is that the link asked to skip verification of the TLS
	// certificate. xray-core has removed that option, so settings never writes
	// it: the certificate is still verified, and warnings says so.
	AllowInsecure bool
	// PinnedCertSHA256 lists SHA-256 hashes of the server's certificate, in hex
	// and separated by commas; a certificate that matches one is trusted even
	// if it does not chain to a CA. VerifyCertByName is the name the
	// certificate is verified against instead of the SNI. Both are for tls
	// only, and settings passes them on as they are, trimmed.
	PinnedCertSHA256, VerifyCertByName string
}

// streamKeys are the query parameters that streamFromQuery reads. A malformed
// one fails the link, as dropping it would change the outbound.
var streamKeys = []string{
	"type", "security", "sni", "fp", "alpn", "pbk", "sid", "spx", "host", "path",
	"serviceName", "authority", "mode", "headerType", "allowInsecure", "insecure", "pcs", "vcn",
}

// streamFromQuery reads the transport and security from a share link's query.
// It uses defaultSecurity when the link does not set security or sets it to
// nothing.
func streamFromQuery(q url.Values, defaultSecurity string) stream {
	s := stream{
		Network:       q.Get("type"),
		Security:      q.Get("security"),
		SNI:           q.Get("sni"),
		Fingerprint:   q.Get("fp"),
		ALPN:          q.Get("alpn"),
		PublicKey:     q.Get("pbk"),
		ShortID:       q.Get("sid"),
		SpiderX:       q.Get("spx"),
		Host:          q.Get("host"),
		Path:          q.Get("path"),
		ServiceName:   q.Get("serviceName"),
		Authority:     q.Get("authority"),
		Mode:          q.Get("mode"),
		HeaderType:    q.Get("headerType"),
		AllowInsecure: isTrue(q.Get("allowInsecure")) || isTrue(q.Get("insecure")),

		PinnedCertSHA256: q.Get("pcs"),
		VerifyCertByName: q.Get("vcn"),
	}
	if strings.TrimSpace(s.Security) == "" {
		s.Security = defaultSecurity
	}
	return s
}

// isTrue reports whether a query flag is on: 1 or true, in any case.
func isTrue(v string) bool {
	v = strings.TrimSpace(v)
	return v == "1" || strings.EqualFold(v, "true")
}

// security is the security with its case and space normalized.
func (s stream) security() string { return strings.ToLower(strings.TrimSpace(s.Security)) }

// warnings says what settings ignored that the user should know. A link that
// asks for allowInsecure over tls still parses, with verification on, unless
// it pins the certificate with pcs, which is what replaces allowInsecure. It
// returns nil when there is nothing to say.
func (s stream) warnings() []string {
	if s.security() == "tls" && s.AllowInsecure && strings.TrimSpace(s.PinnedCertSHA256) == "" {
		return []string{warnInsecureRemoved}
	}
	return nil
}

// settings builds the xray streamSettings object. Network, Security and
// HeaderType are matched without regard to case. The tls server name is SNI,
// or the first name in Host when SNI is empty. It returns an error that
// wraps ErrUnsupported for a transport tikray cannot run, and any other
// error for settings that xray would refuse. An error for a value it does not
// know does not repeat the value, since a parameter can hold anything, even
// the secret of the link.
func (s stream) settings() (map[string]any, error) {
	network := strings.ToLower(strings.TrimSpace(s.Network))
	out := map[string]any{}
	switch network {
	case "", "tcp", "raw":
		network = "tcp"
		header := strings.ToLower(strings.TrimSpace(s.HeaderType))
		switch header {
		case "", "none":
		case "http":
			headers := map[string]any{}
			if s.Host != "" {
				headers["Host"] = []string{s.Host}
			}
			out["tcpSettings"] = map[string]any{"header": map[string]any{
				"type": "http",
				"request": map[string]any{
					"path":    []string{orDefault(s.Path, "/")},
					"headers": headers,
				},
			}}
		default:
			return nil, errors.New("sharelink: unknown tcp header type, want none or http")
		}
	case "ws":
		out["wsSettings"] = compact(map[string]string{"path": orDefault(s.Path, "/"), "host": s.Host})
	case "grpc":
		g := compact(map[string]string{"serviceName": s.ServiceName, "authority": s.Authority})
		g["multiMode"] = strings.EqualFold(s.Mode, "multi")
		out["grpcSettings"] = g
	case "httpupgrade":
		out["httpupgradeSettings"] = compact(map[string]string{"path": s.Path, "host": s.Host})
	case "xhttp", "splithttp":
		network = "xhttp"
		out["xhttpSettings"] = compact(map[string]string{"path": s.Path, "host": s.Host, "mode": orDefault(s.Mode, "auto")})
	case "kcp", "mkcp", "quic", "h2", "http":
		return nil, fmt.Errorf("%w network %q", ErrUnsupported, network)
	default:
		return nil, errors.New("sharelink: unknown network, want tcp, ws, grpc, httpupgrade or xhttp")
	}
	out["network"] = network

	switch s.security() {
	case "", "none":
	case "tls":
		// AllowInsecure is not written: current xray refuses a config that has it.
		// A CDN-fronted link has a clean address and a host, and often no sni; a
		// handshake that names the address would fail, so the host is the name,
		// as v2rayN does it. Reality does not do this.
		serverName := s.SNI
		if strings.TrimSpace(serverName) == "" {
			serverName = firstHost(s.Host)
		}
		t := compact(map[string]string{
			"serverName":           serverName,
			"fingerprint":          s.Fingerprint,
			"pinnedPeerCertSha256": strings.TrimSpace(s.PinnedCertSHA256),
			"verifyPeerCertByName": strings.TrimSpace(s.VerifyCertByName),
		})
		if alpn := splitList(s.ALPN); len(alpn) > 0 {
			t["alpn"] = alpn
		}
		out["security"] = "tls"
		out["tlsSettings"] = t
	case "reality":
		if s.PublicKey == "" {
			return nil, errors.New("sharelink: reality needs a public key (pbk)")
		}
		if network != "tcp" && network != "grpc" && network != "xhttp" {
			return nil, fmt.Errorf("sharelink: reality does not work over network %q, only tcp, grpc and xhttp", network)
		}
		out["security"] = "reality"
		out["realitySettings"] = compact(map[string]string{
			"serverName":  s.SNI,
			"fingerprint": orDefault(s.Fingerprint, "chrome"),
			"publicKey":   s.PublicKey,
			"shortId":     s.ShortID,
			"spiderX":     s.SpiderX,
		})
	default:
		return nil, errors.New("sharelink: unknown security, want none, tls or reality")
	}
	return out, nil
}

// firstHost is the first of the comma separated names in a host parameter,
// trimmed. It is empty when the first name is.
func firstHost(h string) string {
	first, _, _ := strings.Cut(h, ",")
	return strings.TrimSpace(first)
}

// orDefault returns v, or def when v is empty.
func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// compact turns m into a settings object that leaves out the empty strings.
func compact(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

// splitList splits a comma separated list, trimming each element and leaving
// out the empty ones.
func splitList(s string) []string {
	var out []string
	for _, e := range strings.Split(s, ",") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}
