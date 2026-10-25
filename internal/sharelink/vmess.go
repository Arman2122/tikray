package sharelink

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// vmessSecurities are the encryption methods xray has for a VMess user.
var vmessSecurities = []string{"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}

// parseVMess reads vmess://<base64 of a JSON object>, the link v2rayN writes.
//
// The body is base64 in the standard or the URL alphabet, with or without the
// padding. In the JSON, port and aid may be numbers or strings, and
// allowInsecure may be a boolean, a number or a string. The URL form
// vmess://<id>@<host>:<port>?<query> is not read.
//
// A VMess link has one set of fields for every transport, so they are read as
// the transport needs them: for gRPC, path is the service name, host is the
// authority and type is the mode; for xhttp, type is the mode. A type of none
// says nothing. A link that sets allowInsecure still gets a verified
// connection, and a warning, as in stream.warnings.
//
// The errors it returns do not repeat any of the link, and a wrong type in
// the JSON is reported by the name of the field only.
func parseVMess(link string) (Server, error) {
	_, body, _ := strings.Cut(link, "://")
	// Base64 has no @, so one means the URL form.
	if strings.Contains(body, "@") {
		return Server{}, fmt.Errorf("%w vmess link in URL form, want vmess://<base64 of a JSON object>", ErrUnsupported)
	}
	raw, ok := decodeBase64(body)
	if !ok {
		return Server{}, errors.New("sharelink: vmess link is not base64")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return Server{}, errors.New("sharelink: vmess link does not hold a JSON object")
	}

	r := &vmessReader{fields: fields}
	var (
		ps       = r.text("ps")
		add      = r.text("add")
		portText = strings.TrimSpace(r.text("port"))
		id       = strings.TrimSpace(r.text("id"))
		aid      = strings.TrimSpace(r.text("aid"))
		scy      = strings.ToLower(strings.TrimSpace(r.text("scy")))
		network  = r.text("net")
		typ      = r.text("type")
		httpHost = r.text("host")
		path     = r.text("path")
		tlsField = strings.ToLower(strings.TrimSpace(r.text("tls")))
		sni      = r.text("sni")
		alpn     = r.text("alpn")
		fp       = r.text("fp")
		pcs      = r.text("pcs")
		vcn      = r.text("vcn")
		insecure = r.flag("allowInsecure")
	)
	if r.err != nil {
		return Server{}, r.err
	}

	host, ok := cleanHost(add)
	if !ok {
		return Server{}, errors.New("sharelink: vmess link has no valid address (add)")
	}
	if portText == "" {
		return Server{}, errors.New("sharelink: vmess link has no port")
	}
	port, ok := parsePort(portText)
	if !ok {
		return Server{}, errors.New("sharelink: vmess link has an invalid port, want 1 to 65535")
	}
	if id == "" {
		return Server{}, errors.New("sharelink: vmess link has no id")
	}
	if aid != "" {
		n, err := strconv.Atoi(aid)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return Server{}, errors.New(`sharelink: vmess field "aid" is not a number`)
		}
		if n != 0 || err != nil {
			return Server{}, fmt.Errorf("%w vmess alterId (aid), which xray-core dropped: the server must use aid 0", ErrUnsupported)
		}
	}
	if scy == "" {
		scy = "auto"
	}
	if !slices.Contains(vmessSecurities, scy) {
		return Server{}, fmt.Errorf("sharelink: vmess security (scy) must be one of %s", strings.Join(vmessSecurities, ", "))
	}
	switch tlsField {
	case "", "none":
		tlsField = ""
	case "tls":
	default:
		return Server{}, errors.New(`sharelink: vmess field "tls" must be "tls", "none" or empty`)
	}

	mode := typ
	if strings.EqualFold(strings.TrimSpace(mode), "none") {
		mode = ""
	}
	strm := stream{
		Network:          network,
		Security:         tlsField,
		SNI:              sni,
		Fingerprint:      fp,
		ALPN:             alpn,
		Host:             httpHost,
		Path:             path,
		ServiceName:      path,
		Authority:        httpHost,
		Mode:             mode,
		HeaderType:       typ,
		AllowInsecure:    insecure,
		PinnedCertSHA256: pcs,
		VerifyCertByName: vcn,
	}
	st, err := strm.settings()
	if err != nil {
		return Server{}, err
	}
	out, err := buildOutbound("vmess", map[string]any{
		"vnext": []any{map[string]any{
			"address": host,
			"port":    port,
			"users":   []any{map[string]any{"id": id, "security": scy}},
		}},
	}, st)
	if err != nil {
		return Server{}, err
	}
	return Server{Name: name(ps, host, port), Outbound: out, Warnings: strm.warnings()}, nil
}

// vmessReader reads the members of the JSON object in a VMess link. A member of
// the wrong type sets err, which names the member and nothing of its value; the
// first error stays and later reads give zero values.
type vmessReader struct {
	fields map[string]json.RawMessage
	err    error
}

// fail records that the member key has the wrong type.
func (r *vmessReader) fail(key string) {
	if r.err == nil {
		r.err = fmt.Errorf("sharelink: vmess field %q has the wrong type", key)
	}
}

// scalar decodes the member key. It gives nil for an absent or null member,
// and otherwise a string, a json.Number or a bool; an object or an array is the
// wrong type.
func (r *vmessReader) scalar(key string) any {
	raw, ok := r.fields[key]
	if !ok {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		r.fail(key)
		return nil
	}
	switch v.(type) {
	case nil, string, json.Number, bool:
		return v
	}
	r.fail(key)
	return nil
}

// text reads the member key as text: a string as it is, a number as it was
// written, and "" for an absent or null member.
func (r *vmessReader) text(key string) string {
	switch v := r.scalar(key).(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		r.fail(key)
	}
	return ""
}

// flag reads the member key as a flag: a boolean, or a number or string that
// isTrue, like the same flag in a query. An absent or null member is off.
func (r *vmessReader) flag(key string) bool {
	switch v := r.scalar(key).(type) {
	case bool:
		return v
	case string:
		return isTrue(v)
	case json.Number:
		return isTrue(v.String())
	}
	return false
}
