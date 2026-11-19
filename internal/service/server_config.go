package service

import (
	"bytes"
	"encoding/json"
	"strings"
)

// KeepSecretSentinel stands in for a saved credential inside the sanitized
// server editor view (GET /v1/servers/{id}/config). When submitted back in
// PATCH /v1/servers/{id}, UpdateServer substitutes the server's existing stored
// secret at the matching JSON path so non-secret fields (SNI, port, transport,
// mux, finalmask) can be edited without ever echoing credentials over the API.
const KeepSecretSentinel = "__tikray_saved__"

// ServerConfigView is the credential-safe representation of a single server's
// xray outbound configuration for visual and JSON editing in the Web UI.
type ServerConfigView struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Disabled     bool            `json:"disabled,omitempty"`
	Subscription string          `json:"subscription,omitempty"`
	Outbound     json.RawMessage `json:"outbound"`
}

// editorSecretKeys lists every outbound JSON key whose string value is treated
// as a credential or private access key in the visual/JSON editor view.
var editorSecretKeys = map[string]bool{
	"id":                   true,
	"password":             true,
	"privatekey":           true,
	"presharedkey":         true,
	"seed":                 true,
	"secretkey":            true,
	"user":                 true,
	"pass":                 true,
	"auth":                 true,
	"key":                  true,
	"secrets":              true,
	"authorization":        true,
	"proxy-authorization":  true,
	"publickey":            true,
	"shortid":              true,
	"spiderx":              true,
	"mldsa65verify":        true,
	"echconfiglist":        true,
	"pinnedpeercertsha256": true,
}

// ServerConfig returns the sanitized configuration of server id for the visual
// and JSON editors. Every stored secret is replaced with KeepSecretSentinel and
// the output is checked against RedactorFor as defense in depth.
func (s *Service) ServerConfig(id string) (ServerConfigView, error) {
	st, _ := s.store.State()
	i := serverIndex(st.Servers, id)
	if i < 0 {
		return ServerConfigView{}, notFound(st, "server", id)
	}
	srv := st.Servers[i]
	redact := RedactorFor(st)
	sanitized, err := sanitizeOutboundForEdit(srv.Outbound, redact)
	if err != nil {
		return ServerConfigView{}, &Refused{Reason: "server outbound could not be parsed"}
	}
	return ServerConfigView{
		ID:           srv.ID,
		Name:         redact(srv.Name),
		Disabled:     srv.Disabled,
		Subscription: srv.Subscription,
		Outbound:     sanitized,
	}, nil
}

func sanitizeOutboundForEdit(raw json.RawMessage, redact func(string) string) (json.RawMessage, error) {
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	cleaned := sanitizeValue(root, false, redact)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(cleaned); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(buf.Bytes()), nil
}

func sanitizeValue(v any, secret bool, redact func(string) string) any {
	switch x := v.(type) {
	case string:
		if x == "" {
			return ""
		}
		if secret {
			return KeepSecretSentinel
		}
		// Defense in depth: if any non-credential field unexpectedly holds a
		// known secret string from state, replace it with the sentinel rather
		// than echoing it back to the client.
		if redact != nil && redact(x) != x {
			return KeepSecretSentinel
		}
		return x
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = sanitizeValue(e, secret, redact)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			lk := strings.ToLower(k)
			childSecret := secret || editorSecretKeys[lk] || lk == "headers" || lk == "cookie" || lk == "set-cookie"
			// VLESS post-quantum encryption keys live under "encryption"; plain
			// "none" is non-secret and stays directly visible/editable.
			if lk == "encryption" {
				if s, ok := e.(string); ok && s != "" && !strings.EqualFold(s, "none") {
					childSecret = true
				}
			}
			out[k] = sanitizeValue(e, childSecret, redact)
		}
		return out
	default:
		return v
	}
}

// mergePreservedSecrets resolves any KeepSecretSentinel values in newRaw by
// copying the server's existing secret from the matching JSON path in oldRaw.
// If a sentinel appears where no prior value existed, it refuses the update so
// the placeholder can never be persisted or sent to xray-core.
func mergePreservedSecrets(oldRaw, newRaw json.RawMessage) (json.RawMessage, error) {
	if !bytes.Contains(newRaw, []byte(KeepSecretSentinel)) {
		return newRaw, nil
	}
	var oldDoc any
	if len(oldRaw) > 0 {
		_ = json.Unmarshal(oldRaw, &oldDoc)
	}
	var newDoc any
	if err := json.Unmarshal(newRaw, &newDoc); err != nil {
		return nil, &Refused{Reason: "outbound is not valid JSON"}
	}
	merged, err := resolveSentinels(oldDoc, newDoc)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(merged); err != nil {
		return nil, &Refused{Reason: "could not encode outbound JSON"}
	}
	return bytes.TrimSpace(buf.Bytes()), nil
}

func resolveSentinels(oldVal, newVal any) (any, error) {
	switch nv := newVal.(type) {
	case string:
		if nv != KeepSecretSentinel {
			return nv, nil
		}
		ov, ok := oldVal.(string)
		if !ok || ov == "" || ov == KeepSecretSentinel {
			return nil, &Refused{Reason: "a saved credential placeholder has no previous value; enter the credential directly"}
		}
		return ov, nil
	case []any:
		oldArr, _ := oldVal.([]any)
		out := make([]any, len(nv))
		for i, elem := range nv {
			var oe any
			if i < len(oldArr) {
				oe = oldArr[i]
			}
			r, err := resolveSentinels(oe, elem)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	case map[string]any:
		oldMap, _ := oldVal.(map[string]any)
		out := make(map[string]any, len(nv))
		for k, elem := range nv {
			oe := lookupFold(oldMap, k)
			r, err := resolveSentinels(oe, elem)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	default:
		return newVal, nil
	}
}

func lookupFold(m map[string]any, key string) any {
	if m == nil {
		return nil
	}
	if v, ok := m[key]; ok {
		return v
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return nil
}
