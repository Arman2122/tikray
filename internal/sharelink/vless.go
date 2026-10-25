package sharelink

import "errors"

// parseVLESS reads vless://<id>@<host>:<port>?<query>#<name>.
//
// The encryption parameter is passed through as it is, so VLESS post-quantum
// encryption strings work; it is "none" when the link does not set it.
func parseVLESS(link string) (Server, error) {
	t, err := parseTarget(link, "vless")
	if err != nil {
		return Server{}, err
	}
	if t.secret == "" {
		return Server{}, errors.New("sharelink: vless link has no id")
	}
	st, err := streamFromQuery(t.query, "").settings()
	if err != nil {
		return Server{}, err
	}
	user := map[string]any{
		"id":         t.secret,
		"encryption": orDefault(t.query.Get("encryption"), "none"),
	}
	if flow := t.query.Get("flow"); flow != "" {
		user["flow"] = flow
	}
	out, err := buildOutbound("vless", map[string]any{
		"vnext": []any{map[string]any{
			"address": t.host,
			"port":    t.port,
			"users":   []any{user},
		}},
	}, st)
	if err != nil {
		return Server{}, err
	}
	return Server{Name: name(t.fragment, t.host, t.port), Outbound: out}, nil
}
