package sharelink

import "errors"

// parseTrojan reads trojan://<password>@<host>:<port>?<query>#<name>. The
// password is URL-decoded. Security is tls unless the link says otherwise.
func parseTrojan(link string) (Server, error) {
	t, err := parseTarget(link, "trojan")
	if err != nil {
		return Server{}, err
	}
	if t.secret == "" {
		return Server{}, errors.New("sharelink: trojan link has no password")
	}
	strm := streamFromQuery(t.query, "tls")
	st, err := strm.settings()
	if err != nil {
		return Server{}, err
	}
	out, err := buildOutbound("trojan", map[string]any{
		"servers": []any{map[string]any{
			"address":  t.host,
			"port":     t.port,
			"password": t.secret,
		}},
	}, st)
	if err != nil {
		return Server{}, err
	}
	return Server{Name: name(t.fragment, t.host, t.port), Outbound: out, Warnings: strm.warnings()}, nil
}
