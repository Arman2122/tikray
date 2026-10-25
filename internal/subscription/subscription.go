// Package subscription turns the body of a subscription into servers, merges a
// refresh into the stored servers so that their IDs stay the same, and fetches
// a subscription, directly or through the proxy.
//
// A subscription's body and its links are credentials, and so is its URL, which
// often carries a token. Nothing here repeats one in an error.
package subscription

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Arman2122/tikray/internal/sharelink"
	"github.com/Arman2122/tikray/internal/store"
)

// maxLineRunes is how much of a skipped line Skipped.Line keeps.
const maxLineRunes = 80

// byteOrderMark is what some editors put at the start of a text file.
var byteOrderMark = []byte{0xEF, 0xBB, 0xBF}

// Decode returns the share links in the body of a subscription, in order.
//
// The body is the base64 of a list of links, or the list itself. The base64 may
// be in the standard or the URL alphabet, with or without padding, and may be
// wrapped: line breaks and spaces in it are ignored. In the list a line is a
// link; it is trimmed, and a blank line, a comment (a line that starts with
// "#", such as the "#support-url: https://t.me/x" that providers add) and a
// line without "://" are dropped. A link is not checked, nor are repeats
// removed: Parse does both.
func Decode(body []byte) []string {
	text := bytes.TrimPrefix(body, byteOrderMark)
	if decoded, ok := decodeBase64(text); ok {
		text = bytes.TrimPrefix(decoded, byteOrderMark)
	}
	var links []string
	for line := range strings.FieldsFuncSeq(string(text), func(r rune) bool { return r == '\n' || r == '\r' }) {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "#") && strings.Contains(line, "://") {
			links = append(links, line)
		}
	}
	return links
}

// decodeBase64 decodes text that is wholly base64, in either alphabet, with or
// without padding, and with any white space between its characters. It reports
// false for text that is not, such as a plain list, which has a ':' in it.
func decodeBase64(text []byte) ([]byte, bool) {
	clean := make([]byte, 0, len(text))
	for _, c := range text {
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '+', c == '/', c == '-', c == '_', c == '=':
			clean = append(clean, c)
		default:
			return nil, false
		}
	}
	clean = bytes.TrimRight(clean, "=")
	if len(clean) == 0 {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		out := make([]byte, enc.DecodedLen(len(clean)))
		if n, err := enc.Decode(out, clean); err == nil {
			return out[:n], true
		}
	}
	return nil, false
}

// Entry is one server of a subscription.
type Entry struct {
	// Link is the share link, trimmed.
	Link string
	// Server is what the link describes, with the parser's warnings.
	Server sharelink.Server
}

// Skipped is a line of a subscription that gave no server.
//
// Line is for showing the owner which line failed. It may hold a credential,
// as a share link does, so it does not belong in a log. Err says why the line
// failed and never repeats it.
type Skipped struct {
	// Line is the line, cut to its first 80 runes.
	Line string
	// Err is the reason, such as that the scheme is not supported.
	Err string
}

// Result is what Parse makes of a subscription's body.
type Result struct {
	// Entries are the servers, in the order of the body, each link once.
	Entries []Entry
	// Skipped are the links that gave no server, in the order of the body.
	Skipped []Skipped
}

// Parse decodes a subscription's body (see Decode) and parses each link with
// sharelink.Parse. A link that appears more than once counts once, the first
// time. A link that does not parse is in Skipped, which does not stop the
// others.
func Parse(body []byte) Result {
	var res Result
	seen := map[string]bool{}
	for _, link := range Decode(body) {
		if seen[link] {
			continue
		}
		seen[link] = true
		srv, err := sharelink.Parse(link)
		if err != nil {
			// sharelink's errors never repeat the secret parts of a link.
			res.Skipped = append(res.Skipped, Skipped{Line: cut(link, maxLineRunes), Err: err.Error()})
			continue
		}
		res.Entries = append(res.Entries, Entry{Link: link, Server: srv})
	}
	return res
}

// cut returns the first n runes of s, as valid UTF-8.
func cut(s string, n int) string {
	count := 0
	for i := range s {
		if count == n {
			s = s[:i]
			break
		}
		count++
	}
	return strings.ToValidUTF8(s, string(utf8.RuneError))
}

// newID makes the ID of a new server. Tests replace it.
var newID = store.NewID

// Merge returns servers with the ones of subscription subID replaced by
// entries. It does not change servers.
//
// The new servers follow the order of entries and take the place of the first
// old server of the subscription, or the end of the list when there is none.
// Every server that is not of the subscription stays where it was.
//
// An entry that is the same server as an old one of the subscription keeps
// that server: the result is the old server with the entry's Link, Name and
// Outbound, so its ID, Disabled and any other field are the old ones. A
// provider puts volatile text, such as the traffic left or the expiry, in the
// name of a link, and that changes the link, so the link alone cannot tell the
// servers apart. An entry matches in this order:
//
//  1. An old server with the same Link. This comes first for every entry, so
//     that no entry's outbound takes a server another entry's link names.
//  2. Failing that, an old server with the same Outbound, compared as JSON:
//     the same object whatever the order of its keys or its white space.
//     An outbound that is not a JSON object matches nothing.
//
// An old server matches at most one entry. Among several candidates the first
// old server in servers matches the first entry in entries. The entries that
// match nothing get a new ID that no server in servers has, a removed one
// included, so that a reference to a removed server never lands on another.
// The old servers that match nothing are removed.
//
// Merge never touches Routing. A caller that removes a server that is pinned,
// or that a rule names, has to fix those references before it stores the
// result.
//
// An empty subID, which would be the manual servers, changes nothing.
func Merge(servers []store.Server, subID string, entries []Entry) []store.Server {
	if subID == "" {
		return slices.Clone(servers)
	}

	used := make(map[string]bool, len(servers)+len(entries))
	byLink := map[string][]int{} // the indexes in servers of the old servers, by link
	for i, s := range servers {
		used[s.ID] = true
		if s.Subscription == subID && s.Link != "" {
			byLink[s.Link] = append(byLink[s.Link], i)
		}
	}

	// match[i] is the index in servers of the old server that entries[i] keeps,
	// or -1.
	match := make([]int, len(entries))
	taken := make([]bool, len(servers))
	unmatched := 0
	for i, e := range entries {
		match[i] = -1
		if q := byLink[e.Link]; len(q) > 0 {
			match[i], byLink[e.Link] = q[0], q[1:]
			taken[q[0]] = true
		} else {
			unmatched++
		}
	}
	if unmatched > 0 {
		// Only now are the outbounds worth reading: a refresh whose links did not
		// change does not get here.
		byOutbound := map[string][]int{}
		for i, s := range servers {
			if s.Subscription != subID || taken[i] {
				continue
			}
			if key := outboundKey(s.Outbound); key != "" {
				byOutbound[key] = append(byOutbound[key], i)
			}
		}
		for i, e := range entries {
			if match[i] >= 0 {
				continue
			}
			if key := outboundKey(e.Server.Outbound); key != "" {
				if q := byOutbound[key]; len(q) > 0 {
					match[i], byOutbound[key] = q[0], q[1:]
				}
			}
		}
	}

	merged := make([]store.Server, 0, len(entries))
	for i, e := range entries {
		var s store.Server
		if match[i] >= 0 {
			// The copy keeps what is not overwritten below, whatever fields the
			// server has.
			s = servers[match[i]]
		} else {
			s = store.Server{ID: freshID(used), Subscription: subID}
		}
		s.Link = e.Link
		s.Name = e.Server.Name
		s.Outbound = slices.Clone(e.Server.Outbound)
		merged = append(merged, s)
	}

	out := make([]store.Server, 0, len(servers)+len(merged))
	placed := false
	for _, s := range servers {
		if s.Subscription != subID {
			out = append(out, s)
		} else if !placed {
			out = append(out, merged...)
			placed = true
		}
	}
	if !placed {
		out = append(out, merged...)
	}
	return out
}

// outboundKey returns the canonical, compact JSON of an outbound: the same for
// objects that differ only in white space or in the order of their keys.
// Numbers are kept as written. It returns "" for what is not a JSON object, so
// that it can be no key.
func outboundKey(raw json.RawMessage) string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return ""
	}
	if _, err := dec.Token(); err != io.EOF {
		return "" // text after the object
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	key, err := json.Marshal(obj)
	if err != nil {
		return ""
	}
	return string(key)
}

// freshID returns an ID that is not in used, and adds it.
func freshID(used map[string]bool) string {
	for {
		id := newID()
		if !used[id] {
			used[id] = true
			return id
		}
	}
}
