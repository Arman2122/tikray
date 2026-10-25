package subscription

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Arman2122/tikray/internal/store"
)

// Three links that differ in scheme, and whose list is long enough that its
// base64 uses characters of both alphabets (checked in TestDecode).
const (
	linkVLESS  = "vless://11111111-1111-1111-1111-111111111111@a.example.com:443?security=tls&type=ws&path=%2F%3Fed%3D2048#alpha"
	linkTrojan = "trojan://pw1@b.example.com:443?security=tls&sni=b.example.com#beta"
	linkSS     = "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#gamma"
)

var threeLinks = []string{linkVLESS, linkTrojan, linkSS}

// list is a subscription's list: comments, blank lines and the three links.
//
// The comments hold ??? and >>> at all three alignments, so that the base64 of
// the list has the standard alphabet's '/' and '+', and the URL alphabet's '_'
// and '-'.
var list = "#profile-title: test\n\n" + linkVLESS + "\n# a comment ???>>>\n#???>>>\n#a???>>>\n#ab???>>>\n" +
	linkTrojan + "\n\n\n" + linkSS + "\n"

func wrap(s string, width int, sep string) string {
	var b strings.Builder
	for len(s) > width {
		b.WriteString(s[:width] + sep)
		s = s[width:]
	}
	b.WriteString(s)
	return b.String()
}

func TestDecode(t *testing.T) {
	std := base64.StdEncoding.EncodeToString([]byte(list))
	url := base64.RawURLEncoding.EncodeToString([]byte(list))
	if !strings.ContainsAny(url, "-_") {
		t.Fatalf("the test list does not use the URL alphabet's own characters: %s", url)
	}
	if !strings.ContainsAny(std, "+/") {
		t.Fatalf("the test list does not use the standard alphabet's own characters: %s", std)
	}
	if len(std) < 3*76 {
		t.Fatalf("the test list is too short to wrap at 76 columns: %d", len(std))
	}

	for _, tc := range []struct {
		name string
		body string
		want []string
	}{
		{"plain with LF", list, threeLinks},
		{"plain with CRLF", strings.ReplaceAll(list, "\n", "\r\n"), threeLinks},
		{"plain with CR only", strings.ReplaceAll(list, "\n", "\r"), threeLinks},
		{"plain, no final newline", strings.TrimSpace(list), threeLinks},
		{"plain, indented lines", "  " + linkVLESS + " \n\t" + linkTrojan + "\t\n" + linkSS, threeLinks},
		{"plain, byte order mark", "\ufeff" + linkVLESS + "\n" + linkTrojan + "\n" + linkSS, threeLinks},
		{"base64, byte order mark", "\ufeff" + std, threeLinks},
		{"standard base64 with padding", std, threeLinks},
		{"URL base64 without padding", url, threeLinks},
		{"standard base64 without padding", strings.TrimRight(std, "="), threeLinks},
		{"URL base64 with padding", base64.URLEncoding.EncodeToString([]byte(list)), threeLinks},
		{"base64 wrapped at 76 with LF", wrap(std, 76, "\n") + "\n", threeLinks},
		{"base64 wrapped at 76 with CRLF", wrap(std, 76, "\r\n") + "\r\n", threeLinks},
		{"URL base64 wrapped at 76", wrap(url, 76, "\n"), threeLinks},
		{"base64 with spaces and tabs", " " + std[:20] + " \t" + std[20:] + " ", threeLinks},
		{"base64 of a CRLF list", base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(list, "\n", "\r\n"))), threeLinks},
		{"lines without ://", "vless:/x\nhello\n" + linkSS + "\nhttp:x\n", []string{linkSS}},
		// Providers put their own details in comment lines, URLs included.
		{"comments that hold URLs", "#support-url: https://t.me/x\n#profile-web-page-url: https://example.com/page\n" + linkSS, []string{linkSS}},
		{"comments between links", linkSS + "\n# see http://example.com\n" + linkTrojan + "\n   \t#indented: https://t.me/x\n", []string{linkSS, linkTrojan}},
		{"a link that is commented out", "#" + linkVLESS + "\n# " + linkTrojan + "\n" + linkSS, []string{linkSS}},
		{"base64 of comments that hold URLs", base64.StdEncoding.EncodeToString([]byte("#support-url: https://t.me/x\n" + linkSS + "\n")), []string{linkSS}},
		{"a # inside a link is part of it", linkSS + "\n" + linkVLESS, []string{linkSS, linkVLESS}},
		{"links are kept in order and with repeats", linkSS + "\n" + linkSS + "\n" + linkTrojan, []string{linkSS, linkSS, linkTrojan}},
		{"empty", "", nil},
		{"blank", " \r\n\t\n", nil},
		{"only comments", "#a\n#b\n", nil},
		{"not base64, not a list", "\x00\x01\x02 binary \xff\xfe", nil},
		{"base64 of text without links", base64.StdEncoding.EncodeToString([]byte("hello\nworld")), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Decode([]byte(tc.body))
			if !slices.Equal(got, tc.want) {
				t.Errorf("Decode = %q\nwant     %q", got, tc.want)
			}
		})
	}
}

func TestParseSkipsBadLines(t *testing.T) {
	body := linkVLESS + "\nvmess://!!!\n" + linkTrojan + "\nhttp://x\n"
	res := Parse([]byte(body))

	if len(res.Entries) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(res.Entries), res.Entries)
	}
	for i, want := range []struct{ link, name string }{{linkVLESS, "alpha"}, {linkTrojan, "beta"}} {
		e := res.Entries[i]
		if e.Link != want.link || e.Server.Name != want.name || len(e.Server.Outbound) == 0 {
			t.Errorf("entry %d = {%q, name %q, outbound %d bytes}, want link %q, name %q and an outbound",
				i, e.Link, e.Server.Name, len(e.Server.Outbound), want.link, want.name)
		}
		if !json.Valid(e.Server.Outbound) {
			t.Errorf("entry %d outbound is not JSON: %s", i, e.Server.Outbound)
		}
	}

	if len(res.Skipped) != 2 {
		t.Fatalf("got %d skipped lines, want 2: %+v", len(res.Skipped), res.Skipped)
	}
	vmess, ftp := res.Skipped[0], res.Skipped[1]
	if vmess.Line != "vmess://!!!" || !strings.Contains(vmess.Err, "vmess") {
		t.Errorf("skipped[0] = %+v, want the vmess line and its error", vmess)
	}
	if ftp.Line != "http://x" || !strings.Contains(ftp.Err, "unsupported") || !strings.Contains(ftp.Err, "http") {
		t.Errorf("skipped[1] = %+v, want the http line as an unsupported scheme", ftp)
	}
}

// TestParseSkipsRefusedLines checks that a line xray-core refuses (VLESS with no
// TLS and no encryption to a public address) is skipped with the reason, and
// that the lines around it still give their servers.
func TestParseSkipsRefusedLines(t *testing.T) {
	const secret = "SeCrEtSeCrEt-id"
	refused := "vless://" + secret + "@1.2.3.4:443?type=tcp#plain"
	res := Parse([]byte(linkVLESS + "\n" + refused + "\n" + linkTrojan + "\n"))

	if len(res.Entries) != 2 || res.Entries[0].Server.Name != "alpha" || res.Entries[1].Server.Name != "beta" {
		t.Fatalf("got entries %+v, want alpha and beta", res.Entries)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("got %d skipped lines, want 1: %+v", len(res.Skipped), res.Skipped)
	}
	got := res.Skipped[0]
	if got.Line != refused {
		t.Errorf("Line = %q, want the refused link %q", got.Line, refused)
	}
	if !strings.Contains(got.Err, "xray-core refuses VLESS") || strings.Contains(got.Err, secret) {
		t.Errorf("Err = %q, want the reason without the id", got.Err)
	}
}

func TestParse(t *testing.T) {
	t.Run("base64 body", func(t *testing.T) {
		res := Parse([]byte(base64.StdEncoding.EncodeToString([]byte(list))))
		if len(res.Entries) != 3 || len(res.Skipped) != 0 {
			t.Fatalf("got %d entries and %d skipped, want 3 and 0", len(res.Entries), len(res.Skipped))
		}
	})

	t.Run("duplicates keep the first", func(t *testing.T) {
		renamed := strings.Replace(linkTrojan, "#beta", "#other", 1)
		res := Parse([]byte(linkTrojan + "\n" + linkSS + "\n" + linkTrojan + "\n" + renamed + "\n  " + linkSS + "\n"))
		var links []string
		for _, e := range res.Entries {
			links = append(links, e.Link)
		}
		// A link with another name is another link: only identical lines repeat.
		if want := []string{linkTrojan, linkSS, renamed}; !slices.Equal(links, want) {
			t.Errorf("links = %q, want %q", links, want)
		}
		if res.Entries[0].Server.Name != "beta" {
			t.Errorf("first entry is named %q, want beta", res.Entries[0].Server.Name)
		}
	})

	t.Run("a bad line that repeats is reported once", func(t *testing.T) {
		res := Parse([]byte("vmess://!!!\nvmess://!!!\n"))
		if len(res.Skipped) != 1 {
			t.Errorf("got %d skipped lines, want 1: %+v", len(res.Skipped), res.Skipped)
		}
	})

	// The provider's own details are not failed lines.
	t.Run("comments that hold URLs are not skipped", func(t *testing.T) {
		body := "#support-url: https://t.me/x\n#profile-web-page-url: https://example.com/page\n" + linkSS + "\n"
		for _, b := range [][]byte{[]byte(body), []byte(base64.StdEncoding.EncodeToString([]byte(body)))} {
			res := Parse(b)
			if len(res.Entries) != 1 || len(res.Skipped) != 0 {
				t.Errorf("got %d entries and skipped %+v, want 1 entry and nothing skipped", len(res.Entries), res.Skipped)
			}
		}
	})

	t.Run("nothing to parse", func(t *testing.T) {
		for _, body := range []string{"", "\n\n", "#only a comment", "#url: https://t.me/x", "not a list"} {
			res := Parse([]byte(body))
			if len(res.Entries) != 0 || len(res.Skipped) != 0 {
				t.Errorf("Parse(%q) = %+v, want nothing", body, res)
			}
		}
	})

	// The parser's warnings are for the user: they must reach the entry.
	t.Run("warnings travel with the entry", func(t *testing.T) {
		link := "vless://11111111-1111-1111-1111-111111111111@a.example.com:443?security=tls&allowInsecure=1#insecure"
		res := Parse([]byte(link + "\n" + linkSS))
		if len(res.Entries) != 2 {
			t.Fatalf("got %d entries, want 2 (skipped %+v)", len(res.Entries), res.Skipped)
		}
		if w := res.Entries[0].Server.Warnings; len(w) == 0 || !strings.Contains(w[0], "allowInsecure") {
			t.Errorf("warnings = %q, want the allowInsecure note", w)
		}
		if w := res.Entries[1].Server.Warnings; w != nil {
			t.Errorf("warnings = %q, want none", w)
		}
	})
}

// A skipped line is shown to the owner, so it is cut; its error never repeats
// the line, which may hold a credential.
func TestSkipped(t *testing.T) {
	t.Run("the line is cut to 80 runes", func(t *testing.T) {
		long := "vless://secret@" + strings.Repeat("é", 200) + ":x"
		short := "vless://s@h:99999"
		exact := "vless://" + strings.Repeat("x", 72) // 80 runes
		over := exact + "y"
		res := Parse([]byte(long + "\n" + short + "\n" + exact + "\n" + over))
		if len(res.Skipped) != 4 {
			t.Fatalf("got %d skipped lines, want 4: %+v", len(res.Skipped), res.Skipped)
		}
		for i, want := range []string{string([]rune(long)[:80]), short, exact, exact} {
			got := res.Skipped[i].Line
			if got != want {
				t.Errorf("skipped[%d].Line = %q, want %q", i, got, want)
			}
			if !utf8.ValidString(got) || utf8.RuneCountInString(got) > 80 {
				t.Errorf("skipped[%d].Line is %d runes, valid UTF-8 %v", i, utf8.RuneCountInString(got), utf8.ValidString(got))
			}
		}
	})

	t.Run("the line is valid UTF-8 even when the body is not", func(t *testing.T) {
		res := Parse([]byte("vmess://\xff\xfe!!\n"))
		if len(res.Skipped) != 1 || !utf8.ValidString(res.Skipped[0].Line) || !utf8.ValidString(res.Skipped[0].Err) {
			t.Errorf("skipped = %+v, want one line of valid UTF-8", res.Skipped)
		}
	})

	t.Run("the error does not repeat the line", func(t *testing.T) {
		const secret = "SeCrEtSeCrEt"
		for _, line := range []string{
			"vless://" + secret + "@:443",
			"vless://" + secret + "@example.com",
			"vless://" + secret + "@example.com:99999",
			"trojan://" + secret + "@example.com:0",
			"vmess://" + secret + "!!!",
			"vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"id":"`+secret+`","add":"`)),
			"ss://" + secret + "@example.com:8388?plugin=" + secret,
			"ftp://" + secret + "@example.com",
		} {
			res := Parse([]byte(line))
			if len(res.Skipped) != 1 {
				t.Errorf("%q: got %d skipped lines (and %d entries), want 1", line, len(res.Skipped), len(res.Entries))
				continue
			}
			if got := res.Skipped[0].Err; got == "" || strings.Contains(got, secret) {
				t.Errorf("%q: Err = %q, want an error without the secret", line, got)
			}
		}
	})
}

func srv(id, name, link, sub string) store.Server {
	var out json.RawMessage
	if link != "" {
		out = json.RawMessage(`{"protocol":"vless","n":"` + name + `"}`)
	}
	return store.Server{ID: id, Name: name, Link: link, Subscription: sub, Outbound: out}
}

func entry(name, link string) Entry {
	e := Entry{Link: link}
	e.Server.Name = name
	e.Server.Outbound = json.RawMessage(`{"protocol":"vless","n":"` + name + `-new"}`)
	return e
}

func ids(servers []store.Server) []string {
	var out []string
	for _, s := range servers {
		out = append(out, s.ID)
	}
	return out
}

func clone(servers []store.Server) []store.Server {
	out := slices.Clone(servers)
	for i := range out {
		out[i].Outbound = slices.Clone(out[i].Outbound)
	}
	return out
}

var hexID = regexp.MustCompile(`^[0-9a-f]{8}$`)

func TestMergeKeepsIDs(t *testing.T) {
	m := srv("00000001", "M", "", "")
	m.Outbound = json.RawMessage(`{"protocol":"freedom"}`)
	a := srv("0000000a", "A", "link://a", "s1")
	a.Disabled = true
	b := srv("0000000b", "B", "link://b", "s1")
	c := srv("0000000c", "C", "link://c", "s2")
	servers := []store.Server{m, a, b, c}
	before := clone(servers)

	bNew := entry("B2", "link://b")
	d := entry("D", "link://d")
	aNew := entry("A2", "link://a")
	got := Merge(servers, "s1", []Entry{bNew, d, aNew})

	if !reflect.DeepEqual(servers, before) {
		t.Errorf("Merge changed its input:\n%+v\nwas\n%+v", servers, before)
	}
	if len(got) != 5 {
		t.Fatalf("got %d servers, want 5: %+v", len(got), got)
	}
	if !reflect.DeepEqual(got[0], m) {
		t.Errorf("got[0] = %+v, want the manual server %+v", got[0], m)
	}
	wantB := store.Server{ID: "0000000b", Name: "B2", Link: "link://b", Subscription: "s1", Outbound: bNew.Server.Outbound}
	if !reflect.DeepEqual(got[1], wantB) {
		t.Errorf("got[1] = %+v, want %+v", got[1], wantB)
	}
	if got[2].ID == "" || got[2].Name != "D" || got[2].Link != "link://d" || got[2].Subscription != "s1" ||
		got[2].Disabled || !bytes.Equal(got[2].Outbound, d.Server.Outbound) {
		t.Errorf("got[2] = %+v, want the new server D in s1", got[2])
	}
	if id := got[2].ID; !hexID.MatchString(id) || slices.Contains(ids(servers), id) {
		t.Errorf("D's ID %q is not a new 8-digit hex ID", id)
	}
	wantA := store.Server{ID: "0000000a", Name: "A2", Disabled: true, Link: "link://a", Subscription: "s1", Outbound: aNew.Server.Outbound}
	if !reflect.DeepEqual(got[3], wantA) {
		t.Errorf("got[3] = %+v, want %+v (still disabled)", got[3], wantA)
	}
	if !reflect.DeepEqual(got[4], c) {
		t.Errorf("got[4] = %+v, want %+v", got[4], c)
	}

	// The result does not share the entries' outbound bytes.
	got[2].Outbound[0] = 'X'
	if d.Server.Outbound[0] == 'X' {
		t.Error("the merged server shares its outbound with the entry")
	}
}

func TestMergePlacement(t *testing.T) {
	m1 := srv("00000001", "M1", "", "")
	m2 := srv("00000002", "M2", "", "")
	a := srv("0000000a", "A", "link://a", "s1")
	b := srv("0000000b", "B", "link://b", "s1")
	c := srv("0000000c", "C", "link://c", "s2")

	for _, tc := range []struct {
		name    string
		servers []store.Server
		sub     string
		entries []Entry
		want    []string // names
	}{
		{"the first old server's place, others of it removed", []store.Server{m1, a, m2, b, c}, "s1",
			[]Entry{entry("X", "link://x"), entry("B", "link://b")}, []string{"M1", "X", "B", "M2", "C"}},
		{"no old servers: at the end", []store.Server{m1, c}, "s1",
			[]Entry{entry("X", "link://x"), entry("Y", "link://y")}, []string{"M1", "C", "X", "Y"}},
		{"no servers at all", nil, "s1", []Entry{entry("X", "link://x")}, []string{"X"}},
		{"the entries' order wins over the old order", []store.Server{a, b}, "s1",
			[]Entry{entry("B", "link://b"), entry("A", "link://a")}, []string{"B", "A"}},
		{"a subscription that is last stays last", []store.Server{m1, c, a}, "s1",
			[]Entry{entry("A", "link://a"), entry("X", "link://x")}, []string{"M1", "C", "A", "X"}},
		{"nothing changed", []store.Server{m1, a, b, c}, "s1",
			[]Entry{entry("A", "link://a"), entry("B", "link://b")}, []string{"M1", "A", "B", "C"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Merge(tc.servers, tc.sub, tc.entries)
			var names []string
			seen := map[string]bool{}
			for _, s := range got {
				names = append(names, s.Name)
				if !hexID.MatchString(s.ID) || seen[s.ID] {
					t.Errorf("ID %q of %s is not an 8-digit hex ID, or is used twice", s.ID, s.Name)
				}
				seen[s.ID] = true
			}
			if !slices.Equal(names, tc.want) {
				t.Errorf("order = %v, want %v", names, tc.want)
			}
			for _, s := range got {
				if s.Subscription != "s1" && s.Subscription != "s2" && s.Subscription != "" {
					t.Errorf("%s has subscription %q", s.Name, s.Subscription)
				}
			}
		})
	}

	t.Run("the other servers are not touched", func(t *testing.T) {
		manualWithLink := srv("00000003", "Manual with a link", "link://a", "") // same link, no subscription
		got := Merge([]store.Server{manualWithLink, c}, "s1", []Entry{entry("A", "link://a")})
		if !reflect.DeepEqual(got[0], manualWithLink) || !reflect.DeepEqual(got[1], c) {
			t.Errorf("got %+v, want the manual server and C untouched", got)
		}
		if got[2].ID == manualWithLink.ID {
			t.Error("a manual server's link claimed the subscription's entry")
		}
		other := srv("0000000d", "Same link in s2", "link://a", "s2")
		got = Merge([]store.Server{other}, "s1", []Entry{entry("A", "link://a")})
		if got[0].ID != other.ID || got[1].ID == other.ID || got[1].Subscription != "s1" {
			t.Errorf("got %+v, want a server in s2 left alone and a new one in s1", got)
		}
	})
}

func TestMergeEmptyRemoves(t *testing.T) {
	m := srv("00000001", "M", "", "")
	a := srv("0000000a", "A", "link://a", "s1")
	b := srv("0000000b", "B", "link://b", "s1")
	c := srv("0000000c", "C", "link://c", "s2")

	for _, entries := range [][]Entry{nil, {}} {
		got := Merge([]store.Server{m, a, c, b}, "s1", entries)
		if want := []store.Server{m, c}; !reflect.DeepEqual(got, want) {
			t.Errorf("Merge(entries %#v) = %+v, want %+v", entries, got, want)
		}
	}

	t.Run("nothing to remove", func(t *testing.T) {
		in := []store.Server{m, c}
		got := Merge(in, "s1", nil)
		if !reflect.DeepEqual(got, in) {
			t.Errorf("got %+v, want %+v", got, in)
		}
		if got := Merge(nil, "s1", nil); len(got) != 0 {
			t.Errorf("Merge(nil, nil) = %+v, want nothing", got)
		}
	})
}

// The new IDs avoid those of every server in the list, the removed ones too,
// and each other.
func TestMergeNewIDsAreUnique(t *testing.T) {
	old := newID
	t.Cleanup(func() { newID = old })
	// The generator offers IDs in use first: the manual server's, a removed
	// server's, one it just gave, then fresh ones.
	offer := []string{"00000001", "0000000a", "10000000", "10000000", "00000001", "20000000", "30000000"}
	newID = func() string {
		id := offer[0]
		offer = offer[1:]
		return id
	}

	servers := []store.Server{srv("00000001", "M", "", ""), srv("0000000a", "A", "link://a", "s1")}
	got := Merge(servers, "s1", []Entry{entry("X", "link://x"), entry("Y", "link://y"), entry("Z", "link://z")})
	if want := []string{"00000001", "10000000", "20000000", "30000000"}; !slices.Equal(ids(got), want) {
		t.Errorf("IDs = %v, want %v", ids(got), want)
	}
}

// Entries that repeat a link (Parse never gives them) must not give two servers
// one ID.
func TestMergeRepeatedLink(t *testing.T) {
	a := srv("0000000a", "A", "link://a", "s1")
	got := Merge([]store.Server{a}, "s1", []Entry{entry("A", "link://a"), entry("A again", "link://a")})
	if len(got) != 2 || got[0].ID != "0000000a" || got[1].ID == got[0].ID {
		t.Errorf("got %+v, want the old ID once and a new one", got)
	}
}

// With no subscription ID, Merge would replace the manual servers: it leaves
// the list alone instead.
func TestMergeEmptySubscriptionID(t *testing.T) {
	servers := []store.Server{srv("00000001", "M", "", ""), srv("0000000a", "A", "link://a", "s1")}
	got := Merge(servers, "", []Entry{entry("X", "link://x")})
	if !reflect.DeepEqual(got, servers) {
		t.Errorf("got %+v, want the servers unchanged", got)
	}
	if got := Merge(servers, "", nil); !reflect.DeepEqual(got, servers) {
		t.Errorf("got %+v, want the servers unchanged", got)
	}
}

// A refresh of what Parse gave keeps every ID, and a second refresh changes
// nothing.
func TestMergeIsStable(t *testing.T) {
	res := Parse([]byte(list))
	first := Merge([]store.Server{srv("00000001", "M", "", "")}, "s1", res.Entries)
	if len(first) != 4 {
		t.Fatalf("got %d servers, want 4", len(first))
	}
	second := Merge(first, "s1", Parse([]byte(base64.StdEncoding.EncodeToString([]byte(list)))).Entries)
	if !reflect.DeepEqual(first, second) {
		t.Errorf("a second refresh changed the servers:\n%+v\n%+v", second, first)
	}
}

// The outbounds the identity tests give their servers.
const (
	outboundA = `{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com","port":443}]}}`
	outboundB = `{"protocol":"trojan","settings":{"servers":[{"address":"b.example.com","port":443}]}}`
	outboundC = `{"protocol":"shadowsocks","settings":{"servers":[{"address":"c.example.com","port":8388}]}}`
)

func srvOut(id, name, link, sub, outbound string) store.Server {
	return store.Server{ID: id, Name: name, Link: link, Subscription: sub, Outbound: json.RawMessage(outbound)}
}

func entryOut(name, link, outbound string) Entry {
	e := Entry{Link: link}
	e.Server.Name = name
	e.Server.Outbound = json.RawMessage(outbound)
	return e
}

// vmessLink is the link of a VMess server whose provider put ps in its name.
func vmessLink(ps string) string {
	obj := `{"v":"2","ps":` + strconv.Quote(ps) + `,"add":"vm.example.com","port":"443",` +
		`"id":"22222222-2222-2222-2222-222222222222","aid":"0","net":"tcp","type":"none","tls":""}`
	return "vmess://" + base64.StdEncoding.EncodeToString([]byte(obj))
}

// Providers write volatile text, such as the traffic left or the expiry, in
// the name of a link. A server is the same server while its outbound is, so
// that its ID, Disabled and the references to it survive a refresh.
func TestMergeMatchesByOutbound(t *testing.T) {
	t.Run("a changed fragment keeps the ID and Disabled", func(t *testing.T) {
		first := Merge(nil, "s1", Parse([]byte(linkVLESS+"\n"+linkTrojan+"\n"+linkSS)).Entries)
		if len(first) != 3 {
			t.Fatalf("got %d servers, want 3", len(first))
		}
		first[0].Disabled = true
		before := clone(first)

		volatile := strings.Replace(linkVLESS, "#alpha", "#alpha | 12.5 GB left, expires 2026-12-01", 1)
		res := Parse([]byte(volatile + "\n" + linkTrojan + "\n" + linkSS))
		if len(res.Entries) != 3 {
			t.Fatalf("got %d entries, want 3 (skipped %+v)", len(res.Entries), res.Skipped)
		}
		got := Merge(first, "s1", res.Entries)

		if !reflect.DeepEqual(first, before) {
			t.Error("Merge changed its input")
		}
		if len(got) != 3 || !slices.Equal(ids(got), ids(first)) {
			t.Fatalf("IDs = %v, want %v", ids(got), ids(first))
		}
		want := first[0]
		want.Link = volatile
		want.Name = "alpha | 12.5 GB left, expires 2026-12-01"
		if !reflect.DeepEqual(got[0], want) {
			t.Errorf("got[0] = %+v, want %+v (disabled, with the new link and name)", got[0], want)
		}
		if !reflect.DeepEqual(got[1:], first[1:]) {
			t.Errorf("the other servers changed: %+v", got[1:])
		}

		// The next refresh finds the server by its new link.
		again := Merge(got, "s1", res.Entries)
		if !reflect.DeepEqual(again, got) {
			t.Errorf("a second refresh changed the servers:\n%+v\n%+v", again, got)
		}
	})

	t.Run("a VMess link whose ps changed keeps the ID", func(t *testing.T) {
		old, changed := vmessLink("vm | 40 GB left"), vmessLink("vm | 39 GB left")
		first := Merge(nil, "s1", Parse([]byte(old)).Entries)
		res := Parse([]byte(changed))
		if len(first) != 1 || len(res.Entries) != 1 {
			t.Fatalf("got %d servers and %d entries (skipped %+v), want 1 and 1", len(first), len(res.Entries), res.Skipped)
		}
		if old == changed || first[0].Name != "vm | 40 GB left" || res.Entries[0].Server.Name != "vm | 39 GB left" {
			t.Fatalf("the test links do not differ in the name: %q, %q", first[0].Name, res.Entries[0].Server.Name)
		}
		got := Merge(first, "s1", res.Entries)
		if len(got) != 1 || got[0].ID != first[0].ID || got[0].Name != "vm | 39 GB left" || got[0].Link != changed {
			t.Errorf("got %+v, want the server %s renamed", got, first[0].ID)
		}
	})

	t.Run("the whole server is kept but its link, name and outbound", func(t *testing.T) {
		old := srvOut("0000000a", "A", "link://a", "s1", outboundA)
		old.Disabled = true
		got := Merge([]store.Server{old}, "s1", []Entry{entryOut("A renamed", "link://a2", outboundA)})
		want := old
		want.Link, want.Name, want.Outbound = "link://a2", "A renamed", json.RawMessage(outboundA)
		if len(got) != 1 || !reflect.DeepEqual(got[0], want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("the outbound is compared as JSON, not as bytes", func(t *testing.T) {
		stored := "{\n  \"settings\": {\"vnext\": [ {\"port\": 443, \"address\": \"a.example.com\"} ]},\n  \"protocol\": \"vless\"\n}\n"
		old := srvOut("0000000a", "A", "link://a", "s1", stored)
		got := Merge([]store.Server{old}, "s1", []Entry{entryOut("A", "link://a2", outboundA)})
		if len(got) != 1 || got[0].ID != "0000000a" {
			t.Errorf("got %+v, want the old server's ID", got)
		}
	})

	t.Run("another outbound is another server", func(t *testing.T) {
		old := srvOut("0000000a", "A", "link://a", "s1", outboundA)
		for _, other := range []string{
			outboundB,
			strings.Replace(outboundA, "443", "444", 1),
			strings.Replace(outboundA, "443", "443.0", 1),
			strings.Replace(outboundA, "a.example.com", "A.example.com", 1),
		} {
			got := Merge([]store.Server{old}, "s1", []Entry{entryOut("A", "link://a2", other)})
			if len(got) != 1 || got[0].ID == "0000000a" {
				t.Errorf("outbound %s: got %+v, want a new ID", other, got)
			}
		}
	})

	t.Run("only the subscription's own servers match", func(t *testing.T) {
		manual := srvOut("00000001", "Manual", "", "", outboundA)
		other := srvOut("00000002", "Other", "link://o", "s2", outboundA)
		got := Merge([]store.Server{manual, other}, "s1", []Entry{entryOut("A", "link://a", outboundA)})
		if len(got) != 3 || !reflect.DeepEqual(got[:2], []store.Server{manual, other}) {
			t.Fatalf("got %+v, want the manual server and the s2 server untouched", got)
		}
		if id := got[2].ID; id == manual.ID || id == other.ID || got[2].Subscription != "s1" {
			t.Errorf("got[2] = %+v, want a new server in s1", got[2])
		}
	})

	t.Run("an outbound that is not JSON, or empty, matches nothing", func(t *testing.T) {
		for _, out := range []string{"", "{", "null", "[1,"} {
			old := srvOut("0000000a", "A", "link://a", "s1", out)
			got := Merge([]store.Server{old}, "s1", []Entry{entryOut("A", "link://a2", out)})
			if len(got) != 1 || got[0].ID == "0000000a" {
				t.Errorf("outbound %q: got %+v, want a new ID", out, got)
			}
		}
	})
}

// A server is claimed by one entry at most, and a link beats an outbound.
func TestMergeIdentityRules(t *testing.T) {
	t.Run("identical outbounds, different links: one matches, the other is new", func(t *testing.T) {
		old := srvOut("0000000a", "A", "link://a", "s1", outboundA)
		got := Merge([]store.Server{old}, "s1", []Entry{
			entryOut("first", "link://b", outboundA),
			entryOut("second", "link://c", outboundA),
		})
		if len(got) != 2 {
			t.Fatalf("got %d servers, want 2: %+v", len(got), got)
		}
		if got[0].ID != "0000000a" || got[0].Name != "first" || got[1].Name != "second" {
			t.Errorf("got %+v, want the first entry to take the old ID", got)
		}
		if got[1].ID == "0000000a" || !hexID.MatchString(got[1].ID) {
			t.Errorf("the second entry's ID is %q, want a new one", got[1].ID)
		}
	})

	t.Run("two old servers with one outbound go to two entries, in order", func(t *testing.T) {
		a := srvOut("0000000a", "A", "link://a", "s1", outboundA)
		b := srvOut("0000000b", "B", "link://b", "s1", outboundA)
		got := Merge([]store.Server{a, b}, "s1", []Entry{
			entryOut("x", "link://x", outboundA),
			entryOut("y", "link://y", outboundA),
			entryOut("z", "link://z", outboundA),
		})
		if len(got) != 3 || got[0].ID != "0000000a" || got[1].ID != "0000000b" || slices.Contains([]string{"0000000a", "0000000b"}, got[2].ID) {
			t.Errorf("IDs = %v, want the two old ones in order and a new one", ids(got))
		}
	})

	t.Run("a link match wins over an outbound match", func(t *testing.T) {
		a := srvOut("0000000a", "A", "link://a", "s1", outboundA)
		b := srvOut("0000000b", "B", "link://b", "s1", outboundA)
		// B's link and A's outbound: B it is, whatever the order of the old servers.
		for _, servers := range [][]store.Server{{a, b}, {b, a}} {
			got := Merge(servers, "s1", []Entry{entryOut("new", "link://b", outboundA)})
			if len(got) != 1 || got[0].ID != "0000000b" {
				t.Errorf("got %+v, want B's ID", got)
			}
		}
	})

	t.Run("an entry that matches by link is not outbid by an earlier entry's outbound", func(t *testing.T) {
		a := srvOut("0000000a", "A", "link://a", "s1", outboundA)
		b := srvOut("0000000b", "B", "link://b", "s1", outboundB)
		// The first entry has B's outbound, the second B's link.
		got := Merge([]store.Server{a, b}, "s1", []Entry{
			entryOut("by outbound", "link://c", outboundB),
			entryOut("by link", "link://b", outboundC),
		})
		if len(got) != 2 {
			t.Fatalf("got %d servers, want 2: %+v", len(got), got)
		}
		if got[1].ID != "0000000b" || got[1].Name != "by link" {
			t.Errorf("got[1] = %+v, want B's ID, through its link", got[1])
		}
		if got[0].ID == "0000000a" || got[0].ID == "0000000b" || !hexID.MatchString(got[0].ID) {
			t.Errorf("got[0].ID = %q, want a new ID: B was taken, and A's outbound is another", got[0].ID)
		}
	})

	t.Run("link matches and outbound matches together", func(t *testing.T) {
		a := srvOut("0000000a", "A", "link://a", "s1", outboundA)
		b := srvOut("0000000b", "B", "link://b", "s1", outboundA)
		c := srvOut("0000000c", "C", "link://c", "s1", outboundC)
		got := Merge([]store.Server{a, b, c}, "s1", []Entry{
			entryOut("same A outbound, new link", "link://d", outboundA), // B is taken by link: this is A
			entryOut("by link", "link://b", outboundA),
			entryOut("C moved", "link://e", outboundC),
		})
		if want := []string{"0000000a", "0000000b", "0000000c"}; !slices.Equal(ids(got), want) {
			t.Errorf("IDs = %v, want %v", ids(got), want)
		}
	})

	t.Run("a removed server's ID is not reused", func(t *testing.T) {
		a := srvOut("0000000a", "A", "link://a", "s1", outboundA)
		got := Merge([]store.Server{a}, "s1", []Entry{entryOut("B", "link://b", outboundB)})
		if len(got) != 1 || got[0].ID == "0000000a" {
			t.Errorf("got %+v, want a new ID", got)
		}
	})
}
