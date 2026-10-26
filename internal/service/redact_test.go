package service

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Arman2122/tikray/internal/store"
)

// secret is a credential a test redacts; name stands for it in failure
// messages, which never print it.
type secret struct{ name, value string }

// wantRedacted fails if any of secrets is in got.
func wantRedacted(t *testing.T, got string, secrets ...secret) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(got, s.value) {
			t.Errorf("the redacted text still holds %s", s.name)
		}
	}
}

// wantText fails unless got is want, and prints got with each of secrets
// shown by its name.
func wantText(t *testing.T, got, want string, secrets ...secret) {
	t.Helper()
	if got == want {
		return
	}
	for _, s := range secrets {
		got = strings.ReplaceAll(got, s.value, "<"+s.name+">")
	}
	t.Errorf("redacted text = %q, want %q", got, want)
}

func server(id, outbound string) store.Server {
	return store.Server{ID: id, Name: "s-" + id, Outbound: json.RawMessage(outbound)}
}

func TestRedactorCoversSecrets(t *testing.T) {
	const (
		trojanPW = "trojan-pass-1234"
		ssPW     = "ss-pass-5678"
		subURL   = "https://sub.example.com/api/v1/client/subscribe?token=0123456789abcdef"
		short    = "abc"
	)
	st := store.Default()
	st.Servers = []store.Server{
		server("00000001", vlessOutbound),
		server("00000002", `{"protocol":"trojan","settings":{"servers":[{"address":"example.com","port":443,"password":"`+trojanPW+`"}]}}`),
		server("00000003", `{"protocol":"shadowsocks","settings":{"servers":[{"address":"192.0.2.7","port":8388,"method":"aes-256-gcm","password":"`+ssPW+`"}]}}`),
		server("00000004", `{"protocol":"trojan","settings":{"servers":[{"address":"example.org","port":443,"password":"`+short+`"}]}}`),
	}
	st.Subscriptions = []store.Subscription{{ID: "0000000a", Name: "sub", URL: subURL}}
	red := RedactorFor(st)

	in := "user " + vlessID + " rejected; trojan " + trojanPW + "; ss=" + ssPW + `; fetching "` + subURL + `" failed; pw ` + short
	got := red(in)
	secrets := []secret{
		{"the subscription URL", subURL},
		{"the subscription token", "0123456789abcdef"},
		{"the VLESS id", vlessID},
		{"the Trojan password", trojanPW},
		{"the SS password", ssPW},
	}
	wantRedacted(t, got, secrets...)
	want := "user " + redacted + " rejected; trojan " + redacted + "; ss=" + redacted + `; fetching "` + redacted + `" failed; pw abc`
	wantText(t, got, want, secrets...)
	if got := red("nothing secret here"); got != "nothing secret here" {
		t.Errorf("text with no secret became %q", got)
	}
}

// Secrets sit at any depth of an outbound, under keys in any case (xray reads
// its keys without regard to case), and in lists under those keys. WireGuard's
// private key is secretKey in xray; a public key and a number are no secrets.
func TestRedactorFindsSecretsAnywhere(t *testing.T) {
	st := store.Default()
	st.Servers = []store.Server{
		server("00000001", `{"protocol":"wireguard","settings":{"secretKey":"wg-secret-key-0","privateKey":"wg-private-key-1","peers":[{"publicKey":"wg-public","preSharedKey":"wg-psk-2"}]}}`),
		server("00000002", `{"protocol":"vless","streamSettings":{"kcpSettings":{"seed":"kcp-seed-3"}},"settings":{"vnext":[{"users":[{"ID":"upper-case-id-4"}]}]}}`),
		server("00000003", `{"protocol":"trojan","settings":{"servers":[{"PassWord":["list-pass-5","list-pass-6"],"id":12345678}]}}`),
		server("00000004", `{"protocol":"wireguard","settings":{"SecretKey":"wg-secret-key-7"}}`),
	}
	got := RedactorFor(st)("wg-secret-key-0 wg-private-key-1 wg-psk-2 kcp-seed-3 upper-case-id-4 list-pass-5 list-pass-6 wg-secret-key-7 12345678 wg-public")
	want := strings.Repeat(redacted+" ", 8) + "12345678 wg-public"
	wantText(t, got, want,
		secret{"the WireGuard secret key", "wg-secret-key-0"},
		secret{"the other WireGuard secret key", "wg-secret-key-7"},
		secret{"the WireGuard key", "wg-private-key-1"},
		secret{"the pre-shared key", "wg-psk-2"},
		secret{"the mKCP seed", "kcp-seed-3"},
		secret{"the ID", "upper-case-id-4"},
		secret{"a listed password", "list-pass-5"},
		secret{"another", "list-pass-6"},
	)
}

// The other protocols' credentials, as xray's config names them: SOCKS's and
// HTTP's user and pass, MASQUE's pass, Hysteria 2's auth, a TLS client
// certificate's key (its PEM lines) and XDrive's secrets, in any case.
func TestRedactorCoversOtherCredentials(t *testing.T) {
	for _, c := range []struct {
		name, outbound string
		secrets        []string
	}{
		{"socks", `{"protocol":"socks","settings":{"servers":[{"address":"192.0.2.7","port":1080,"users":[{"user":"socks-user-1","pass":"socks-pass-2"}]}]}}`,
			[]string{"socks-user-1", "socks-pass-2"}},
		{"http", `{"protocol":"http","settings":{"servers":[{"address":"192.0.2.7","port":8080,"users":[{"User":"http-user-3","PASS":"http-pass-4"}]}]}}`,
			[]string{"http-user-3", "http-pass-4"}},
		{"masque", `{"protocol":"masque","settings":{"address":"192.0.2.7","port":443,"pass":"masque-pass-5"}}`,
			[]string{"masque-pass-5"}},
		{"hysteria2", `{"protocol":"hysteria","settings":{"version":2,"address":"192.0.2.7","port":443},"streamSettings":{"network":"hysteria","hysteriaSettings":{"version":2,"Auth":"hy2-auth-6"}}}`,
			[]string{"hy2-auth-6"}},
		{"a client certificate's key", `{"protocol":"vless","streamSettings":{"security":"tls","tlsSettings":{"certificates":[{"usage":"encipherment","certificate":["cert-line-7"],"key":["key-line-8","key-line-9"]}]}}}`,
			[]string{"key-line-8", "key-line-9"}},
		{"xdrive", `{"protocol":"vless","streamSettings":{"network":"xdrive","xdriveSettings":{"service":"gdrive","Secrets":["drive-secret-10","drive-secret-11"]}}}`,
			[]string{"drive-secret-10", "drive-secret-11"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			st := store.Default()
			st.Servers = []store.Server{server("00000001", c.outbound)}
			text := strings.Join(c.secrets, " ") + " 192.0.2.7 cert-line-7"
			var secrets []secret
			for i, s := range c.secrets {
				secrets = append(secrets, secret{fmt.Sprintf("secret %d", i), s})
			}
			want := strings.Repeat(redacted+" ", len(c.secrets)) + "192.0.2.7 cert-line-7"
			wantText(t, RedactorFor(st)(text), want, secrets...)
		})
	}
}

// A secret that holds another is replaced whole, whichever comes first.
func TestRedactorReplacesLongerSecretsFirst(t *testing.T) {
	st := store.Default()
	st.Servers = []store.Server{
		server("00000001", `{"protocol":"trojan","settings":{"servers":[{"password":"pass"}]}}`),
		server("00000002", `{"protocol":"trojan","settings":{"servers":[{"password":"my-pass-word"}]}}`),
		server("00000003", `{"protocol":"trojan","settings":{"servers":[{"password":"zzmy-"}]}}`),
	}
	// In the last word two secrets overlap without one holding the other:
	// neither may leave a part behind.
	got := RedactorFor(st)("a my-pass-word b pass c zzmy-pass-word")
	secrets := []secret{{"the longer password", "my-pass-word"}, {"the third", "zzmy-"}, {"the shorter one", "pass"}}
	wantRedacted(t, got, secrets...)
	wantText(t, got, "a "+redacted+" b "+redacted+" c "+redacted, secrets...)
}

// RedactorWith reads documents that are no part of the state, such as an xray
// config a command runs a core with, by the rules RedactorFor reads an
// outbound by: the credentials at any depth, whatever the document's shape.
func TestRedactorWithDocuments(t *testing.T) {
	st := store.Default()
	st.Servers = []store.Server{server("00000001", `{"protocol":"trojan","settings":{"servers":[{"password":"state-password"}]}}`)}
	doc := json.RawMessage(`{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"users":[{"id":"file-uuid-0001"}]}]}},{"protocol":"trojan","settings":{"servers":[{"password":"file-password","address":"198.51.100.8"}]}}],"inbounds":[{"settings":{"clients":[{"id":"inbound-uuid-02"}]}}]}`)
	secrets := []secret{
		{"the state's password", "state-password"}, {"a file ID", "file-uuid-0001"},
		{"a file password", "file-password"}, {"an inbound ID", "inbound-uuid-02"},
	}
	text := "x state-password y file-uuid-0001 z file-password w inbound-uuid-02 v 198.51.100.8"

	got := RedactorWith(st, doc)(text)
	wantRedacted(t, got, secrets...)
	if !strings.Contains(got, "198.51.100.8") {
		t.Errorf("redacted text %q hides an address, which is no credential", got)
	}
	// Without the document its credentials are not known, and a document that
	// is no JSON adds nothing and breaks nothing.
	if got := RedactorFor(st)(text); !strings.Contains(got, "file-uuid-0001") {
		t.Errorf("RedactorFor hides a credential it was not told: %q", got)
	}
	if got := RedactorWith(st, json.RawMessage(`not json`), nil)("state-password file-uuid-0001"); strings.Contains(got, "state-password") || !strings.Contains(got, "file-uuid-0001") {
		t.Errorf("with a document that is no JSON: %q", got)
	}
	if got := RedactorWith(store.Default())("nothing here"); got != "nothing here" {
		t.Errorf("with nothing to hide: %q", got)
	}
}

// A subscription URL is a secret in every form a client's error can show it
// in: as it is, with its password masked, without its userinfo, and its
// userinfo alone. The probe URL is no secret, but its userinfo is.
func TestRedactorCoversURLForms(t *testing.T) {
	st := store.Default()
	st.Subscriptions = []store.Subscription{{ID: "0000000a", Name: "sub", URL: "https://subuser:subpass99@sub.example.com/s/tok-777"}}
	st.Health.ProbeURL = "https://probeuser:probepass@probe.example.com/generate_204"
	red := RedactorFor(st)
	for _, in := range []string{
		`Get "https://subuser:subpass99@sub.example.com/s/tok-777": EOF`,
		`Get "https://subuser:***@sub.example.com/s/tok-777": EOF`,
		`fetch https://subuser:xxxxx@sub.example.com/s/tok-777 failed`,
		`redirected from https://sub.example.com/s/tok-777`,
		`user subuser, password subpass99`,
	} {
		got := red(in)
		wantRedacted(t, got, secret{"the subscription's user", "subuser"}, secret{"its password", "subpass99"}, secret{"its token", "tok-777"})
	}
	got := red(`Get "https://probeuser:***@probe.example.com/generate_204": probepass`)
	probe := []secret{{"the probe's user", "probeuser"}, {"its password", "probepass"}}
	wantRedacted(t, got, probe...)
	wantText(t, got, `Get "https://`+redacted+`:***@probe.example.com/generate_204": `+redacted, probe...)
}

// A server's share link encodes its credentials, an SS password in base64.
func TestRedactorCoversShareLinks(t *testing.T) {
	const link = "ss://YWVzLTI1Ni1nY206c2VjcmV0LXBhc3M@192.0.2.7:8388#home"
	st := store.Default()
	s := server("00000001", `{"protocol":"shadowsocks","settings":{"servers":[{"password":"secret-pass"}]}}`)
	s.Link = link
	st.Servers = []store.Server{s}
	got := RedactorFor(st)("parsing " + link + ": bad port")
	wantRedacted(t, got, secret{"the link", "YWVzLTI1Ni1nY206c2VjcmV0LXBhc3M"})
}

// The service's redactor follows the state: a server added since is covered.
func TestServiceRedactorFollowsState(t *testing.T) {
	e := newEnv(t)
	red := e.s.Redactor()
	if got := red("user " + vlessID); got != "user "+vlessID {
		t.Fatalf("before the server is added, the redactor changed the text")
	}
	e.addServer("v", vlessOutbound)
	if got := red("user " + vlessID); got != "user "+redacted {
		t.Errorf("after the server is added, the redactor leaves its id")
	}
}
