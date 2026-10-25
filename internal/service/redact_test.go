package service

import (
	"encoding/json"
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
