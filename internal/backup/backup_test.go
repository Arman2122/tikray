package backup

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/store"
)

func sampleState() store.State {
	st := store.Default()
	st.Servers = []store.Server{{
		ID:       "a1b2c3d4",
		Name:     "edge-eu",
		Link:     "vless://5fdc6e8a-4a2b-4a3c-9d8e-1f2a3b4c5d6e@198.51.100.10:443?security=tls&sni=edge.example#edge-eu",
		Outbound: json.RawMessage(`{"protocol":"vless","settings":{"vnext":[{"address":"198.51.100.10","port":443,"users":[{"id":"5fdc6e8a-4a2b-4a3c-9d8e-1f2a3b4c5d6e","encryption":"none"}]}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"edge.example"}}}`),
	}}
	st.Subscriptions = []store.Subscription{{
		ID:       "11223344",
		Name:     "provider",
		URL:      "https://sub.example.com/secret-token-99887766",
		Interval: store.Duration(12 * time.Hour),
	}}
	st.Devices = []store.Device{{
		Address: netip.MustParsePrefix("192.168.88.25/32"),
		Name:    "workstation",
		MAC:     "02:11:22:33:44:55",
		Policy:  store.Policy{Mode: store.ModeSmart, KillSwitch: true},
	}}
	st.DefaultPolicy = store.Policy{Mode: store.ModeSmart}
	st.Routing.Pinned = "a1b2c3d4"
	st.Routing.BlockList = []string{"geosite:category-ads-all"}
	st.Routing.Rules = []store.Rule{{Domains: []string{"domain:example.org"}, Action: store.ActionDirect}}
	return st
}

func TestSealAndOpenRoundTrip(t *testing.T) {
	const pass = "correct-horse-battery-staple"
	st := sampleState()

	bundle, err := Seal(t.Context(), st, pass)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bundle.Format != FormatV1 || bundle.KDF != "argon2id" || bundle.CreatedAt.IsZero() {
		t.Fatalf("unexpected bundle metadata: %+v", bundle)
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		"5fdc6e8a-4a2b-4a3c-9d8e-1f2a3b4c5d6e",
		"secret-token-99887766",
		"sub.example.com",
		pass,
	} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("encrypted bundle leaked secret material")
		}
	}

	got, err := Open(t.Context(), bundle, pass)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(got.Servers) != 1 || got.Servers[0].ID != "a1b2c3d4" || got.Servers[0].Link != st.Servers[0].Link {
		t.Fatalf("restored servers differ: %+v", got.Servers)
	}
	if len(got.Subscriptions) != 1 || got.Subscriptions[0].URL != st.Subscriptions[0].URL {
		t.Fatalf("restored subscriptions differ")
	}
	if len(got.Devices) != 1 || got.Devices[0] != st.Devices[0] || got.DefaultPolicy != st.DefaultPolicy {
		t.Fatalf("restored devices/policy differ")
	}
	if got.Routing.Pinned != "a1b2c3d4" || len(got.Routing.Rules) != 1 {
		t.Fatalf("restored routing differs: %+v", got.Routing)
	}
}

func TestOpenRejectsWrongPassphraseAndTampering(t *testing.T) {
	const pass = "strong-passphrase-12345"
	bundle, err := Seal(t.Context(), sampleState(), pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), bundle, "wrong-passphrase-12345"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong passphrase err = %v, want ErrDecrypt", err)
	}
	tampered := bundle
	ctBytes, err := base64.StdEncoding.DecodeString(tampered.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	ctBytes[0] ^= 0xff
	tampered.Ciphertext = base64.StdEncoding.EncodeToString(ctBytes)
	if _, err := Open(t.Context(), tampered, pass); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered ciphertext err = %v, want ErrDecrypt", err)
	}
	badFormat := bundle
	badFormat.Format = "tikray-backup-v99"
	if _, err := Open(t.Context(), badFormat, pass); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad format err = %v, want ErrInvalid", err)
	}
	dos := bundle
	dos.KDFParams.Memory = 1024 * 1024 // 1 GiB must be rejected before hashing
	if _, err := Open(t.Context(), dos, pass); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized KDF memory err = %v, want ErrInvalid", err)
	}
}

func TestPassphraseValidationAndPrefix(t *testing.T) {
	st := store.Default()
	for _, bad := range []string{"", "short", strings.Repeat("a", MaxPassLen+1)} {
		_, err := Seal(t.Context(), st, bad)
		if !errors.Is(err, ErrInvalid) || !strings.HasPrefix(err.Error(), "backup: ") {
			t.Fatalf("Seal(len=%d) = %v, want backup: ErrInvalid", len(bad), err)
		}
		if bad != "" && strings.Contains(err.Error(), bad) {
			t.Fatal("error echoed passphrase")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Seal(ctx, st, "valid-passphrase-123"); err == nil || !strings.HasPrefix(err.Error(), "backup: ") {
		t.Fatalf("canceled Seal = %v, want prefixed error", err)
	}
}
