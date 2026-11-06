//go:build lab

package m3

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	native "github.com/Arman2122/tikray/internal/routeros"
)

// Use the production transport against the same two pinned CHRs as Task 0.
// Each read selects the exact disposable row on the router.
func TestM3NativeClient(t *testing.T) {
	r := newRig(t)
	pemText, e := r.chr.RunPrivate(r.ctx, ":put [/file/get m3-cap-public.crt contents]")
	block, _ := pem.Decode([]byte(pemText))
	if e != nil || block == nil {
		t.Fatal("native client: certificate fixture unavailable")
	}
	sum := sha256.Sum256(block.Bytes)
	password, e := r.chr.RunPrivate(r.ctx, `{ :local p [:rndstr length=40 from="abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"]; /user/add name=m3-native-user group=m3-cap-group address=172.31.255.2/32 password=$p; :put $p }`)
	password = strings.TrimSpace(password)
	if e != nil || len(password) != 40 {
		t.Fatal("native client: account fixture unavailable")
	}
	r.auditCanary(t, password)
	ctx, cancel := context.WithTimeout(r.ctx, 25*time.Second)
	defer cancel()
	client, e := native.Dial(ctx, native.ConnConfig{Address: "172.31.255.1:8729", Username: "m3-native-user", Password: password, Fingerprint: hex.EncodeToString(sum[:])})
	if e != nil {
		t.Fatalf("native client: pin=%t profile=%t protocol=%t limit=%t deadline=%t auth=%t", errors.Is(e, native.ErrPin), errors.Is(e, native.ErrUnsupported), errors.Is(e, native.ErrProtocol), errors.Is(e, native.ErrLimit), errors.Is(e, context.DeadlineExceeded), errors.Is(e, native.ErrAuth))
	}
	defer client.Close()
	if client.Profile().Version() != r.version || client.Generation() == 0 {
		t.Fatal("native client: profile mismatch")
	}
	tag := "tikray:native-client-fixture"
	add, e := client.Command(ctx, []string{"/ip/firewall/address-list/add", "=list=tikray-native-test", "=address=192.0.2.18", "=comment=" + tag})
	if e != nil || len(add) != 1 || add[0]["ret"] == "" {
		t.Fatal("native client: add acknowledgement missing")
	}
	id := add[0]["ret"]
	lctx, lcancel := context.WithCancel(ctx)
	defer lcancel()
	ready := make(chan struct{}, 1)
	changed := make(chan struct{}, 1)
	foreign := make(chan struct{}, 1)
	ended := make(chan error, 1)
	go func() {
		ended <- client.Listen(lctx, []string{"/ip/firewall/address-list/listen", "?comment=" + tag, "=.proplist=.id,.dead,comment,address"}, func(ch native.Change) {
			if ch.Kind == native.ChangeReady {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
			if ch.Kind == native.ChangeRow && ch.Row[".id"] != "" && ch.Row[".id"] != id {
				select {
				case foreign <- struct{}{}:
				default:
				}
			}
			if ch.Kind == native.ChangeRow && ch.Row[".id"] == id && ch.Row["address"] == "192.0.2.19" {
				select {
				case changed <- struct{}{}:
				default:
				}
			}
		})
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal("native client: listener did not start")
	}
	query := []string{"/ip/firewall/address-list/print", "?comment=" + tag, "=.proplist=.id,comment"}
	rows, e := client.Command(ctx, query)
	if e != nil || len(rows) != 1 || rows[0][".id"] != id {
		t.Fatal("native client: filtered read failed")
	}
	decoy, e := client.Command(ctx, []string{"/ip/firewall/address-list/add", "=list=owner-native-decoy", "=address=192.0.2.38", "=comment=owner:native-decoy"})
	if e != nil || len(decoy) != 1 || decoy[0]["ret"] == "" {
		t.Fatal("native client: foreign control failed")
	}
	defer r.admin.RunContext(r.ctx, "/ip/firewall/address-list/remove", "=.id="+decoy[0]["ret"])
	if _, e = client.Command(ctx, []string{"/ip/firewall/address-list/set", "=.id=" + decoy[0]["ret"], "=address=192.0.2.39"}); e != nil {
		t.Fatal("native client: foreign change control failed")
	}
	if _, e = client.Command(ctx, []string{"/ip/firewall/address-list/set", "=.id=" + id, "=address=192.0.2.19"}); e != nil {
		t.Fatal("native client: set failed")
	}
	select {
	case <-changed:
	case <-foreign:
		t.Fatal("native client: subscription filter leaked a foreign row")
	case <-ended:
		t.Fatal("native client: subscription ended before its observation")
	case <-ctx.Done():
		t.Fatal("native client: filtered change notification missing")
	}
	select {
	case <-foreign:
		t.Fatal("native client: subscription filter leaked a foreign row")
	case <-time.After(time.Second):
	}
	if _, e = client.Command(ctx, []string{"/ip/firewall/address-list/remove", "=.id=" + id}); e != nil {
		t.Fatal("native client: remove failed")
	}
	lcancel()
	select {
	case <-ended:
	case <-time.After(3 * time.Second):
		t.Fatal("native client: cancellation stalled")
	}
	rows, e = client.Command(ctx, query)
	if e != nil || len(rows) != 0 || client.Generation() != 1 {
		t.Fatal("native client: cancellation broke the shared connection")
	}
	t.Log("native client: pinned profile, filtered CRUD, changed-row event and targeted cancellation passed on one connection")
}
