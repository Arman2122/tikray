package artifacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/xrayver"
)

func updateRef(component, hex string) ImageRef {
	return ImageRef{Component: component, Digest: strings.Repeat(hex, 64), Chain: strings.Repeat(hex, 128), Size: 4096, ImageID: strings.Repeat(hex, 64)}
}

// A lost response or a restart cannot authorize replacing the only recovery
// instruction with another one. The request stays readable in full.
func TestUpdateMarkerCrashRecovery(t *testing.T) {
	data := t.TempDir()
	dir := filepath.Join(data, "state")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	old, next := updateRef("runner", "a"), updateRef("runner", "b")
	sel := runnerapi.Selection{Core: "26.10.31", Config: "config/" + strings.Repeat("c", 64) + ".json"}
	now := time.Unix(1720000000, 0)
	m, err := newImageRequest(strings.Repeat("f", 32), old, next, sel, now)
	if err != nil || m.Phase != "requested" || m.Deadline-m.Started != 300 || !m.valid() {
		t.Fatal("invalid recovery envelope", err)
	}
	const n = 8
	var wg sync.WaitGroup
	outcomes := make(chan error, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := newImageRequest(m.InstallationID, old, next, sel, now)
			if e == nil {
				e = publishImageRequest(data, r)
			}
			outcomes <- e
		}()
	}
	wg.Wait()
	close(outcomes)
	accepted := 0
	for e := range outcomes {
		if e == nil {
			accepted++
		} else if !errors.Is(e, ErrImageBusy) {
			t.Fatal("unexpected publication error", e)
		}
	}
	if accepted != 1 {
		t.Fatal("more than one durable request was accepted")
	}
	got, err := readImageRequest(data, m.InstallationID)
	if err != nil || got == nil || !got.valid() || got.Previous != old || got.Candidate != next || got.SelectionDigest != m.SelectionDigest || got.Nonce == "" {
		t.Fatal("could not resume the entire original request")
	}
	if _, err := readImageRequest(data, strings.Repeat("0", 32)); err == nil {
		t.Fatal("accepted another installation's request")
	}
	path := filepath.Join(dir, "image-update.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishImageRequest(data, m); !errors.Is(err, ErrImageBusy) {
		t.Fatal("repeat overwrote a pending request")
	}
	again, _ := os.ReadFile(path)
	if string(again) != string(b) {
		t.Fatal("changed pending marker during repeat")
	}
	m.Candidate.Component = "tikray"
	if m.valid() {
		t.Fatal("accepted mismatched component")
	}
	m.Candidate = old
	if m.valid() {
		t.Fatal("accepted identical candidate and prior")
	}
	if err := os.WriteFile(path, []byte(`{"version":999,"path":"private-fixture"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if !ImagePending(data) {
		t.Fatal("unreadable marker opened ordinary mutations")
	}
	if _, err := readImageRequest(data, m.InstallationID); err == nil || strings.Contains(err.Error(), "private-fixture") {
		t.Fatal("invalid marker was accepted or echoed")
	}
}

func TestRunnerImageProofBoundToRequestAndSelection(t *testing.T) {
	data := t.TempDir()
	dir := filepath.Join(data, "state")
	os.Mkdir(dir, 0700)
	sel := runnerapi.Selection{Core: "26.10.31", Config: "config/" + strings.Repeat("c", 64) + ".json"}
	id := strings.Repeat("d", 32)
	m, _ := newImageRequest(id, updateRef("runner", "a"), updateRef("runner", "b"), sel, time.Now())
	if err := publishImageRequest(data, m); err != nil {
		t.Fatal(err)
	}
	p := imageProbe{Version: 1, Nonce: m.Nonce, Digest: m.Candidate.Digest, Challenge: strings.Repeat("e", 32)}
	setProbe := func() {
		b, _ := json.Marshal(p)
		if err := os.WriteFile(filepath.Join(dir, "image-probe.json"), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	setProbe()
	proof := filepath.Join(dir, "image-proved")
	denied := errors.New("peer detail")
	check := func(context.Context, string) error { return denied }
	if err := proveRunnerImage(t.Context(), data, id, check); err == nil || strings.Contains(err.Error(), denied.Error()) {
		t.Fatal("failed health became a public proof or diagnosis")
	}
	if _, err := os.Stat(proof); !os.IsNotExist(err) {
		t.Fatal("unhealthy runner got a proof")
	}
	err := proveRunnerImage(t.Context(), data, id, func(_ context.Context, want string) error {
		if want != m.SelectionDigest {
			t.Fatal("wrong committed selection")
		}
		p.Challenge = strings.Repeat("1", 32)
		setProbe()
		return nil
	})
	if err == nil {
		t.Fatal("stale probe was acknowledged")
	}
	if err := proveRunnerImage(t.Context(), data, id, func(context.Context, string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(proof)
	if string(raw) != p.Nonce+" "+p.Digest+" "+p.Challenge {
		t.Fatal("incomplete runner proof")
	}
}

func TestImageReceiptMissingAfterCommitCannotSelectBootstrap(t *testing.T) {
	data := t.TempDir()
	dir := filepath.Join(data, "state")
	if os.Mkdir(dir, 0700) != nil {
		t.Fatal("private fixture")
	}
	id := strings.Repeat("f", 32)
	boot := ImageBootstrap{Version: 1, Arch: "amd64", Tikray: updateRef("tikray", "a"), Runner: updateRef("runner", "b")}
	if _, err := imageVersions(data, id, "tikray", boot); err == nil {
		t.Fatal("missing lineage selected an unproven bootstrap image")
	}
	save := func(active ImageRef, previous any, id string) {
		row := map[string]any{"version": 1, "installation_id": id, "active": active, "previous": previous}
		b, _ := json.Marshal(row)
		if os.WriteFile(filepath.Join(dir, "image-tikray.json"), b, 0600) != nil {
			t.Fatal("cannot write receipt")
		}
	}
	for _, previous := range []string{"", `,"previous":{}`} {
		active, _ := json.Marshal(boot.Tikray)
		row := `{"version":1,"installation_id":"` + id + `","active":` + string(active) + previous + "}"
		if err := os.WriteFile(filepath.Join(dir, "image-tikray.json"), []byte(row), 0600); err != nil {
			t.Fatal("cannot write incomplete lineage")
		}
		if _, err := imageVersions(data, id, "tikray", boot); err == nil {
			t.Error("an incomplete receipt discarded the rollback lineage")
		}
	}
	save(boot.Tikray, nil, id)
	if r, e := imageVersions(data, id, "tikray", boot); e != nil || r.Active != boot.Tikray || r.Previous.Valid() {
		t.Fatal("initial verified receipt refused")
	}
	save(updateRef("tikray", "c"), nil, id)
	if _, e := imageVersions(data, id, "tikray", boot); e == nil {
		t.Fatal("missing rollback archive accepted")
	}
	save(updateRef("tikray", "c"), boot.Tikray, id)
	if r, e := imageVersions(data, id, "tikray", boot); e != nil || r.Previous != boot.Tikray {
		t.Fatal("committed lineage refused")
	}
	save(updateRef("tikray", "c"), boot.Runner, id)
	if _, e := imageVersions(data, id, "tikray", boot); e == nil {
		t.Fatal("cross-component rollback approved")
	}
	save(boot.Tikray, nil, strings.Repeat("e", 32))
	if _, e := imageVersions(data, id, "tikray", boot); e == nil {
		t.Fatal("another installation authorized an update")
	}
}

func TestStateRetentionUsesBothSignedControlSchemas(t *testing.T) {
	u, key := seedImageTrust(t)
	id := strings.Repeat("a", 32)
	state := filepath.Join(u.Data, "state")
	os.WriteFile(filepath.Join(state, "install.id"), []byte(id), 0600)
	stage := func(tag, schema string) ImageRef {
		t.Helper()
		raw := imageWithStateLabel(t, "tikray", u.Arch, tag, schema)
		putInboxImage(t, u, "tikray", tag, raw, signImageFixture(t, key, raw))
		im, err := u.StageImage(t.Context(), "tikray", tag)
		if err != nil {
			t.Fatal(err)
		}
		return im.Ref()
	}
	prev := stage("v2", "2")
	current := stage("v3", "3")
	b, _ := json.Marshal(imageReceipt{1, id, current, prev})
	os.WriteFile(filepath.Join(state, "image-tikray.json"), b, 0600)
	active, older, err := RetainedStateSchemas(t.Context(), u.Data)
	if err != nil || active != 3 || older != 2 {
		t.Fatal("wrong authenticated schema pair")
	}
	path := filepath.Join(u.Data, "images", imageFilename(prev)+".sig")
	if os.WriteFile(path, []byte("invalid"), 0644) != nil {
		t.Fatal("fixture")
	}
	if _, _, err := RetainedStateSchemas(t.Context(), u.Data); err == nil {
		t.Fatal("used the schema of an unverified rollback image")
	}
}

func TestOfflineRunnerRollbackNeedsCommittedSelection(t *testing.T) {
	u, key := seedImageTrust(t)
	for _, name := range []string{"v1", "v2"} {
		b := testImage(t, "runner", "amd64", name)
		putInboxImage(t, u, "runner", name, b, signImageFixture(t, key, b))
	}
	prior, err := u.StageImage(t.Context(), "runner", "v1")
	if err != nil {
		t.Fatal(err)
	}
	current, err := u.StageImage(t.Context(), "runner", "v2")
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(u.Data, "state")
	id := strings.Repeat("c", 32)
	os.WriteFile(filepath.Join(state, "install.id"), []byte(id), 0600)
	b, _ := json.Marshal(imageReceipt{1, id, current.Ref(), prior.Ref()})
	os.WriteFile(filepath.Join(state, "image-runner.json"), b, 0600)
	httpd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer httpd.Close()
	u.Runner = &runnerapi.Client{BaseURL: httpd.URL, Token: "fixture", HTTP: httpd.Client()}
	cfg := []byte(`{"routing":{}}`)
	u.Render = func(xrayver.Version, string) ([]byte, error) { return cfg, nil }
	sel := runnerapi.Selection{Core: "26.10.31", Config: ConfigName(cfg)}
	run := filepath.Join(u.Data, "run")
	os.MkdirAll(filepath.Join(run, "config"), 0700)
	os.WriteFile(filepath.Join(run, sel.Config), cfg, 0600)
	b, _ = json.Marshal(sel)
	os.WriteFile(filepath.Join(run, "active.json"), b, 0600)
	core := filepath.Join(u.Data, "cores", sel.Core)
	os.MkdirAll(core, 0755)
	bin := []byte("verified-fixture-core")
	os.WriteFile(filepath.Join(core, "xray"), bin, 0755)
	h := sha256.Sum256(bin)
	m := Meta{Version: sel.Core, Verified: "dgst", BinarySHA256: hex.EncodeToString(h[:])}
	b, _ = json.Marshal(m)
	os.WriteFile(filepath.Join(core, "meta.json"), b, 0644)
	if err := os.WriteFile(filepath.Join(run, "candidate.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := u.BeginImageRollback(t.Context(), "runner"); err == nil || ImagePending(u.Data) {
		t.Fatal("queued alongside unresolved trial")
	}
	os.Remove(filepath.Join(run, "candidate.json"))
	op, err := u.BeginImageRollback(t.Context(), "runner")
	if err != nil || op.From != current.Ref().Digest || op.To != prior.Ref().Digest {
		t.Fatal("could not queue proven rollback of unavailable runner", err)
	}
	request, err := readImageRequest(u.Data, id)
	if err != nil || request.SelectionDigest != ImageSelectionDigest(sel) {
		t.Fatal("did not bind offline rollback to the verified state")
	}
	os.Remove(filepath.Join(state, imageRequestFile))
	os.WriteFile(filepath.Join(run, sel.Config), []byte("changed"), 0600)
	if _, err = u.BeginImageRollback(t.Context(), "runner"); err == nil || ImagePending(u.Data) {
		t.Fatal("corrupt saved selection authorized offline rollback")
	}
}
