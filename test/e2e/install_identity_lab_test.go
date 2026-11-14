//go:build lab

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var publicInstallID = regexp.MustCompile(`^[a-f0-9]{32}$`)

type watchdogRecord struct {
	InstallationID string `json:"installation_id"`
	Control        struct {
		Misses int `json:"miss"`
	} `json:"tikray"`
}

func (f *installLab) watchdogRecord(ctx context.Context, t *testing.T) watchdogRecord {
	t.Helper()
	comment := f.mustRun(ctx, t, `:put [/system/script/get [find where name="tikray-watchdog-state"] comment]`)
	raw, ok := strings.CutPrefix(comment, "tikray:watchdog-state ")
	var record watchdogRecord
	if !ok || json.Unmarshal([]byte(raw), &record) != nil || !publicInstallID.MatchString(record.InstallationID) {
		t.Fatal("unreadable watchdog installation identity")
	}
	return record
}

func (f *installLab) checkHealthIdentity(ctx context.Context, t *testing.T) string {
	t.Helper()
	id := f.file(ctx, t, dataRoot+"/state/install.id")
	if !publicInstallID.MatchString(id) || f.watchdogRecord(ctx, t).InstallationID != id {
		t.Fatal("installation and watchdog identity differ")
	}
	api := f.pinned(ctx, t)
	probe, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(probe, http.MethodGet, api.BaseURL+"/healthz", nil)
	if err != nil {
		t.Fatal("health request fixture")
	}
	resp, err := api.HTTPClient().Do(req)
	if err != nil {
		t.Fatal("managed public health endpoint unavailable")
	}
	defer resp.Body.Close()
	var result struct {
		OK bool   `json:"ok"`
		ID string `json:"installation_id"`
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1025))
	if err != nil || len(body) > 1024 || resp.StatusCode != http.StatusOK || json.Unmarshal(body, &result) != nil || !result.OK || result.ID != id {
		t.Fatal("managed public health endpoint omitted the installation identity")
	}
	return id
}

// The owner fixture deliberately sends an output connection to a different
// HTTPS responder. Both responders return 200 and the same JSON shape, so
// accepting the wrong ID cannot pass as a network or certificate failure.
func (f *installLab) checkWrongHealthIdentity(ctx context.Context, t *testing.T, tick func()) {
	t.Helper()
	id := f.checkHealthIdentity(ctx, t)
	wrong := "a" + id[1:]
	if wrong == id {
		wrong = "b" + id[1:]
	}
	if f.watchdogRecord(ctx, t).Control.Misses != 0 {
		t.Fatal("healthy control did not clear the watchdog counter")
	}
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"installation_id":"%s"}`, wrong)
	}))
	server.Listener.Close()
	ln, err := net.Listen("tcp4", "192.168.88.201:0")
	if err != nil {
		t.Fatal("wrong-ID HTTPS witness could not bind on lab LAN")
	}
	server.Listener = ln
	server.StartTLS()
	defer server.Close()

	const tag = "lab:watchdog-wrong-identity"
	f.mustRun(ctx, t, `/ip/firewall/nat/add chain=output action=dst-nat protocol=tcp dst-address=172.30.252.2 dst-port=443 to-addresses=192.168.88.201 to-ports=`+strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)+` comment="`+tag+`"`)
	active := true
	remove := func() {
		t.Helper()
		if active {
			f.mustRun(ctx, t, `/ip/firewall/nat/remove [find where comment="`+tag+`"]`)
			active = false
		}
	}
	defer remove()
	control := f.mustRun(ctx, t, `{:local r [/tool/fetch url="https://172.30.252.2/healthz" src-address=172.30.252.1 output=user check-certificate=no http-max-redirect-count=0 as-value]; :local b [:deserialize from=json options=json.no-string-conversion value=($r->"data")]; :put ((($b->"ok") = true) and (($b->"installation_id") = "`+wrong+`"))}`)
	if control != "true" || requests.Load() == 0 {
		t.Fatal("independent wrong-service reachability control failed")
	}
	before := requests.Load()
	tick()
	if requests.Load() <= before || f.watchdogRecord(ctx, t).Control.Misses != 1 {
		t.Fatal("valid HTTPS response from another installation counted healthy")
	}
	remove()
	tick()
	if f.watchdogRecord(ctx, t).Control.Misses != 0 {
		t.Fatal("genuine control identity did not restore health")
	}
}
