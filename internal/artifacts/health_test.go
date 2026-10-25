package artifacts

import (
	"context"
	"errors"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Arman2122/tikray/internal/runnerapi"
)

// healthFunc is a HealthChecker made of a function.
type healthFunc func(ctx context.Context) error

func (f healthFunc) Check(ctx context.Context) error { return f(ctx) }

func TestSOCKSProbe(t *testing.T) {
	origin := serve(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/generate_204":
			w.WriteHeader(http.StatusNoContent)
		case "/ok":
			w.Write([]byte("hello"))
		case "/blocked":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/moved":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/slow":
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		default:
			http.NotFound(w, r)
		}
	})
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	// The name cannot resolve locally: only the SOCKS server can map it.
	host := "probe.invalid:" + port
	socks, asked := startSOCKS5(t, map[string]string{host: origin.Listener.Addr().String()})

	for _, path := range []string{"/generate_204", "/ok"} {
		if err := (SOCKSProbe{Addr: socks, URL: "http://" + host + path}).Check(bg); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
	for _, h := range asked() {
		if h != host {
			t.Errorf("SOCKS server was asked for %q, want %q", h, host)
		}
	}
	for path, want := range map[string]string{"/blocked": "503", "/moved": "302", "/nowhere": "404"} {
		err := (SOCKSProbe{Addr: socks, URL: "http://" + host + path}).Check(bg)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want HTTP %s", path, err, want)
		}
	}

	start := time.Now()
	err := (SOCKSProbe{Addr: socks, URL: "http://" + host + "/slow", Timeout: 100 * time.Millisecond}).Check(bg)
	if err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("slow origin: err = %v after %s, want a timeout after 100ms", err, time.Since(start))
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()
	if err := (SOCKSProbe{Addr: dead, URL: "http://" + host + "/ok"}).Check(bg); err == nil {
		t.Error("a probe through a dead SOCKS port passed")
	}
}

func TestXrayAPIProbe(t *testing.T) {
	f := newFakeRunner(t, t.TempDir(), &runnerapi.Selection{Core: "26.10.21", Config: "config/" + strings.Repeat("ab", 32) + ".json"})
	var got [][]string
	answer := runnerapi.XrayAPIResponse{}
	f.script(func(f *fakeRunner) {
		f.onXrayAPI = func(w http.ResponseWriter, args []string) {
			got = append(got, args)
			writeJSONReply(w, http.StatusOK, answer)
		}
	})

	if err := (XrayAPIProbe{Runner: f.client()}).Check(bg); err != nil {
		t.Fatal(err)
	}
	if err := (XrayAPIProbe{Runner: f.client(), Server: "127.0.0.1:9999"}).Check(bg); err != nil {
		t.Fatal(err)
	}
	f.script(func(*fakeRunner) {
		want := [][]string{{"statssys", "--server=127.0.0.1:10085"}, {"statssys", "--server=127.0.0.1:9999"}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("xray api args = %q, want %q", got, want)
		}
		answer = runnerapi.XrayAPIResponse{ExitCode: 1, Stderr: "failed to dial: connection refused\n"}
	})
	err := (XrayAPIProbe{Runner: f.client()}).Check(bg)
	if err == nil || !strings.Contains(err.Error(), "connection refused") || !strings.Contains(err.Error(), "exit status 1") {
		t.Errorf("err = %v, want the exit code and stderr", err)
	}

	f.script(func(f *fakeRunner) {
		f.onXrayAPI = func(w http.ResponseWriter, args []string) {
			fakeError(w, http.StatusServiceUnavailable, "no_xray", "no xray is running")
		}
	})
	if err := (XrayAPIProbe{Runner: f.client()}).Check(bg); err == nil || !strings.Contains(err.Error(), "no xray") {
		t.Errorf("err = %v, want the runner's refusal", err)
	}

	// The runner gives xray api 10 s, as long as the client's default
	// timeout, so the probe must wait longer than its client would.
	f.script(func(f *fakeRunner) {
		f.delay["xray-api"] = 300 * time.Millisecond
		f.onXrayAPI = nil
	})
	hc := &http.Client{Timeout: 100 * time.Millisecond, Transport: f.srv.Client().Transport}
	c := f.client()
	c.HTTP = hc
	if err := (XrayAPIProbe{Runner: c}).Check(bg); err != nil {
		t.Errorf("slow xray api: %v", err)
	}
	if c.HTTP != hc || hc.Timeout != 100*time.Millisecond {
		t.Errorf("the caller's client was changed: %+v", c.HTTP)
	}

	if err := (XrayAPIProbe{}).Check(bg); err == nil {
		t.Error("a probe without a runner passed")
	}
}

func TestAllOf(t *testing.T) {
	var ran []string
	pass := func(name string) HealthChecker {
		return healthFunc(func(context.Context) error { ran = append(ran, name); return nil })
	}
	boom := errors.New("boom")
	fail := healthFunc(func(context.Context) error { ran = append(ran, "fail"); return boom })

	if err := AllOf(pass("a"), pass("b")).Check(bg); err != nil || !reflect.DeepEqual(ran, []string{"a", "b"}) {
		t.Errorf("AllOf(a, b) = %v, ran %v", err, ran)
	}
	ran = nil
	if err := AllOf(pass("a"), fail, pass("c")).Check(bg); !errors.Is(err, boom) || !reflect.DeepEqual(ran, []string{"a", "fail"}) {
		t.Errorf("AllOf(a, fail, c) = %v, ran %v; want the failure and c skipped", err, ran)
	}
	if err := AllOf().Check(bg); err != nil {
		t.Errorf("AllOf() = %v", err)
	}
}
