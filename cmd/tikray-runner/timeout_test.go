package main

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRunnerSlowBodyTimesOutButTrialCompletes(t *testing.T) {
	server := controlServer("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, e := io.ReadAll(r.Body); e != nil {
			w.WriteHeader(408)
			return
		}
		time.Sleep(140 * time.Millisecond)
		w.WriteHeader(204)
	}))
	if server.ReadTimeout != 30*time.Second || server.WriteTimeout != 0 {
		t.Fatal("runner deadline policy")
	}
	server.ReadTimeout = 70 * time.Millisecond
	ln, e := net.Listen("tcp", server.Addr)
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	go server.Serve(ln)
	slow, e := net.Dial("tcp", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer slow.Close()
	slow.SetDeadline(time.Now().Add(time.Second))
	if _, e = io.WriteString(slow, "POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 8\r\n\r\np"); e != nil {
		t.Fatal(e)
	}
	var b [100]byte
	n, e := slow.Read(b[:])
	if e != nil || !strings.Contains(string(b[:n]), "408") {
		t.Fatal("slow body not bounded")
	}
	resp, e := http.Post("http://"+ln.Addr().String(), "application/json", strings.NewReader("{}"))
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatal("long trial response timed out")
	}
}
