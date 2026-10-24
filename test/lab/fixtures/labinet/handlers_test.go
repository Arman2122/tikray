package labinet

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSAnswer(t *testing.T) {
	proxy := netip.MustParseAddr("203.0.113.10")
	direct := netip.MustParseAddr("198.51.100.2")
	cases := []struct {
		qname  string
		src    netip.Addr
		want   string
		wantOK bool
	}{
		{"foreign.test.", proxy, "203.0.113.30", true},
		{"foreign.test.", direct, "10.10.34.34", true},
		{"domestic.test.", direct, "10.10.34.34", true},
		{"domestic.test.", proxy, "203.0.113.30", true},
		{"example.com.", proxy, "", false},
	}
	for _, c := range cases {
		got, ok := DNSAnswer(c.qname, c.src)
		if ok != c.wantOK || (ok && got.String() != c.want) {
			t.Errorf("DNSAnswer(%q, %s) = %s, %v; want %s, %v", c.qname, c.src, got, ok, c.want, c.wantOK)
		}
	}
}

func TestWhoami(t *testing.T) {
	r := httptest.NewRequest("GET", "/whoami", nil)
	r.RemoteAddr = "203.0.113.10:5555"
	w := httptest.NewRecorder()
	HTTPHandler().ServeHTTP(w, r)
	if body := w.Body.String(); body != "203.0.113.10" {
		t.Errorf("whoami body %q, want 203.0.113.10", body)
	}
}

func TestBlob(t *testing.T) {
	r := httptest.NewRequest("GET", "/blob10m", nil)
	w := httptest.NewRecorder()
	HTTPHandler().ServeHTTP(w, r)
	b := w.Body.Bytes()
	if len(b) != 10*1024*1024 {
		t.Fatalf("blob length %d, want %d", len(b), 10*1024*1024)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != BlobSHA256() {
		t.Errorf("blob sha256 %s, BlobSHA256() %s", got, BlobSHA256())
	}
}

func TestUDPEcho(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go ServeUDPEcho(pc)

	c, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte("ping"))
	b := make([]byte, 64)
	n, err := c.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b[:n]); got != "127.0.0.1" {
		t.Errorf("echo reply %q, want 127.0.0.1", got)
	}
}

func TestDNSServer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: DNSHandler()}
	go srv.ActivateAndServe()
	defer srv.Shutdown()

	m := new(dns.Msg)
	m.SetQuestion("foreign.test.", dns.TypeA)
	in, err := dns.Exchange(m, pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Answer) != 1 {
		t.Fatalf("answers %v, want 1", in.Answer)
	}
	if a := in.Answer[0].(*dns.A).A.String(); a != "10.10.34.34" {
		t.Errorf("answer %s from 127.0.0.1, want 10.10.34.34", a)
	}

	m.SetQuestion("example.com.", dns.TypeA)
	in, err = dns.Exchange(m, pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if in.Rcode != dns.RcodeNameError {
		t.Errorf("example.com rcode %s, want NXDOMAIN", dns.RcodeToString[in.Rcode])
	}
}
