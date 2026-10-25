// Package labinet is the lab's fake internet: target web servers that report
// the caller's IP, a UDP echo, a DNS server that answers differently
// depending on whether the query came through the VLESS proxy, and a
// stand-in for XTLS's GitHub releases with a mirror of them. The source IP a
// fixture sees tells a test which path a request took.
package labinet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	proxyEgress = netip.MustParseAddr("203.0.113.10")
	realAnswer  = netip.MustParseAddr("203.0.113.30")
	poisoned    = netip.MustParseAddr("10.10.34.34")
)

// DNSAnswer is the A record for qname as seen by a resolver at src: the real
// address when the query came through the proxy, the poisoned one an ISP
// resolver would give otherwise. ok is false for names the lab doesn't serve.
func DNSAnswer(qname string, src netip.Addr) (addr netip.Addr, ok bool) {
	switch qname {
	case "domestic.test.", "foreign.test.":
	default:
		return netip.Addr{}, false
	}
	if src == proxyEgress {
		return realAnswer, true
	}
	return poisoned, true
}

// blobSize keeps the transfer test short under CHR's ~1 Mbps free-license
// cap while still spanning well over a thousand full-size segments.
const blobSize = 2 * 1024 * 1024

// startTime is the Last-Modified time of /blob2m.
var startTime = time.Now()

var blob = sync.OnceValue(func() []byte {
	b := make([]byte, blobSize)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
})

// BlobSHA256 is the hex SHA-256 of the /blob2m body.
func BlobSHA256() string {
	sum := sha256.Sum256(blob())
	return hex.EncodeToString(sum[:])
}

func callerIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// HTTPHandler serves /whoami (the caller's IP) and /blob2m.
func HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(callerIP(r.RemoteAddr)))
	})
	mux.HandleFunc("/blob2m", func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "blob2m", startTime, bytes.NewReader(blob()))
	})
	return mux
}

// ServeUDPEcho answers every datagram with the sender's IP until pc closes.
func ServeUDPEcho(pc net.PacketConn) error {
	b := make([]byte, 2048)
	for {
		_, addr, err := pc.ReadFrom(b)
		if err != nil {
			return err
		}
		pc.WriteTo([]byte(callerIP(addr.String())), addr)
	}
}

// DNSHandler answers A queries with DNSAnswer for the querier's address.
func DNSHandler() dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		src, _ := netip.ParseAddr(callerIP(w.RemoteAddr().String()))
		if len(req.Question) == 1 {
			q := req.Question[0]
			addr, ok := DNSAnswer(q.Name, src.Unmap())
			switch {
			case !ok:
				m.Rcode = dns.RcodeNameError
			case q.Qtype == dns.TypeA:
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   addr.AsSlice(),
				})
			}
		}
		w.WriteMsg(m)
	})
}

// SelfSignedCert returns a throwaway certificate for names; lab clients
// connect with certificate checks off.
func SelfSignedCert(names ...string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
