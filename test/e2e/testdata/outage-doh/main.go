// The outage test uses xray's real HTTP/2 DNS resolver in the fake WAN.
package main

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func main() {
	if len(os.Args) != 8 {
		os.Exit(2)
	}
	address, cert, key, witness, wan := os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5]
	proxies := os.Args[6:]
	out, err := os.OpenFile(witness, os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		os.Exit(1)
	}
	defer out.Close()
	listener, err := net.Listen("tcp4", net.JoinHostPort(address, "443"))
	if err != nil {
		os.Exit(1)
	}
	server := &http.Server{
		ReadHeaderTimeout: 4 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/dns-query" || r.ProtoMajor != 2 {
				http.NotFound(w, r)
				return
			}
			source, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			marker, last := byte('P'), byte(2)
			switch {
			case source == wan:
				marker, last = 'D', 1
			case slices.Contains(proxies, source):
			default:
				w.WriteHeader(http.StatusForbidden)
				return
			}
			var wire []byte
			switch r.Method {
			case http.MethodPost:
				wire, err = io.ReadAll(io.LimitReader(r.Body, 513))
			case http.MethodGet:
				wire, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			msg := new(dns.Msg)
			if err != nil || len(wire) > 512 || msg.Unpack(wire) != nil || len(msg.Question) != 1 ||
				!strings.HasSuffix(strings.ToLower(msg.Question[0].Name), ".foreign.routing-probe.test.") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			reply := new(dns.Msg)
			reply.SetReply(msg)
			if q := msg.Question[0]; q.Qtype == dns.TypeA && q.Qclass == dns.ClassINET {
				reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.IPv4(198, 18, 55, last)}}
				if _, err := out.Write([]byte{marker}); err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}
			data, err := reply.Pack()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(data)
		}),
	}
	if err := server.ServeTLS(listener, cert, key); err != nil {
		os.Exit(1)
	}
}
