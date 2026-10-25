// Command labinet runs the lab's fake-internet services (see package
// labinet) inside the tklab-inet network namespace.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/Arman2122/tikray/test/lab/fixtures/labinet"
	"github.com/miekg/dns"
)

func main() {
	httpAddrs := flag.String("http", "203.0.113.20:80,203.0.113.30:80", "HTTP listen addresses")
	httpsAddrs := flag.String("https", "203.0.113.20:443,203.0.113.30:443", "HTTPS listen addresses")
	echoAddr := flag.String("udp-echo", "203.0.113.30:9000", "UDP echo listen address")
	dnsAddrs := flag.String("dns", "203.0.113.53:53,203.0.113.54:53", "DNS listen addresses (UDP and TCP)")
	flag.Parse()

	cert, err := labinet.SelfSignedCert("domestic.test", "foreign.test")
	if err != nil {
		log.Fatal(err)
	}
	h := labinet.HTTPHandler()
	errs := make(chan error)
	for _, a := range strings.Split(*httpAddrs, ",") {
		go func() { errs <- http.ListenAndServe(a, h) }()
	}
	for _, a := range strings.Split(*httpsAddrs, ",") {
		srv := &http.Server{Addr: a, Handler: h, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
		go func() { errs <- srv.ListenAndServeTLS("", "") }()
	}
	pc, err := net.ListenPacket("udp", *echoAddr)
	if err != nil {
		log.Fatal(err)
	}
	go func() { errs <- labinet.ServeUDPEcho(pc) }()
	for _, a := range strings.Split(*dnsAddrs, ",") {
		for _, netw := range []string{"udp", "tcp"} {
			srv := &dns.Server{Addr: a, Net: netw, Handler: labinet.DNSHandler()}
			go func() { errs <- srv.ListenAndServe() }()
		}
	}
	log.Print("labinet: serving")
	log.Fatal(<-errs)
}
