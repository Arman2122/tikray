package labinet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/net/quic"
)

// StartQUICWitness publishes the public leaf only after the endpoint is
// listening. Clients dial a numeric IP and independently select the TLS SNI.
func StartQUICWitness(address, publicCert string) (*quic.Endpoint, error) {
	cert, err := SelfSignedCert("domestic.test", "foreign.test")
	if err != nil {
		return nil, err
	}
	server, err := quic.Listen("udp4", address, &quic.Config{TLSConfig: &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert}, NextProtos: []string{"tikray-route-test"},
	}})
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(publicCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		server.Close(context.Background())
		return nil, err
	}
	return server, nil
}

// ServeQUICWitness replies inside the established QUIC connection. The
// ClientHello, source and destination are observations made by the receiver.
func ServeQUICWitness(ctx context.Context, server *quic.Endpoint) error {
	for {
		conn, err := server.Accept(ctx)
		if err != nil {
			return err
		}
		go func() {
			probe, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			stream, err := conn.AcceptStream(probe)
			if err != nil {
				return
			}
			stream.SetReadContext(probe)
			stream.SetWriteContext(probe)
			var question [1]byte
			if _, err = io.ReadFull(stream, question[:]); err != nil || question[0] != '?' {
				return
			}
			sni := conn.ConnectionState().ServerName
			if sni != "domestic.test" && sni != "foreign.test" {
				return
			}
			_, err = fmt.Fprintf(stream, "%s %s %s", conn.RemoteAddr().Addr().Unmap(), conn.LocalAddr().Addr().Unmap(), sni)
			if err == nil {
				stream.CloseWrite()
			}
		}()
	}
}

func ProbeQUIC(ctx context.Context, source, target, sni, publicCert string) (string, string, string, error) {
	b, err := os.ReadFile(publicCert)
	if err != nil {
		return "", "", "", err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(b) {
		return "", "", "", errors.New("labinet: QUIC witness certificate unreadable")
	}
	client, err := quic.Listen("udp4", source, nil)
	if err != nil {
		return "", "", "", err
	}
	defer client.Close(ctx)
	conn, err := client.Dial(ctx, "udp4", target, &quic.Config{TLSConfig: &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots, ServerName: sni, NextProtos: []string{"tikray-route-test"},
		// Fit a complete ClientHello, including SNI, in the first datagram.
		CurvePreferences: []tls.CurveID{tls.X25519},
	}})
	if err != nil {
		return "", "", "", err
	}
	defer conn.Abort(nil)
	stream, err := conn.NewStream(ctx)
	if err != nil {
		return "", "", "", err
	}
	stream.SetReadContext(ctx)
	stream.SetWriteContext(ctx)
	if _, err = stream.Write([]byte("?")); err != nil {
		return "", "", "", err
	}
	stream.CloseWrite()
	reply, err := io.ReadAll(io.LimitReader(stream, 128))
	if err != nil {
		return "", "", "", err
	}
	fields := strings.Fields(string(reply))
	if len(fields) != 3 {
		return "", "", "", errors.New("labinet: invalid QUIC witness")
	}
	return fields[0], fields[1], fields[2], nil
}
