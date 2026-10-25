package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

// shutdownTimeout is how long a stopping server waits for the requests it is
// serving. It is a variable for the tests.
var shutdownTimeout = 10 * time.Second

// readTimeout is how long a caller has to send a request, its body included
// (1 MiB at most). It is a variable for the tests.
var readTimeout = 60 * time.Second

// newServer is the http.Server of the API.
//
// It has a ReadTimeout, which a long operation does not run into: net/http
// clears the read deadline when there is no body to read, and when the
// handler has read the body to its end. Without a ReadTimeout, a caller
// that declares a body and never sends it holds its connection for good,
// because net/http reads what is left of the body before it answers, a 401
// included, and by then no deadline is set.
//
// It has no WriteTimeout: a core update or an apply takes minutes, and the
// response comes when it is done.
func newServer(h http.Handler, cert tls.Certificate) *http.Server {
	return &http.Server{
		Handler: h,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       readTimeout,
		IdleTimeout:       60 * time.Second,
	}
}

// Serve serves h over TLS on addr, with cert (TLS 1.2 or newer), until ctx
// ends. It then stops accepting, waits up to 10 s for the requests it is
// serving, and returns nil; if they outlast that, it closes them and returns
// an error. It returns an error at once if addr can't be listened on.
func Serve(ctx context.Context, addr string, h http.Handler, cert tls.Certificate) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("api: %w", err)
	}
	return ServeListener(ctx, ln, h, cert)
}

// ServeListener is Serve on a listener that the caller has opened, so that it
// can learn the address of one made for port 0. It closes ln.
func ServeListener(ctx context.Context, ln net.Listener, h http.Handler, cert tls.Certificate) error {
	// ServeTLS closes ln once it serves, but not when it refuses to start.
	defer ln.Close()
	srv := newServer(h, cert)
	failed := make(chan error, 1)
	go func() { failed <- srv.ServeTLS(ln, "", "") }()

	select {
	case err := <-failed:
		// Shutdown has not been called, so this is no http.ErrServerClosed.
		return fmt.Errorf("api: serving: %w", err)
	case <-ctx.Done():
	}

	sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		srv.Close()
		<-failed
		return fmt.Errorf("api: shutting down (the requests still open were closed): %w", err)
	}
	<-failed
	return nil
}
