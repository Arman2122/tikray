package xray

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// grpcServer starts an in-process h2c server running h, and returns a client
// that talks to it.
func grpcServer(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewUnstartedServer(h2c.NewHandler(h, &http2.Server{}))
	srv.Start()
	// Cleanups run last in, first out: the client's idle connections close
	// before the server does.
	t.Cleanup(srv.Close)
	t.Cleanup(h2cTransport.CloseIdleConnections)
	return &Client{Addr: srv.Listener.Addr().String(), Timeout: 10 * time.Second}
}

// frame is a gRPC message: a flag byte, the length, the bytes.
func frame(msg []byte) []byte {
	b := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(b[1:], uint32(len(msg)))
	return append(b, msg...)
}

// reply answers with msg and the grpc-status trailer status, the way a gRPC
// server does: the trailers are not announced in a Trailer header.
func reply(w http.ResponseWriter, msg []byte, status, message string) {
	w.Header().Set("Content-Type", "application/grpc")
	w.WriteHeader(http.StatusOK)
	w.Write(frame(msg))
	w.Header().Set(http.TrailerPrefix+"Grpc-Status", status)
	if message != "" {
		w.Header().Set(http.TrailerPrefix+"Grpc-Message", message)
	}
}

func TestCallFraming(t *testing.T) {
	var path, contentType, te, method string
	var body []byte
	c := grpcServer(t, func(w http.ResponseWriter, r *http.Request) {
		path, contentType, te, method = r.URL.Path, r.Header.Get("Content-Type"), r.Header.Get("Te"), r.Method
		body, _ = io.ReadAll(r.Body)
		if r.ProtoMajor != 2 {
			t.Errorf("request is HTTP/%d, want HTTP/2", r.ProtoMajor)
		}
		reply(w, []byte("pong"), "0", "")
	})
	got, err := c.call(t.Context(), "pkg.Svc/Method", []byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "pong" {
		t.Errorf("answer = %q, want pong", got)
	}
	if method != http.MethodPost || path != "/pkg.Svc/Method" {
		t.Errorf("request = %s %s, want POST /pkg.Svc/Method", method, path)
	}
	if contentType != "application/grpc" || te != "trailers" {
		t.Errorf("content-type %q, te %q; want application/grpc, trailers", contentType, te)
	}
	if want := "\x00\x00\x00\x00\x04ping"; string(body) != want {
		t.Errorf("body = %q, want %q", body, want)
	}
}

func TestCallEmptyMessage(t *testing.T) {
	var body []byte
	c := grpcServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		reply(w, nil, "0", "")
	})
	got, err := c.call(t.Context(), "pkg.Svc/Method", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("answer = %q, want empty", got)
	}
	if want := "\x00\x00\x00\x00\x00"; string(body) != want {
		t.Errorf("body = %q, want %q", body, want)
	}
}

// TestCallStatusFromTrailer: a message and then a grpc-status trailer other
// than 0 is a *StatusError. The message is percent-encoded on the wire.
func TestCallStatusFromTrailer(t *testing.T) {
	c := grpcServer(t, func(w http.ResponseWriter, r *http.Request) {
		reply(w, nil, "14", "connection%20refused%3A %25")
	})
	_, err := c.call(t.Context(), "pkg.Svc/Method", nil)
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v (%T), want a *StatusError", err, err)
	}
	if se.Code != 14 || se.Message != "connection refused: %" {
		t.Errorf("status = %d %q, want 14 %q", se.Code, se.Message, "connection refused: %")
	}
	if msg := se.Error(); !strings.HasPrefix(msg, "xray: ") || !strings.Contains(msg, "14") || !strings.Contains(msg, "UNAVAILABLE") || !strings.Contains(msg, "connection refused") {
		t.Errorf("Error() = %q, want the xray prefix, the code, its name and the message", msg)
	}
}

// TestCallTrailersOnly: an answer with the status in the headers, no body and
// no trailers, is how a gRPC server refuses a call.
func TestCallTrailersOnly(t *testing.T) {
	c := grpcServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Grpc-Status", "12")
		w.Header().Set("Grpc-Message", "unknown service")
		w.WriteHeader(http.StatusOK)
	})
	_, err := c.call(t.Context(), "pkg.Svc/Method", nil)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 12 || se.Message != "unknown service" {
		t.Fatalf("err = %v, want a *StatusError with code 12 and message %q", err, "unknown service")
	}
}

// TestCallBadAnswers: answers that are not a unary gRPC answer are errors,
// and not *StatusError.
func TestCallBadAnswers(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    http.HandlerFunc
		want string
	}{
		{"length prefix beyond the body", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte{0, 0, 0, 0, 100, 'a', 'b', 'c'})
			w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		}, "100"},
		{"truncated length prefix", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte{0, 0, 0})
			w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		}, "reading the answer"},
		{"length prefix over the limit", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte{0, 0xff, 0xff, 0xff, 0xff})
			w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		}, "too large"},
		{"compressed message", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte{1, 0, 0, 0, 1, 'a'})
			w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		}, "compress"},
		{"two messages", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc")
			w.WriteHeader(http.StatusOK)
			w.Write(frame([]byte("a")))
			w.Write(frame([]byte("b")))
			w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		}, "more than one"},
		{"no status", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc")
			w.WriteHeader(http.StatusOK)
			w.Write(frame([]byte("a")))
		}, "grpc-status"},
		{"status that is not a number", func(w http.ResponseWriter, r *http.Request) {
			reply(w, []byte("a"), "oops", "")
		}, "oops"},
		{"ok without a message", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Grpc-Status", "0")
			w.WriteHeader(http.StatusOK)
		}, "no message"},
		{"not grpc", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("hello"))
		}, "text/plain"},
		{"http error", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusBadGateway)
		}, "502"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := grpcServer(t, tc.h)
			_, err := c.call(t.Context(), "pkg.Svc/Method", nil)
			if err == nil {
				t.Fatal("call succeeded")
			}
			var se *StatusError
			if errors.As(err, &se) {
				t.Errorf("err = %v, want not a *StatusError", err)
			}
			if !strings.HasPrefix(err.Error(), "xray: ") || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want the xray prefix and %q", err, tc.want)
			}
		})
	}
}

// TestCallDeadline: a deadline cuts off a server that never answers, and one
// that stops after the headers, whether it comes from the context or from
// Client.Timeout.
func TestCallDeadline(t *testing.T) {
	stall := func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}
	stallAfterHeaders := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}
	for _, tc := range []struct {
		name    string
		h       http.HandlerFunc
		timeout time.Duration
		ctx     time.Duration
	}{
		{"context, no answer", stall, 0, 100 * time.Millisecond},
		{"timeout, no answer", stall, 100 * time.Millisecond, 0},
		{"context, headers only", stallAfterHeaders, 0, 100 * time.Millisecond},
		{"timeout, headers only", stallAfterHeaders, 100 * time.Millisecond, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := grpcServer(t, tc.h)
			c.Timeout = tc.timeout
			ctx := t.Context()
			if tc.ctx > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.ctx)
				defer cancel()
			}
			if tc.timeout == 0 {
				// A zero Timeout is the default, which is longer than the
				// context's deadline.
				if c.timeout() <= tc.ctx {
					t.Fatalf("default timeout %v is not longer than the test's %v", c.timeout(), tc.ctx)
				}
			}
			start := time.Now()
			_, err := c.call(ctx, "pkg.Svc/Method", nil)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("err = %v, want context.DeadlineExceeded", err)
			}
			if d := time.Since(start); d > 3*time.Second {
				t.Errorf("call took %v, want about 100ms", d)
			}
		})
	}
}

func TestCallCanceled(t *testing.T) {
	c := grpcServer(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(50*time.Millisecond, cancel)
	if _, err := c.call(ctx, "pkg.Svc/Method", nil); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestCallConnectionRefused(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	addr := srv.Listener.Addr().String()
	srv.Close()
	c := &Client{Addr: addr, Timeout: 2 * time.Second}
	_, err := c.call(t.Context(), "pkg.Svc/Method", nil)
	if err == nil || !strings.HasPrefix(err.Error(), "xray: Method: ") {
		t.Errorf("err = %v, want one with the xray prefix and the RPC name", err)
	}
	if _, err := (&Client{}).call(t.Context(), "pkg.Svc/Method", nil); err == nil || !strings.Contains(err.Error(), "address") {
		t.Errorf("a Client with no Addr gives %v, want an error about the address", err)
	}
}

func TestTimeoutDefault(t *testing.T) {
	if got := (&Client{}).timeout(); got != 5*time.Second {
		t.Errorf("default timeout = %v, want 5s", got)
	}
	if got := (&Client{Timeout: time.Second}).timeout(); got != time.Second {
		t.Errorf("timeout = %v, want 1s", got)
	}
}

func TestStatusErrorText(t *testing.T) {
	for _, tc := range []struct {
		err  StatusError
		want string
	}{
		{StatusError{Code: 12, Message: "unknown service"}, "xray: grpc status 12 (UNIMPLEMENTED): unknown service"},
		{StatusError{Code: 14}, "xray: grpc status 14 (UNAVAILABLE)"},
		{StatusError{Code: 99, Message: "x"}, "xray: grpc status 99: x"},
	} {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("%+v.Error() = %q, want %q", tc.err, got, tc.want)
		}
	}
}
