package xray

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

// A minimal gRPC client: unary calls over HTTP/2 without TLS (h2c, which is
// how xray's API listens), uncompressed, and nothing else. The protocol is
// https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md.

const (
	defaultTimeout = 5 * time.Second
	// maxMessage bounds a message from xray; QueryStats with an empty
	// pattern, which names every counter, is the largest answer.
	maxMessage = 16 << 20
)

// h2cTransport carries every call. It keeps one connection per address, so
// the health monitor's polling does not open one each time. http2 dials
// through DialTLSContext, even for the http scheme that AllowHTTP permits;
// ours dials plain TCP.
var h2cTransport = &http2.Transport{
	AllowHTTP: true,
	DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	},
	IdleConnTimeout: time.Minute,
}

// StatusError is a call that xray answered with a grpc-status other than 0.
type StatusError struct {
	Code    int // a gRPC status code, such as 14 for UNAVAILABLE
	Message string
}

// codeNames are the gRPC status codes' names, by code.
var codeNames = [...]string{
	"OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED", "NOT_FOUND",
	"ALREADY_EXISTS", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION",
	"ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED", "INTERNAL", "UNAVAILABLE", "DATA_LOSS",
	"UNAUTHENTICATED",
}

func (e *StatusError) Error() string {
	s := "xray: grpc status " + strconv.Itoa(e.Code)
	if e.Code >= 0 && e.Code < len(codeNames) {
		s += " (" + codeNames[e.Code] + ")"
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	return s
}

// timeout is how long a call may take: Timeout, or 5 s when that is zero.
func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return defaultTimeout
}

// call makes one unary call of "<service>/<method>" with the protobuf message
// req, and returns the message that xray answers with. It gives up at ctx's
// deadline or after c's timeout, whichever comes first. A grpc-status other
// than 0 is a *StatusError; the other errors are about the transport or the
// framing.
func (c *Client) call(ctx context.Context, method string, req []byte) ([]byte, error) {
	name := method[strings.LastIndexByte(method, '/')+1:]
	fail := func(format string, args ...any) ([]byte, error) {
		return nil, fmt.Errorf("xray: "+name+": "+format, args...)
	}
	if c.Addr == "" {
		return fail("no address to call")
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	body := make([]byte, 5, 5+len(req))
	binary.BigEndian.PutUint32(body[1:], uint32(len(req))) // body[0], the flag, is 0: not compressed
	body = append(body, req...)
	u := url.URL{Scheme: "http", Host: c.Addr, Path: "/" + method}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return fail("%w", err)
	}
	r.Header.Set("Content-Type", "application/grpc")
	r.Header.Set("Te", "trailers")
	resp, err := h2cTransport.RoundTrip(r)
	if err != nil {
		return fail("%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fail("HTTP status %s", resp.Status)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/grpc") {
		return fail("answer has content type %q, not gRPC", ct)
	}

	msg, err := readMessage(resp.Body)
	if err != nil {
		return fail("%w", err)
	}
	// The trailers arrive after the body. A server that has nothing to send
	// (an error, mostly) answers with the status in the headers instead.
	status, text := resp.Trailer.Get("Grpc-Status"), resp.Trailer.Get("Grpc-Message")
	if status == "" {
		status, text = resp.Header.Get("Grpc-Status"), resp.Header.Get("Grpc-Message")
	}
	if status == "" {
		return fail("answer has no grpc-status")
	}
	code, err := strconv.Atoi(status)
	if err != nil {
		return fail("grpc-status %q is not a number", status)
	}
	if code != 0 {
		return nil, &StatusError{Code: code, Message: unescapeMessage(text)}
	}
	if msg == nil {
		return fail("status OK but no message")
	}
	return msg, nil
}

// readMessage reads the one length-prefixed message of a unary answer, and
// the end of the body after it. It returns nil, and no error, for a body with
// no message in it. The message of zero length is a non-nil empty slice.
func readMessage(body io.Reader) ([]byte, error) {
	var prefix [5]byte
	if _, err := io.ReadFull(body, prefix[:]); err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, fmt.Errorf("reading the answer: %w", err)
	}
	if prefix[0] != 0 {
		return nil, errors.New("message is compressed, which this client does not accept")
	}
	size := binary.BigEndian.Uint32(prefix[1:])
	if size > maxMessage {
		return nil, fmt.Errorf("message of %d bytes is too large", size)
	}
	msg, err := io.ReadAll(io.LimitReader(body, int64(size)))
	if err != nil {
		return nil, fmt.Errorf("reading the answer: %w", err)
	}
	if len(msg) < int(size) {
		return nil, fmt.Errorf("length prefix says %d bytes, the body has %d", size, len(msg))
	}
	// A unary answer has no more messages. Reading to the end of the body is
	// also what makes the trailers available.
	if n, err := io.Copy(io.Discard, io.LimitReader(body, maxMessage)); err != nil {
		return nil, fmt.Errorf("reading the answer: %w", err)
	} else if n > 0 {
		return nil, errors.New("more than one message in the answer")
	}
	if msg == nil {
		msg = []byte{}
	}
	return msg, nil
}

// unescapeMessage decodes a grpc-message, which percent-encodes the bytes
// outside printable ASCII, and the percent sign. Text that does not decode is
// returned as it is.
func unescapeMessage(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}
