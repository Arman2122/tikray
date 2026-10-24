package lab

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// prompt is one step of the serial-console login: when the console output
// since the last reply ends with re, send reply. A prompt marked done ends
// the login.
type prompt struct {
	re    *regexp.Regexp
	reply string
	done  bool
}

// loginPrompts is the first-boot login sequence. Order matters: a later
// entry must not match text an earlier one is meant to catch.
func loginPrompts(password string) []prompt {
	return []prompt{
		{re: regexp.MustCompile(`repeat new password> $`), reply: password + "\r"},
		{re: regexp.MustCompile(`new password> $`), reply: password + "\r"},
		// A bare "n": a trailing CR would land on the next prompt.
		{re: regexp.MustCompile(`software license\? \[Y/n\]: ?$`), reply: "n"},
		{re: regexp.MustCompile(`Login: $`), reply: "admin+ct\r"},
		{re: regexp.MustCompile(`Password: $`), reply: "\r"},
		{re: regexp.MustCompile(`\] > $`), done: true},
	}
}

var shellPrompt = regexp.MustCompile(`\] > $`)

// console owns the single connection QEMU allows to the serial socket. It
// copies everything to a log file and keeps the output since the last reset
// for expect.
type console struct {
	conn net.Conn
	log  *os.File
	tl   *os.File // console lines with timestamps
	line []byte

	mu      sync.Mutex
	pending bytes.Buffer
	last    time.Time
	changed chan struct{}
	closed  chan struct{}
}

func openConsole(ctx context.Context, sock, logPath string) (*console, error) {
	var conn net.Conn
	var err error
	for {
		conn, err = net.Dial("unix", sock)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("console %s: %w", sock, err)
		case <-time.After(200 * time.Millisecond):
		}
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		conn.Close()
		return nil, err
	}
	tl, err := os.OpenFile(logPath+".timeline", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		conn.Close()
		f.Close()
		return nil, err
	}
	c := &console{conn: conn, log: f, tl: tl, last: time.Now(), changed: make(chan struct{}, 1), closed: make(chan struct{})}
	go c.read()
	return c, nil
}

func (c *console) read() {
	defer close(c.closed)
	b := make([]byte, 4096)
	for {
		n, err := c.conn.Read(b)
		if n > 0 {
			c.log.Write(b[:n])
			c.timeline(b[:n])
			c.mu.Lock()
			c.pending.Write(b[:n])
			c.last = time.Now()
			c.mu.Unlock()
			select {
			case c.changed <- struct{}{}:
			default:
			}
		}
		if err != nil {
			return
		}
	}
}

func (c *console) timeline(b []byte) {
	for _, ch := range b {
		if ch != '\n' && ch != '\r' {
			c.line = append(c.line, ch)
			continue
		}
		if len(bytes.TrimSpace(c.line)) > 0 {
			fmt.Fprintf(c.tl, "%s %q\n", time.Now().Format("15:04:05.000"), c.line)
		}
		c.line = c.line[:0]
	}
}

func (c *console) send(s string) error {
	c.mu.Lock()
	c.pending.Reset()
	c.mu.Unlock()
	_, err := c.conn.Write([]byte(s))
	return err
}

// expect waits until the pending output ends with one of res and returns its
// index. After kick of silence with no match it sends a CR, in case the
// prompt was printed before we connected.
func (c *console) expect(ctx context.Context, kick time.Duration, res ...*regexp.Regexp) (int, error) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		c.mu.Lock()
		out := c.pending.Bytes()
		for i, re := range res {
			if re.Match(out) {
				c.mu.Unlock()
				return i, nil
			}
		}
		silent := time.Since(c.last)
		c.mu.Unlock()
		if silent > kick {
			c.mu.Lock()
			c.last = time.Now()
			c.mu.Unlock()
			c.conn.Write([]byte("\r"))
		}
		select {
		case <-ctx.Done():
			c.mu.Lock()
			tail := c.pending.String()
			c.mu.Unlock()
			if len(tail) > 300 {
				tail = tail[len(tail)-300:]
			}
			return -1, fmt.Errorf("console: %w; last output %q", ctx.Err(), tail)
		case <-c.closed:
			return -1, fmt.Errorf("console closed")
		case <-c.changed:
		case <-tick.C:
		}
	}
}

// login walks loginPrompts until the shell prompt appears.
func (c *console) login(ctx context.Context, password string) error {
	ps := loginPrompts(password)
	res := make([]*regexp.Regexp, len(ps))
	for i, p := range ps {
		res[i] = p.re
	}
	for {
		i, err := c.expect(ctx, 30*time.Second, res...)
		if err != nil {
			return err
		}
		if ps[i].done {
			return nil
		}
		if err := c.send(ps[i].reply); err != nil {
			return err
		}
	}
}

// command sends one line at the shell prompt, waits for the next prompt and
// fails if RouterOS printed an error.
func (c *console) command(ctx context.Context, line string) error {
	if err := c.send(line + "\r"); err != nil {
		return err
	}
	if _, err := c.expect(ctx, time.Minute, shellPrompt); err != nil {
		return err
	}
	c.mu.Lock()
	out := c.pending.String()
	c.mu.Unlock()
	for _, l := range strings.Split(out, "\n") {
		if rosError.MatchString(l) {
			return fmt.Errorf("RouterOS: %s", strings.TrimSpace(l))
		}
	}
	return nil
}

func (c *console) close() {
	c.conn.Close()
	<-c.closed
	c.log.Close()
	c.tl.Close()
}
