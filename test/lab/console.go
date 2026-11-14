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

// The serial peer can echo a login reply, including across separate reads.
// Keep its bytes in memory for prompt matching. Only local lifecycle events
// belong in the diagnostic file.
type console struct {
	conn net.Conn
	log  *os.File

	mu        sync.Mutex
	pending   bytes.Buffer
	truncated bool
	last      time.Time
	changed   chan struct{}
	closed    chan struct{}
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
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		conn.Close()
		return nil, err
	}
	c := &console{conn: conn, log: f, last: time.Now(), changed: make(chan struct{}, 1), closed: make(chan struct{})}
	fmt.Fprintln(c.log, "serial connection opened")
	go c.read()
	return c, nil
}

func (c *console) read() {
	defer close(c.closed)
	b := make([]byte, 4096)
	for {
		n, err := c.conn.Read(b)
		if n > 0 {
			c.mu.Lock()
			if excess := c.pending.Len() + n - (64 << 10); excess > 0 {
				c.pending.Next(excess)
				c.truncated = true
			}
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

func (c *console) send(s string) error {
	c.mu.Lock()
	c.pending.Reset()
	c.truncated = false
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
			return -1, fmt.Errorf("console: waiting for a prompt: %w", ctx.Err())
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
			fmt.Fprintln(c.log, "login completed")
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
	truncated := c.truncated
	c.mu.Unlock()
	if truncated {
		return fmt.Errorf("console: command response exceeded limit")
	}
	for _, l := range strings.Split(out, "\n") {
		if class := rosError.FindString(l); class != "" {
			if strings.Contains(l, "input does not match any value of interface") {
				class = "input does not match any value of interface"
			}
			fmt.Fprintln(c.log, "command rejected")
			return fmt.Errorf("RouterOS: %s", class)
		}
	}
	fmt.Fprintln(c.log, "command completed")
	return nil
}

func (c *console) close() {
	c.conn.Close()
	<-c.closed
	c.log.Close()
}
