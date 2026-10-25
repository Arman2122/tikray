package lab

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const chrSSH = "198.51.100.2:22"

// rosError matches the ways RouterOS reports a failed command on stdout; SSH
// exec itself exits 0 either way.
var rosError = regexp.MustCompile(`failure:|syntax error|expected end of command|expected command name|bad command name|input does not match any value|no such item|invalid value|ambiguous value|missing value|Script Error`)

func (c *CHR) dial(ctx context.Context) (*ssh.Client, error) {
	d := net.Dialer{Timeout: c.ssh.Timeout}
	conn, err := d.DialContext(ctx, "tcp", chrSSH)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, chrSSH, c.ssh)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return ssh.NewClient(sc, chans, reqs), nil
}

// session opens a session on the shared SSH connection, reconnecting once if
// it has gone away. One connection for all commands matters: RouterOS
// rejects logins when they arrive in quick bursts.
func (c *CHR) session(ctx context.Context) (*ssh.Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		if s, err := newSession(ctx, c.client); err == nil {
			return s, nil
		}
		c.client.Close()
		c.client = nil
	}
	cl, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	s, err := newSession(ctx, cl)
	if err != nil {
		cl.Close()
		return nil, err
	}
	c.client = cl
	return s, nil
}

// newSession is cl.NewSession bounded by ctx (and at most 30 s): on a
// connection that died without a reset it would otherwise block forever.
func newSession(ctx context.Context, cl *ssh.Client) (*ssh.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	type res struct {
		s   *ssh.Session
		err error
	}
	ch := make(chan res, 1)
	go func() {
		s, err := cl.NewSession()
		ch <- res{s, err}
	}()
	select {
	case r := <-ch:
		return r.s, r.err
	case <-ctx.Done():
		cl.Close()
		return nil, fmt.Errorf("open SSH session: %w", ctx.Err())
	}
}

// dropClient closes the shared SSH connection, e.g. when the VM restarts.
func (c *CHR) dropClient() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		c.client.Close()
		c.client = nil
	}
}

// Run executes one RouterOS command over SSH and returns its output. Output
// that RouterOS uses to report a failure is returned as an error.
func (c *CHR) Run(ctx context.Context, cmd string) (out string, err error) {
	start := time.Now()
	defer func() {
		if err != nil {
			c.logf("run %q: %v (%.1fs)", cmd, err, time.Since(start).Seconds())
		}
	}()
	s, err := c.session(ctx)
	if err != nil {
		return "", err
	}
	defer s.Close()
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := s.CombinedOutput(cmd)
		done <- result{out, err}
	}()
	select {
	case <-ctx.Done():
		return "", fmt.Errorf("%s: %w", cmd, ctx.Err())
	case r := <-done:
		out := strings.ReplaceAll(string(r.out), "\r", "")
		if r.err != nil {
			return out, fmt.Errorf("%s: %w: %s", cmd, r.err, out)
		}
		if rosError.MatchString(out) {
			return out, fmt.Errorf("%s: %s", cmd, strings.TrimSpace(out))
		}
		return out, nil
	}
}

// Get evaluates a RouterOS expression with :put and returns it trimmed.
func (c *CHR) Get(ctx context.Context, expr string) (string, error) {
	out, err := c.Run(ctx, ":put ["+expr+"]")
	return strings.TrimSpace(out), err
}

// waitSSH waits up to one boot timeout for SSH to answer a command.
func (c *CHR) waitSSH(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.bootTimeout())
	defer cancel()
	var last error
	for {
		actx, acancel := context.WithTimeout(ctx, 30*time.Second)
		out, err := c.Run(actx, `:put "up"`)
		acancel()
		if err == nil && strings.TrimSpace(out) == "up" {
			c.logf("ssh up")
			return nil
		}
		c.logf("ssh not up: %v", err)
		last = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("CHR SSH did not come up: %v", last)
		case <-c.exited:
			return fmt.Errorf("QEMU exited while waiting for SSH (see %s)", filepath.Join(c.opts.WorkDir, "qemu.log"))
		case <-time.After(3 * time.Second):
		}
	}
}

// waitSSHDown waits for the SSH port to stop answering, so a reboot can't be
// mistaken for the system still being up.
func (c *CHR) waitSSHDown(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	for {
		conn, err := net.DialTimeout("tcp", chrSSH, 2*time.Second)
		if err != nil {
			return nil
		}
		conn.Close()
		select {
		case <-ctx.Done():
			return fmt.Errorf("CHR SSH still up: %w", ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

// Push copies a local file to dstPath on the router: the host serves it over
// HTTP on the WAN bridge and RouterOS fetches it.
func (c *CHR) Push(ctx context.Context, localPath, dstPath string) error {
	st, err := os.Stat(localPath)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "198.51.100.1:0")
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, localPath)
	})}
	go srv.Serve(ln)
	defer srv.Close()

	url := "http://" + ln.Addr().String() + "/" + filepath.Base(localPath)
	want := strconv.FormatInt(st.Size(), 10)
	// Right after a boot, a fetch that reported no failure once left no file
	// behind (M2a lab, 7.25 x86_64, the first push after SSH came up). Such a
	// fetch is tried once more, after a short wait in case the file only shows
	// up late.
	var size, out string
	for attempt := 1; ; attempt++ {
		if out, err = c.Run(ctx, fmt.Sprintf(`/tool/fetch url="%s" dst-path="%s"`, url, dstPath)); err != nil {
			return err
		}
		for range 5 {
			if size, err = c.Get(ctx, fmt.Sprintf(`/file/get [find name="%s"] size`, dstPath)); err == nil {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
		}
		if err == nil || attempt == 2 {
			break
		}
		c.logf("push %s: no file at %s after the fetch, which said %q; fetching again", localPath, dstPath, strings.TrimSpace(out))
	}
	if err != nil {
		return fmt.Errorf("push %s: %w (the fetch said %q)", localPath, err, strings.TrimSpace(out))
	}
	if size != want {
		return fmt.Errorf("push %s: router has %s bytes at %s, want %s", localPath, size, dstPath, want)
	}
	return nil
}

// Import runs a RouterOS script file on the router.
func (c *CHR) Import(ctx context.Context, rscPath string) error {
	const tmp = "tikray-tmp.rsc"
	if err := c.Push(ctx, rscPath, tmp); err != nil {
		return err
	}
	defer c.Run(context.Background(), "/file/remove "+tmp)
	if _, err := c.Run(ctx, "/import "+tmp+" verbose=yes"); err != nil {
		return fmt.Errorf("import %s: %w", rscPath, err)
	}
	return nil
}
