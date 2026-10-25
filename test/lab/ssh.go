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
// HTTP on the WAN bridge and RouterOS fetches it (see fetchFile). When the
// fetch had to be retried, Push says so in harness.log and through
// BootOptions.Notef, so that a run that passes still shows it.
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
	retry, err := fetchFile(ctx, c.Run, c.Get, url, dstPath, st.Size(), time.Second)
	if retry != "" {
		c.logf("push %s: %s", localPath, retry)
		if c.opts.Notef != nil {
			c.opts.Notef("lab: push %s: %s", localPath, retry)
		}
	}
	if err != nil {
		return fmt.Errorf("push %s: %w", localPath, err)
	}
	return nil
}

// fetchReads is how many times fetchFile looks for the file after a fetch,
// a wait apart, before it counts the fetch as having left none.
const fetchReads = 5

// fetchFile has the router fetch url into dstPath (with run), then reads the
// size of the file there (with get) and checks that it is size.
//
// Once, right after a boot (M2a lab, CHR 7.25 x86_64, the first push after
// SSH came up), a fetch printed no failure and left no file. Why is not
// known: RouterOS may list the file late, or the fetch may not have written
// it. So fetchFile looks for the file fetchReads times, wait apart, and if it
// is still missing fetches once more, and never more than that. retry, when
// not empty, says what that took, for the caller to show even when the file
// came. When no fetch left a file, err says what each one printed.
func fetchFile(ctx context.Context, run, get func(context.Context, string) (string, error), url, dstPath string, size int64, wait time.Duration) (retry string, err error) {
	var said []string
	for fetch := 1; fetch <= 2; fetch++ {
		var out, got string
		if out, err = run(ctx, fmt.Sprintf(`/tool/fetch url="%s" dst-path="%s"`, url, dstPath)); err != nil {
			return retry, err
		}
		said = append(said, strings.TrimSpace(out))
		for read := 1; read <= fetchReads; read++ {
			if got, err = get(ctx, fmt.Sprintf(`/file/get [find name="%s"] size`, dstPath)); err == nil {
				if read > 1 {
					late := fmt.Sprintf("the file at %s showed up on read %d after fetch %d", dstPath, read, fetch)
					if retry != "" {
						late = retry + "; " + late
					}
					retry = late
				}
				break
			}
			if read < fetchReads {
				select {
				case <-ctx.Done():
					return retry, ctx.Err()
				case <-time.After(wait):
				}
			}
		}
		if err == nil {
			if want := strconv.FormatInt(size, 10); got != want {
				return retry, fmt.Errorf("router has %s bytes at %s, want %s", got, dstPath, want)
			}
			return retry, nil
		}
		if fetch == 1 {
			retry = fmt.Sprintf("no file at %s after the fetch, which said %q; fetched again", dstPath, said[0])
		}
	}
	return retry, fmt.Errorf("no file at %s after 2 fetches, which said %q and %q: %w", dstPath, said[0], said[1], err)
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
