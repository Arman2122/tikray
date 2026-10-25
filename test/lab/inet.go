package lab

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// fixturePath resolves a file under test/lab/fixtures from any caller's
// working directory.
func fixturePath(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "fixtures", name)
}

// InetOptions tunes StartInetWith.
type InetOptions struct {
	// ReleasesDir is the root of the fake GitHub releases and the mirror:
	// <tag>/<file> files, LATEST, index/index.json[.sig], and the flag files
	// .down, .block-direct and .mirror-down (see labinet.ReleasesHandler).
	// The directory must exist, and the test may change its contents while
	// the services run. When set, labinet serves the fake GitHub on
	// 203.0.113.40:80 and the mirror on 203.0.113.41:80; when empty, it
	// serves neither.
	ReleasesDir string
}

// vlessServers are the lab's two VLESS servers. Each listens on its own address
// in tklab-inet and sends from it, so a target's idea of the caller tells which
// server a request went through. name is what Inet.SetServer takes.
var vlessServers = []vlessServer{
	{"a", "203.0.113.10:443", "xray-server.json"},
	{"b", "203.0.113.11:443", "xray-server-b.json"},
}

type vlessServer struct{ name, addr, config string }

func findServer(name string) (vlessServer, bool) {
	for _, s := range vlessServers {
		if s.name == name {
			return s, true
		}
	}
	return vlessServer{}, false
}

// Inet is the running fake-internet services: labinet and the two VLESS
// servers, all in tklab-inet. A test can take a VLESS server down and bring it
// back with SetServer.
type Inet struct {
	n    *Network
	dir  string // logs; removed by Stop
	xray string // the xray binary both VLESS servers run

	mu      sync.Mutex
	stopped bool
	labinet *exec.Cmd
	servers map[string]*exec.Cmd // the VLESS servers that are running, by name
}

// StartInet starts the fake-internet services in tklab-inet: labinet (web,
// UDP echo, DNS) and the two VLESS test servers. stop kills them all.
func StartInet(ctx context.Context, n *Network) (stop func(), err error) {
	return StartInetWith(ctx, n, InetOptions{})
}

// StartInetWith is StartInet with options.
func StartInetWith(ctx context.Context, n *Network, o InetOptions) (stop func(), err error) {
	i, err := StartInetLab(ctx, n, o)
	if err != nil {
		return nil, err
	}
	return i.Stop, nil
}

// StartInetLab is StartInetWith that returns a handle, so that a test can stop
// and start the VLESS servers. Both servers are up when it returns.
func StartInetLab(ctx context.Context, n *Network, o InetOptions) (*Inet, error) {
	var labinetArgs []string
	waitFor := []string{"203.0.113.30:80"}
	for _, s := range vlessServers {
		waitFor = append(waitFor, s.addr)
	}
	if o.ReleasesDir != "" {
		releases, err := filepath.Abs(o.ReleasesDir)
		if err != nil {
			return nil, err
		}
		if fi, err := os.Stat(releases); err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("releases dir %s is not a directory (%v)", releases, err)
		}
		labinetArgs = append(labinetArgs, "-releases", releases)
		waitFor = append(waitFor, "203.0.113.40:80", "203.0.113.41:80")
	}

	dir, err := os.MkdirTemp("", "labinet-")
	if err != nil {
		return nil, err
	}
	bin := filepath.Join(dir, "labinet")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "github.com/Arman2122/tikray/test/lab/fixtures/labinet/cmd/labinet")
	build.Dir = filepath.Dir(fixturePath(""))
	if b, err := build.CombinedOutput(); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("build labinet: %v: %s", err, b)
	}
	xray, err := XrayBinary(ctx, CacheDir(), runtime.GOARCH)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}

	i := &Inet{n: n, dir: dir, xray: xray, servers: map[string]*exec.Cmd{}}
	if i.labinet, err = i.spawn("labinet.log", append([]string{bin}, labinetArgs...)); err != nil {
		i.Stop()
		return nil, err
	}
	for _, s := range vlessServers {
		if err := i.startServer(s); err != nil {
			i.Stop()
			return nil, err
		}
	}
	for _, addr := range waitFor {
		if err := waitTCP(ctx, addr, 30*time.Second); err != nil {
			i.Stop()
			return nil, err
		}
	}
	return i, nil
}

// Stop kills everything StartInetLab started, including a VLESS server that
// SetServer restarted, and removes the logs. Calling it again does nothing.
func (i *Inet) Stop() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stopped {
		return
	}
	i.stopped = true
	if i.labinet != nil {
		reap(i.labinet)
	}
	for _, cmd := range i.servers {
		reap(cmd)
	}
	os.RemoveAll(i.dir)
}

// SetServer takes the VLESS server name ("a", 203.0.113.10, or "b",
// 203.0.113.11) down or brings it up. Down kills and reaps its process and
// returns once the port refuses connections. Up starts it again, with the same
// xray binary and config, and returns once the port accepts them. Either is
// harmless when the server is already in that state.
func (i *Inet) SetServer(name string, up bool) error {
	s, ok := findServer(name)
	if !ok {
		return fmt.Errorf("no VLESS server %q (want a or b)", name)
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stopped {
		return errors.New("fake internet is stopped")
	}

	ctx := context.Background()
	if !up {
		i.killServer(name)
		return waitRefused(ctx, s.addr, 30*time.Second)
	}
	if i.servers[name] == nil {
		if err := i.startServer(s); err != nil {
			return err
		}
	}
	if err := waitTCP(ctx, s.addr, 30*time.Second); err != nil {
		// Don't leave a server that never came up for the next call to trust.
		i.killServer(name)
		return err
	}
	return nil
}

// startServer starts the VLESS server s, which must not be running, and does
// not wait for its port. The caller holds i.mu, or is StartInetLab.
func (i *Inet) startServer(s vlessServer) error {
	cmd, err := i.spawn("xray-"+s.name+".log", []string{i.xray, "run", "-c", fixturePath(s.config)})
	if err != nil {
		return err
	}
	i.servers[s.name] = cmd
	return nil
}

// killServer kills the VLESS server name, if it runs, and waits for the
// process so that no zombie is left. The caller holds i.mu.
func (i *Inet) killServer(name string) {
	if cmd := i.servers[name]; cmd != nil {
		reap(cmd)
		delete(i.servers, name)
	}
}

// spawn starts argv in tklab-inet with its output appended to dir/log, so that
// a server that is started again keeps what it said before.
func (i *Inet) spawn(log string, argv []string) (*exec.Cmd, error) {
	logf, err := os.OpenFile(filepath.Join(i.dir, log), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	defer logf.Close() // the child has its own copy
	cmd := i.n.Inet(context.Background(), argv[0], argv[1:]...)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// reap kills cmd and waits for it.
func reap(cmd *exec.Cmd) {
	cmd.Process.Kill()
	cmd.Wait()
}

func waitTCP(ctx context.Context, addr string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("%s not listening: %v", addr, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// waitRefused waits up to d for connections to addr to be refused, which is
// what a port with no listener does. An accepted connection or a timeout is
// not the port being closed.
func waitRefused(ctx context.Context, addr string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
			err = errors.New("connection accepted")
		} else if errors.Is(err, syscall.ECONNREFUSED) {
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("%s still not refusing connections: %v", addr, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
