package lab

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

// StartInet starts the fake-internet services in tklab-inet: labinet (web,
// UDP echo, DNS) and the VLESS test server. stop kills both.
func StartInet(ctx context.Context, n *Network) (stop func(), err error) {
	return StartInetWith(ctx, n, InetOptions{})
}

// StartInetWith is StartInet with options.
func StartInetWith(ctx context.Context, n *Network, o InetOptions) (stop func(), err error) {
	var labinetArgs []string
	waitFor := []string{"203.0.113.30:80", "203.0.113.10:443"}
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

	var procs []*exec.Cmd
	stop = func() {
		for _, p := range procs {
			p.Process.Kill()
			p.Wait()
		}
		os.RemoveAll(dir)
	}
	for _, args := range [][]string{
		append([]string{bin}, labinetArgs...),
		{xray, "run", "-c", fixturePath("xray-server.json")},
	} {
		logf, err := os.Create(filepath.Join(dir, filepath.Base(args[0])+".log"))
		if err != nil {
			stop()
			return nil, err
		}
		cmd := n.Inet(context.Background(), args[0], args[1:]...)
		cmd.Stdout, cmd.Stderr = logf, logf
		if err := cmd.Start(); err != nil {
			stop()
			return nil, err
		}
		procs = append(procs, cmd)
	}
	for _, addr := range waitFor {
		if err := waitTCP(ctx, addr, 30*time.Second); err != nil {
			stop()
			return nil, err
		}
	}
	return stop, nil
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
