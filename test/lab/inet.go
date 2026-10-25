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

// StartInet starts the fake-internet services in tklab-inet: labinet (web,
// UDP echo, DNS) and the VLESS test server. stop kills both.
func StartInet(ctx context.Context, n *Network) (stop func(), err error) {
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
		{bin},
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
	for _, addr := range []string{"203.0.113.30:80", "203.0.113.10:443"} {
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
