package lab

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeShell plays a RouterOS console: it echoes each line and answers with
// reply(line) before the next prompt.
func fakeShell(t *testing.T, reply func(line string) string) *console {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "console.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\r')
			if err != nil {
				return
			}
			fmt.Fprintf(conn, "%s\n%s[admin@CHR] > ", line, reply(strings.TrimSuffix(line, "\r")))
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := openConsole(ctx, sock, filepath.Join(dir, "console.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.close)
	return c
}

// On arm64 CHR the login prompt can appear before ether1/ether2 exist; the
// address commands then fail with this text, and provisioning must say so
// instead of waiting for SSH until the boot deadline.
func TestConsoleCommandReportsRouterOSError(t *testing.T) {
	c := fakeShell(t, func(line string) string {
		if strings.Contains(line, "interface=ether9") {
			return "input does not match any value of interface\r\n"
		}
		return ""
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := c.command(ctx, "/ip/address/add address=192.0.2.1/24 interface=ether9 comment=lab:x")
	if err == nil || !strings.Contains(err.Error(), "input does not match any value of interface") {
		t.Errorf("failed command: err %v, want the RouterOS error text", err)
	}
	if err := c.command(ctx, "/ip/service/set ssh disabled=no"); err != nil {
		t.Errorf("good command: %v", err)
	}
}
