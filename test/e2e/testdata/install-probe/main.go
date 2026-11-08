// The disposable CHR fixture runs this binary inside the real control
// container. Its output is limited to proof of success or an instance ID.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Arman2122/tikray/internal/routeros"
	"github.com/Arman2122/tikray/internal/runnerapi"
	"github.com/Arman2122/tikray/internal/store"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var in routeros.Installation
	data, err := os.ReadFile("/data/state/routeros.json")
	if err != nil || json.Unmarshal(data, &in) != nil || len(os.Args) != 2 {
		os.Exit(1)
	}
	n := store.Network{Subnet: in.Scope.Subnet}
	// RouterOS can deliver asynchronous console text on the same SSH
	// response. Only a full receipt from this process is our observation.
	emit := func(v string) { fmt.Printf("m3-witness-%s=%s|end\n", os.Args[1], v) }
	switch os.Args[1] {
	case "uninstall-links", "uninstall-unlink":
		// Only these two fixture-owned links can be created or removed.
		// The host verifies the destination's inode from a separate mount.
		for name, target := range map[string]string{"/data/uninstall-link": "../../tikray-owner-sibling", "/data/uninstall-dir-link": "../../tikray-external-probe"} {
			if os.Args[1] == "uninstall-links" {
				if err := os.Symlink(target, name); err != nil && !errors.Is(err, os.ErrExist) {
					os.Exit(1)
				}
			}
			st, err := os.Lstat(name)
			if errors.Is(err, os.ErrNotExist) && os.Args[1] == "uninstall-unlink" {
				continue
			}
			actual, e := os.Readlink(name)
			if err != nil || st.Mode()&os.ModeSymlink == 0 || e != nil || actual != target {
				os.Exit(1)
			}
			if os.Args[1] == "uninstall-unlink" && os.Remove(name) != nil {
				os.Exit(1)
			}
		}
		syscall.Sync()
		emit("verified")
	case "control-start":
		proc, err := os.ReadFile("/proc/1/stat")
		if err != nil {
			os.Exit(1)
		}
		end := strings.LastIndex(string(proc), ")")
		if end < 0 {
			os.Exit(1)
		}
		fields := strings.Fields(string(proc[end+1:]))
		if len(fields) <= 19 {
			os.Exit(1)
		}
		start, err := strconv.ParseUint(fields[19], 10, 64)
		if err != nil {
			os.Exit(1)
		}
		// A new PID namespace can report its init process at tick zero. Pair
		// start ticks with the kernel's namespace identity to distinguish
		// incarnations without assuming a positive namespace-relative time.
		ns, err := os.Readlink("/proc/1/ns/pid")
		if err != nil || !strings.HasPrefix(ns, "pid:[") || !strings.HasSuffix(ns, "]") {
			os.Exit(1)
		}
		inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(ns, "pid:["), "]"), 10, 64)
		if err != nil || inode == 0 {
			os.Exit(1)
		}
		emit(fmt.Sprintf("%d-%d", inode, start))
	case "account":
		c, err := routeros.Dial(ctx, routeros.ConnConfig{Address: in.Address, Username: in.Username, Password: in.Password, Fingerprint: in.Fingerprint})
		if err != nil {
			os.Exit(1)
		}
		defer c.Close()
		g := c.Generation()
		rows, err := c.CommandAt(ctx, g, []string{"/interface/bridge/print", "?name=tikray", "=.proplist=name,comment"})
		if err != nil || len(rows) != 1 || rows[0]["comment"] != "tikray:bridge" {
			os.Exit(1)
		}
		// The unique name and valid policy would succeed with elevated
		// permissions. Same authenticated session and source as the read.
		if _, err := c.CommandAt(ctx, g, []string{"/user/group/add", "=name=m3-privilege-witness", "=policy=read", "=comment=lab:forbidden"}); !errors.Is(err, routeros.ErrRejected) {
			os.Exit(1)
		}
		emit("verified")
	case "runner":
		token, err := os.ReadFile("/data/run/runner.token")
		if err != nil {
			os.Exit(1)
		}
		client := runnerapi.Client{BaseURL: "http://" + n.Runner().String() + ":8080", Token: strings.TrimSpace(string(token))}
		s, err := client.Status(ctx)
		if err != nil || s.Active == nil || s.Candidate != nil || !s.GatewayUp || s.XrayInstance == "" || strings.ContainsAny(s.XrayInstance, "|\n\r ") {
			os.Exit(1)
		}
		emit(s.Active.Core + "|" + s.XrayInstance)
	case "ports":
		for _, port := range []string{"53", "1080", "8080", "10085"} {
			c, err := net.DialTimeout("tcp", net.JoinHostPort(n.Runner().String(), port), 2*time.Second)
			if err != nil {
				os.Exit(1)
			}
			c.Close()
		}
		emit("verified")
	default:
		os.Exit(1)
	}
}
