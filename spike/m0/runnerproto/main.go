// Command runnerproto is the M0 spike's stand-in for tikray-runner. It runs as
// PID 1 in the runner container: it enables forwarding, starts xray (whose TUN
// inbound creates xray0), routes packets arriving on the ingress link into
// xray0, and reports what it managed to do on :8080. Throwaway.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
)

const (
	tunName  = "xray0"
	tunTable = 1001
	rulePrio = 1001
)

type status struct {
	Sysctl       map[string]string `json:"sysctl"`
	Ingress      string            `json:"ingress"`
	XrayPID      int               `json:"xray_pid"`
	XrayRSSKB    int               `json:"xray_rss_kb"`
	RoutesOK     bool              `json:"routes_ok"`
	XrayRestarts int               `json:"xray_restarts"`
}

var (
	mu sync.Mutex
	st = status{Sysctl: map[string]string{}}
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func sysctl(key, value string) {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	res := "ok"
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		res = err.Error()
	}
	log.Printf("sysctl %s=%s: %s", key, value, res)
	mu.Lock()
	st.Sysctl[key] = res
	mu.Unlock()
}

// ingressLink is the link holding the IPv4 default route.
func ingressLink() (netlink.Link, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		if r.Dst == nil || r.Dst.String() == "0.0.0.0/0" {
			return netlink.LinkByIndex(r.LinkIndex)
		}
	}
	return nil, fmt.Errorf("no default route")
}

func superviseXray(bin, cfg string) {
	for {
		cmd := exec.Command(bin, "run", "-c", cfg)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			log.Printf("start xray: %v", err)
		} else {
			mu.Lock()
			st.XrayPID = cmd.Process.Pid
			mu.Unlock()
			err = cmd.Wait()
			log.Printf("xray exited: %v", err)
		}
		mu.Lock()
		st.XrayPID = 0
		st.XrayRestarts++
		mu.Unlock()
		time.Sleep(time.Second)
	}
}

// ensureRoutes keeps "default dev xray0 table 1001" and "iif <ingress>
// lookup 1001" in place; xray0 disappears whenever xray restarts.
func ensureRoutes(ingress netlink.Link) bool {
	tun, err := netlink.LinkByName(tunName)
	if err != nil {
		return false
	}
	if err := netlink.LinkSetUp(tun); err != nil {
		log.Printf("set %s up: %v", tunName, err)
		return false
	}
	os.WriteFile("/proc/sys/net/ipv4/conf/"+tunName+"/rp_filter", []byte("0"), 0o644)
	_, all, _ := net.ParseCIDR("0.0.0.0/0")
	if err := netlink.RouteReplace(&netlink.Route{LinkIndex: tun.Attrs().Index, Dst: all, Table: tunTable}); err != nil {
		log.Printf("route default dev %s table %d: %v", tunName, tunTable, err)
		return false
	}
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return false
	}
	for _, r := range rules {
		if r.Priority == rulePrio && r.Table == tunTable && r.IifName == ingress.Attrs().Name {
			return true
		}
	}
	rule := netlink.NewRule()
	rule.Priority, rule.Table, rule.IifName = rulePrio, tunTable, ingress.Attrs().Name
	if err := netlink.RuleAdd(rule); err != nil {
		log.Printf("rule iif %s lookup %d: %v", ingress.Attrs().Name, tunTable, err)
		return false
	}
	return true
}

func rssKB(pid int) int {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "VmRSS:" {
			n, _ := strconv.Atoi(f[1])
			return n
		}
	}
	return 0
}

func main() {
	log.SetFlags(log.Ltime)
	sysctl("net.ipv4.ip_forward", "1")
	sysctl("net.ipv4.conf.all.rp_filter", "0")
	sysctl("net.ipv4.conf.default.rp_filter", "0")

	var ingress netlink.Link
	for {
		l, err := ingressLink()
		if err == nil {
			ingress = l
			break
		}
		log.Printf("ingress link: %v", err)
		time.Sleep(time.Second)
	}
	mu.Lock()
	st.Ingress = ingress.Attrs().Name
	mu.Unlock()
	log.Printf("ingress link %s", ingress.Attrs().Name)

	go superviseXray(env("XRAY_BIN", "/data/cores/26.3.27/xray"), env("XRAY_CONFIG", "/data/run/config.json"))
	go func() {
		for {
			ok := ensureRoutes(ingress)
			mu.Lock()
			if ok != st.RoutesOK {
				log.Printf("routes_ok=%v", ok)
			}
			st.RoutesOK = ok
			mu.Unlock()
			time.Sleep(time.Second)
		}
	}()

	http.HandleFunc("/v0/status", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		s := st
		s.Sysctl = map[string]string{}
		for k, v := range st.Sysctl {
			s.Sysctl[k] = v
		}
		mu.Unlock()
		if s.XrayPID > 0 {
			s.XrayRSSKB = rssKB(s.XrayPID)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s)
	})
	http.HandleFunc("/v0/file", func(w http.ResponseWriter, r *http.Request) {
		b, err := os.ReadFile(r.URL.Query().Get("path"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Write(b)
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
