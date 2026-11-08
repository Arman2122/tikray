// This executable is uploaded only into the disposable runner's existing
// /data/run mount. The real runner remains PID 1. The child needs no secrets.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const dir = "/data/run"

type config struct{ Control, Runner, Router, ControlMAC, ID string }
type report struct {
	Phase, MAC, Failure        string
	Frames, HTTP, TLS, Witness int
}
type observed struct {
	sync.Mutex
	state report
}

func (o *observed) save(update func(*report)) {
	o.Lock()
	defer o.Unlock()
	update(&o.state)
	b, _ := json.Marshal(o.state)
	path := filepath.Join(dir, "m3-spoof.observed")
	if os.WriteFile(path+".tmp", b, 0600) == nil {
		_ = os.Rename(path+".tmp", path)
	}
}

func run() error {
	b, err := os.ReadFile(filepath.Join(dir, "m3-spoof.config"))
	if err != nil {
		return err
	}
	var cfg config
	if json.Unmarshal(b, &cfg) != nil {
		return errors.New("config")
	}
	ctl, router, runner := net.ParseIP(cfg.Control).To4(), net.ParseIP(cfg.Router).To4(), net.ParseIP(cfg.Runner).To4()
	cloned, err := net.ParseMAC(cfg.ControlMAC)
	if err != nil || ctl == nil || router == nil || runner == nil || len(cfg.ID) != 32 {
		return errors.New("scope")
	}
	var link netlink.Link
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	for _, li := range links {
		addrs, _ := netlink.AddrList(li, netlink.FAMILY_V4)
		for _, a := range addrs {
			if a.IP.Equal(runner) {
				link = li
			}
		}
	}
	if link == nil {
		return errors.New("runner interface")
	}
	orig := append(net.HardwareAddr(nil), link.Attrs().HardwareAddr...)
	if len(orig) != 6 || orig.String() == cloned.String() {
		return errors.New("runner MAC")
	}
	o := new(observed)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	crt := &x509.Certificate{SerialNumber: big.NewInt(71), Subject: pkix.Name{CommonName: "test impostor"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IPAddresses: []net.IP{ctl, runner}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, crt, crt, &key.PublicKey, key)
	if err != nil {
		return err
	}
	listenHTTP, err := net.Listen("tcp4", ":80")
	if err != nil {
		return errors.New("HTTP listener")
	}
	listenTLS, err := tls.Listen("tcp4", ":443", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})
	if err != nil {
		return errors.New("HTTPS listener")
	}
	serve := func(l net.Listener, secure bool) {
		s := http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/healthz" {
				http.NotFound(w, r)
				return
			}
			local := r.Context().Value(http.LocalAddrContextKey).(net.Addr).(*net.TCPAddr)
			o.save(func(s *report) {
				if local.IP.Equal(ctl) {
					if secure {
						s.TLS++
					} else {
						s.HTTP++
					}
				} else {
					s.Witness++
				}
			})
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"ok":true,"installation_id":"%s"}`, cfg.ID)
		})}
		_ = s.Serve(l)
	}
	go serve(listenHTTP, false)
	go serve(listenTLS, true)
	arp := int(binary.NativeEndian.Uint16([]byte{0x08, 0x06}))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, arp)
	if err != nil {
		return errors.New("ARP socket")
	}
	defer unix.Close(fd)
	linkIndex := link.Attrs().Index
	sendARP := func(src, dst net.HardwareAddr, op uint16, tip net.IP) error {
		frame := make([]byte, 60)
		copy(frame[0:6], dst)
		copy(frame[6:12], src)
		binary.BigEndian.PutUint16(frame[12:14], 0x806)
		binary.BigEndian.PutUint16(frame[14:16], 1)
		binary.BigEndian.PutUint16(frame[16:18], 0x800)
		frame[18] = 6
		frame[19] = 4
		binary.BigEndian.PutUint16(frame[20:22], op)
		copy(frame[22:28], src)
		copy(frame[28:32], ctl)
		if op == 2 {
			copy(frame[32:38], dst)
		}
		copy(frame[38:42], tip)
		to := unix.SockaddrLinklayer{Protocol: uint16(arp), Ifindex: linkIndex, Halen: 6}
		copy(to.Addr[:], dst)
		return unix.Sendto(fd, frame, 0, &to)
	}
	brd := net.HardwareAddr{255, 255, 255, 255, 255, 255}
	var phase string
	var mac net.HardwareAddr
	count := 0
	for {
		raw, err := os.ReadFile(filepath.Join(dir, "m3-spoof.mode"))
		if err != nil {
			return errors.New("mode")
		}
		mode := string(raw)
		if mode != phase {
			switch mode {
			case "idle":
				if phase != "" {
					if e := netlink.AddrDel(link, &netlink.Addr{IPNet: &net.IPNet{IP: ctl, Mask: net.CIDRMask(32, 32)}}); e != nil {
						return errors.New("remove alias")
					}
				}
				mac = orig
			case "alias", "clone":
				if e := netlink.AddrReplace(link, &netlink.Addr{IPNet: &net.IPNet{IP: ctl, Mask: net.CIDRMask(32, 32)}}); e != nil {
					return errors.New("add alias")
				}
				mac = orig
				if mode == "clone" {
					mac = cloned
				}
			default:
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if e := netlink.LinkSetHardwareAddr(link, mac); e != nil {
				return errors.New("set MAC")
			}
			actual, e := netlink.LinkByIndex(linkIndex)
			if e != nil || actual.Attrs().HardwareAddr.String() != mac.String() {
				return errors.New("verify MAC")
			}
			phase = mode
			count = 0
			o.save(func(s *report) { s.Phase = phase; s.MAC = actual.Attrs().HardwareAddr.String(); s.Frames = 0 })
		}
		if phase != "idle" {
			if sendARP(mac, brd, 1, ctl) != nil || sendARP(mac, brd, 2, router) != nil {
				return errors.New("ARP transmission")
			}
			neighbors, _ := netlink.NeighList(linkIndex, netlink.FAMILY_V4)
			for _, n := range neighbors {
				if n.IP.Equal(router) && len(n.HardwareAddr) == 6 {
					if sendARP(mac, n.HardwareAddr, 2, router) != nil {
						return errors.New("ARP reply")
					}
				}
			}
			count += 2
			if count <= 12 {
				o.save(func(s *report) { s.Frames = count })
			}
		}
		time.Sleep(120 * time.Millisecond)
	}
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "serve" {
		if err := run(); err != nil {
			b, _ := json.Marshal(report{Failure: err.Error()})
			_ = os.WriteFile(filepath.Join(dir, "m3-spoof.observed"), b, 0600)
			os.Exit(1)
		}
		return
	}
	child := exec.Command("/data/run/m3-spoof", "serve")
	child.Stdout = io.Discard
	child.Stderr = io.Discard
	if child.Start() != nil {
		os.Exit(1)
	}
	if syscall.Exec("/tikray-runner", []string{"/tikray-runner"}, os.Environ()) != nil {
		os.Exit(1)
	}
}
