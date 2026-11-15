// A benign ordinary router for a disposable CHR. Record native defaults before
// setting forwarding, and send an independent container-origin WAN heartbeat.
package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	bit := func(path string) string {
		v, e := os.ReadFile(path)
		if e != nil {
			return "x"
		}
		return strings.TrimSpace(string(v))
	}
	devs, _ := net.Interfaces()
	ing := "x"
	for _, iface := range devs {
		if iface.Flags&net.FlagLoopback == 0 {
			ing = bit("/proc/sys/net/ipv4/conf/" + iface.Name + "/forwarding")
			break
		}
	}
	flags := fmt.Sprintf("%t %s %s %s", os.Getpid() == 1, bit("/proc/sys/net/ipv4/ip_forward"), ing, bit("/proc/sys/net/ipv4/icmp_echo_ignore_all"))
	socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 254), Port: 31798})
	if err != nil {
		return
	}
	_, _ = socket.Write([]byte("init " + flags))
	if os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644) != nil {
		return
	}
	for {
		_ = socket.SetDeadline(time.Now().Add(500 * time.Millisecond))
		_, _ = socket.Write([]byte("runner-origin"))
		buf := make([]byte, 32)
		n, err := socket.Read(buf)
		if err == nil && string(buf[:n]) == "confirmed" {
			_, _ = socket.Write([]byte("round-trip " + flags))
		}
		time.Sleep(250 * time.Millisecond)
	}
}
