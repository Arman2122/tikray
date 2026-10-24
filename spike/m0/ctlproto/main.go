// Command ctlproto is the M0 spike's stand-in for the tikray control plane.
// It runs as PID 1 in the control container and serves two probes on :8080:
// writing into the shared mounts, and watching a RouterOS address list over
// API-SSL with a restricted user. Throwaway.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-routeros/routeros/v3"
)

func main() {
	log.SetFlags(log.Ltime)
	http.HandleFunc("/v0/write", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		b, _ := io.ReadAll(r.Body)
		if err := os.WriteFile(r.URL.Query().Get("path"), b, 0o644); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	http.HandleFunc("/v0/api-probe", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		q := r.URL.Query()
		c, err := routeros.DialTLSContext(ctx, "172.31.255.1:8729", q.Get("user"), q.Get("pass"), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			http.Error(w, "dial: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer c.Close()
		l, err := c.ListenContext(ctx, "/ip/firewall/address-list/listen")
		if err != nil {
			http.Error(w, "listen: "+err.Error(), http.StatusBadGateway)
			return
		}
		select {
		case s, ok := <-l.Chan():
			if !ok {
				http.Error(w, "listen ended", http.StatusBadGateway)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(s.Map)
		case <-ctx.Done():
			http.Error(w, "no event within 60s", http.StatusGatewayTimeout)
		}
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
