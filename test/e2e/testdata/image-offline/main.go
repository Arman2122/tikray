// This signed QA image has a real, running container and veth but no healthy
// control listener or runner data plane. No privileged behavior is necessary.
package main

import (
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Arman2122/tikray/internal/store"
)

func main() {
	// Model a newer control that created a separate state file before
	// failing its health check. The prior version must still read its own.
	if filepath.Base(os.Args[0]) == "tikray" {
		next := filepath.Join("/data/state", "state.v"+strconv.Itoa(store.Current+1)+".json")
		if f, err := os.OpenFile(next, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600); err == nil {
			_, _ = f.WriteString(`{"lab":"future schema"}`)
			_ = f.Sync()
			_ = f.Close()
		}
	}
	for {
		time.Sleep(time.Hour)
	}
}
