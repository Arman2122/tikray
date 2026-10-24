// Command fakexray stands in for xray-core in the runner's tests. Its behaviour
// is fixed at build time:
//
//	go build -ldflags "-X main.mode=ok" -o fake-ok ./internal/runner/testdata/fakexray
//
// Modes: ok (serves until SIGTERM, then exits 0), badconfig (rejects "run
// -test"), exit2s and exit15s (exit 1 after 2 s or 15 s), stubborn (ignores
// SIGTERM, so only SIGKILL stops it).
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var mode = "ok"

func main() {
	args := os.Args[1:]
	switch {
	case len(args) == 1 && args[0] == "version":
		fmt.Printf("Xray 99.0.0 (fake %s)\n", mode)
		fmt.Println("A unified platform for anti-censorship.")
	case len(args) == 3 && args[0] == "run" && args[1] == "-c":
		serve(args[2])
	case len(args) == 4 && args[0] == "run" && args[1] == "-test" && args[2] == "-c":
		if mode == "badconfig" {
			fmt.Println("Failed to start: failed to load config")
			os.Exit(23)
		}
		fmt.Println("Configuration OK.")
	default:
		fmt.Fprintf(os.Stderr, "fakexray: unexpected arguments %q\n", args)
		os.Exit(2)
	}
}

// serve is "xray run -c config". Signal handling is in place before the first
// line is printed, so a test that has seen the line can signal safely.
func serve(config string) {
	term := make(chan os.Signal, 1)
	switch mode {
	case "ok":
		signal.Notify(term, syscall.SIGTERM)
	case "stubborn":
		signal.Ignore(syscall.SIGTERM)
	}
	fmt.Printf("env GOMEMLIMIT=%s XRAY_LOCATION_ASSET=%s\n", os.Getenv("GOMEMLIMIT"), os.Getenv("XRAY_LOCATION_ASSET"))
	fmt.Printf("config %s\n", config)
	switch mode {
	case "exit2s":
		time.Sleep(2 * time.Second)
		os.Exit(1)
	case "exit15s":
		time.Sleep(15 * time.Second)
		os.Exit(1)
	case "ok":
		<-term
	default:
		time.Sleep(time.Hour)
	}
}
