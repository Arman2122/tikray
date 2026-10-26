// Command fakexray stands in for xray-core in the runner's tests. Its behaviour
// is fixed at build time:
//
//	go build -ldflags "-X main.mode=ok" -o fake-ok ./internal/runner/testdata/fakexray
//
// Modes: ok (serves until SIGTERM, then exits 0), badconfig (rejects "run
// -test"), exit2s and exit15s (exit 1 after 2 s or 15 s), stubborn (ignores
// SIGTERM, so only SIGKILL stops it), slowtest (takes 1 s to accept "run
// -test"), noisytest (rejects "run -test" after 20 KiB of output). A "run
// -test" that accepts the config prints "config <path>" and the file's
// contents first, then the permissions of the file and its directory and the
// XRAY_LOCATION_ASSET it runs with. In every mode "api <args>" echoes its
// arguments, and the first argument "fail" or "hang" makes it fail or never
// return.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
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
		switch mode {
		case "badconfig":
			fmt.Println("Failed to start: failed to load config")
			os.Exit(23)
		case "noisytest":
			fmt.Println("Failed to start: failed to load config")
			for range 400 {
				fmt.Println(strings.Repeat("x", 49)) // 50 bytes a line
			}
			os.Exit(23)
		case "slowtest":
			time.Sleep(time.Second)
		}
		// What was tested, for the tests to check.
		fmt.Printf("config %s\n", args[3])
		if b, err := os.ReadFile(args[3]); err == nil {
			fmt.Printf("%s\n", b)
		}
		if fi, err := os.Stat(args[3]); err == nil {
			if di, err := os.Stat(filepath.Dir(args[3])); err == nil {
				fmt.Printf("perm file=%o dir=%o\n", fi.Mode().Perm(), di.Mode().Perm())
			}
		}
		fmt.Printf("env XRAY_LOCATION_ASSET=%s\n", os.Getenv("XRAY_LOCATION_ASSET"))
		fmt.Println("Configuration OK.")
	case len(args) >= 2 && args[0] == "api":
		api(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "fakexray: unexpected arguments %q\n", args)
		os.Exit(2)
	}
}

// api is "xray api <args>", the same in every mode. "fail" prints some output,
// complains and exits 3; "hang" never returns; anything else echoes its
// arguments, joined by "|".
func api(args []string) {
	switch args[0] {
	case "fail":
		fmt.Println("partial")
		fmt.Fprintln(os.Stderr, "fakexray: api failed")
		os.Exit(3)
	case "hang":
		time.Sleep(time.Hour)
	default:
		fmt.Printf("api: %s\n", strings.Join(args, "|"))
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
