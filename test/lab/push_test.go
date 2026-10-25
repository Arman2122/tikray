package lab

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fakeRouter stands in for the router of fetchFile: it records each fetch and
// answers each read of the file's size. The file is there once fetches
// reached showAfter (0: never) and, then, from the lateBy-th read after the
// fetch that made it.
type fakeRouter struct {
	fetches, reads int
	showAfter      int    // fetches it takes to have a file
	lateBy         int    // reads after that fetch that still find nothing
	size           string // what a read finds
	fetchOut       string // what a fetch prints
	fetchErr       error
	sinceFile      int
}

const noSuchItem = `:put [/file/get [find name="disk1/x"] size]: no such item (/file/get; line 1)`

func (f *fakeRouter) run(_ context.Context, cmd string) (string, error) {
	if !strings.HasPrefix(cmd, "/tool/fetch ") {
		return "", fmt.Errorf("unexpected command %q", cmd)
	}
	f.fetches++
	f.sinceFile = 0
	return f.fetchOut, f.fetchErr
}

func (f *fakeRouter) get(_ context.Context, expr string) (string, error) {
	if !strings.HasPrefix(expr, `/file/get [find name="disk1/x"] size`) {
		return "", fmt.Errorf("unexpected expression %q", expr)
	}
	f.reads++
	f.sinceFile++
	if f.showAfter == 0 || f.fetches < f.showAfter || f.sinceFile <= f.lateBy {
		return "", errors.New(noSuchItem)
	}
	return f.size, nil
}

func (f *fakeRouter) fetch(t *testing.T) (string, error) {
	t.Helper()
	return fetchFile(t.Context(), f.run, f.get, "http://198.51.100.1:1/x", "disk1/x", 12, 0)
}

func TestFetchFileFirstTime(t *testing.T) {
	f := &fakeRouter{showAfter: 1, size: "12", fetchOut: "status: finished"}
	retry, err := f.fetch(t)
	if err != nil || retry != "" {
		t.Fatalf("fetchFile = %q, %v; want no retry and no error", retry, err)
	}
	if f.fetches != 1 || f.reads != 1 {
		t.Errorf("%d fetches and %d reads, want 1 and 1", f.fetches, f.reads)
	}
}

// The first fetch leaves no file: only the second fetch gives one. Without
// the retry, fetchFile fails.
func TestFetchFileFetchesAgain(t *testing.T) {
	f := &fakeRouter{showAfter: 2, size: "12", fetchOut: "status: finished"}
	retry, err := f.fetch(t)
	if err != nil {
		t.Fatalf("fetchFile: %v, want the second fetch to give the file", err)
	}
	if f.fetches != 2 {
		t.Errorf("%d fetches, want 2", f.fetches)
	}
	if !strings.Contains(retry, "fetched again") || !strings.Contains(retry, "status: finished") || !strings.Contains(retry, "disk1/x") {
		t.Errorf("retry note %q, want it to say the file was fetched again, with the first fetch's output and the path", retry)
	}
}

// A file that shows up a moment after the fetch needs no second fetch, but
// the run still says it waited.
func TestFetchFileLateFile(t *testing.T) {
	f := &fakeRouter{showAfter: 1, lateBy: 2, size: "12", fetchOut: "status: finished"}
	retry, err := f.fetch(t)
	if err != nil {
		t.Fatalf("fetchFile: %v", err)
	}
	if f.fetches != 1 || f.reads != 3 {
		t.Errorf("%d fetches and %d reads, want 1 and 3", f.fetches, f.reads)
	}
	if !strings.Contains(retry, "showed up") || !strings.Contains(retry, "disk1/x") {
		t.Errorf("retry note %q, want it to say the file showed up late", retry)
	}
}

// When no fetch leaves a file, the error says so loudly, with what each
// fetch printed.
func TestFetchFileNeverThere(t *testing.T) {
	f := &fakeRouter{fetchOut: "status: finished\n  downloaded: 0KiB"}
	retry, err := f.fetch(t)
	if err == nil {
		t.Fatal("fetchFile succeeded with no file")
	}
	if f.fetches != 2 {
		t.Errorf("%d fetches, want 2 (one retry, no more)", f.fetches)
	}
	msg := err.Error()
	for _, want := range []string{"disk1/x", "2 fetches", "status: finished", "downloaded: 0KiB", "no such item"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q lacks %q", msg, want)
		}
	}
	if retry == "" {
		t.Error("no retry note when the retry ran")
	}
}

func TestFetchFileWrongSize(t *testing.T) {
	f := &fakeRouter{showAfter: 1, size: "7"}
	if _, err := f.fetch(t); err == nil || !strings.Contains(err.Error(), "7 bytes") {
		t.Fatalf("fetchFile = %v, want an error naming the size the router has", err)
	}
	if f.fetches != 1 {
		t.Errorf("%d fetches, want 1: a file of the wrong size is not a missing one", f.fetches)
	}
}

func TestFetchFileFetchFails(t *testing.T) {
	f := &fakeRouter{showAfter: 1, size: "12", fetchErr: errors.New("failure: connection refused")}
	if _, err := f.fetch(t); err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("fetchFile = %v, want the fetch's error", err)
	}
	if f.fetches != 1 || f.reads != 0 {
		t.Errorf("%d fetches and %d reads, want 1 and 0", f.fetches, f.reads)
	}
}
