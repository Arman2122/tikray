package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// serveLockName is the lock of the state's owner, in the state directory.
const serveLockName = "serve.lock"

// errServeHeld means that another process holds serve.lock.
var errServeHeld = errors.New("serve.lock is held")

// lockServe takes the lock of the state's owner, <data>/state/serve.lock,
// without waiting, and makes the state directory (0700) if it is missing.
// It gives errServeHeld when another process holds it.
//
// tikray serve holds it for as long as it runs, and a command that runs the
// updater in its own process (apply, core update and core rollback, where no
// daemon answers) holds it for as long as it runs, so that only one process
// owns the state at a time: whatever the probe of the daemon's address found,
// it is never two. The lock is the flock of an open file, so it goes when
// unlock closes the file or the process dies.
func lockServe(data string) (unlock func(), err error) {
	if err := os.MkdirAll(stateDir(data), 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(stateDir(data), serveLockName)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errServeHeld
		}
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	return func() { f.Close() }, nil
}
