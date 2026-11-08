package atomicfile

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// ReadRegular reads a bounded handoff without following a final symlink or
// blocking on a FIFO. With nonzero perm the mode must match exactly.
func ReadRegular(path string, limit int64, perm fs.FileMode) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || perm != 0 && st.Mode().Perm() != perm || st.Size() > limit {
		return nil, errors.New("atomicfile: invalid handoff file")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(b)) > limit {
		return nil, errors.New("atomicfile: handoff too large")
	}
	return b, err
}
