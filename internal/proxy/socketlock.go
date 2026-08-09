package proxy

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
)

// ErrSocketInUse reports that another process owns or is serving a group
// socket. Callers must not remove the socket when this error is returned.
var ErrSocketInUse = errors.New("socket is already in use")

type socketLock interface {
	Close() error
}

// acquireSocketLocks takes every lock before startup touches any socket. The
// stable order avoids lock-order inversions between instances with equivalent
// group configurations in different orders.
func acquireSocketLocks(paths []string) ([]socketLock, error) {
	ordered := append([]string(nil), paths...)
	for i := range ordered {
		ordered[i] = filepath.Clean(ordered[i])
	}
	sort.Strings(ordered)

	locks := make([]socketLock, 0, len(ordered))
	for i, path := range ordered {
		if i > 0 && path == ordered[i-1] {
			return nil, errors.Join(
				fmt.Errorf("duplicate group socket path %q", path),
				closeSocketLocks(locks),
			)
		}
		lock, err := acquireSocketLock(path)
		if err != nil {
			return nil, errors.Join(
				fmt.Errorf("locking socket %q: %w", path, err),
				closeSocketLocks(locks),
			)
		}
		locks = append(locks, lock)
	}
	return locks, nil
}

func closeSocketLocks(locks []socketLock) error {
	var closeErr error
	for i := len(locks) - 1; i >= 0; i-- {
		if err := locks[i].Close(); err != nil {
			closeErr = errors.Join(closeErr, err)
		}
	}
	return closeErr
}
