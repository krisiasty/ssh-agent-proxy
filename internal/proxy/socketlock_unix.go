//go:build linux || darwin

package proxy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type fileSocketLock struct {
	file *os.File
	path string
}

func acquireSocketLock(socketPath string) (socketLock, error) {
	//nolint:gosec // G703: the socket path comes from the operator-owned validated config.
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return nil, fmt.Errorf("creating socket directory: %w", err)
	}

	lockPath := socketPath + ".lock"
	fd, err := unix.Open(lockPath, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening lock file %q: %w", lockPath, err)
	}
	file := os.NewFile(uintptr(fd), lockPath)
	if file == nil {
		if closeErr := unix.Close(fd); closeErr != nil {
			return nil, errors.Join(
				fmt.Errorf("wrapping lock file %q", lockPath),
				fmt.Errorf("closing lock descriptor: %w", closeErr),
			)
		}
		return nil, fmt.Errorf("wrapping lock file %q", lockPath)
	}
	closeOnError := func(operationErr error) error {
		if closeErr := file.Close(); closeErr != nil {
			return errors.Join(operationErr, fmt.Errorf("closing lock file %q: %w", lockPath, closeErr))
		}
		return operationErr
	}

	info, err := file.Stat()
	if err != nil {
		return nil, closeOnError(fmt.Errorf("inspecting lock file %q: %w", lockPath, err))
	}
	if !info.Mode().IsRegular() {
		return nil, closeOnError(fmt.Errorf("lock path %q is not a regular file", lockPath))
	}
	if err := file.Chmod(0o600); err != nil {
		return nil, closeOnError(fmt.Errorf("restricting lock file %q: %w", lockPath, err))
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, closeOnError(fmt.Errorf("%w: %q", ErrSocketInUse, socketPath))
		}
		return nil, closeOnError(fmt.Errorf("locking file %q: %w", lockPath, err))
	}
	return &fileSocketLock{file: file, path: lockPath}, nil
}

func (l *fileSocketLock) Close() error {
	var closeErr error
	if err := unix.Flock(int(l.file.Fd()), unix.LOCK_UN); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("unlocking file %q: %w", l.path, err))
	}
	if err := l.file.Close(); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("closing lock file %q: %w", l.path, err))
	}
	return closeErr
}
