package proxy

import (
	"errors"
	"fmt"
	"net"
	"os"
)

// ownedUnixListener disables net.UnixListener's unconditional unlink-on-close
// behavior and removes the path only while it still identifies this listener.
type ownedUnixListener struct {
	*net.UnixListener
	path     string
	identity os.FileInfo
}

func (l *ownedUnixListener) Close() error {
	if err := l.UnixListener.Close(); err != nil {
		if errors.Is(err, net.ErrClosed) {
			return err
		}
		return fmt.Errorf("closing Unix listener: %w", err)
	}

	current, err := os.Lstat(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspecting listener path during cleanup: %w", err)
	}
	if !os.SameFile(l.identity, current) {
		return nil
	}
	if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing owned listener socket: %w", err)
	}
	return nil
}
