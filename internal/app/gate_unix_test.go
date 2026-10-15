//go:build linux || darwin

package app

import (
	"errors"
	"fmt"
	"os"

	"github.com/krisiasty/ssh-agent-proxy/internal/config"
	"golang.org/x/sys/unix"
)

// holdSocketLocks takes the ownership lock of every enabled group socket, as
// proxy.Server.Run does before it dials the upstream. The lock file is the
// socket path plus ".lock" (see internal/proxy/socketlock_unix.go).
func holdSocketLocks(groups []config.Group) (func(), error) {
	var files []*os.File
	release := func() {
		for _, file := range files {
			_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
			_ = file.Close()
		}
	}
	for _, g := range groups {
		if !g.IsEnabled() {
			continue
		}
		file, err := os.OpenFile(g.Socket+".lock", os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			release()
			return nil, err
		}
		if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			_ = file.Close()
			release()
			if errors.Is(err, unix.EWOULDBLOCK) {
				return nil, fmt.Errorf("group socket %q is still owned by another runtime", g.Socket)
			}
			return nil, err
		}
		files = append(files, file)
	}
	return release, nil
}
