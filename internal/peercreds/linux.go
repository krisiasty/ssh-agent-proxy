//go:build linux

package peercreds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func get(_ context.Context, conn io.Reader) (info Info, retErr error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Info{}, io.EOF
	}

	f, err := uc.File()
	if err != nil {
		return Info{}, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("closing peer socket descriptor: %w", err))
		}
	}()

	fd := int(f.Fd())
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return Info{}, err
	}

	info = Info{
		PID: cred.Pid,
		UID: cred.Uid,
	}

	// Read process name from /proc/<pid>/cmdline.
	if cred.Pid > 0 {
		info.Process = processName(cred.Pid)
	}
	return info, nil
}

// processName reads the process name from /proc/<pid>/cmdline.
func processName(pid int32) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/cmdline")
	if err != nil {
		return ""
	}
	// cmdline is NUL-separated; take the first component.
	if idx := strings.IndexByte(string(data), 0); idx >= 0 {
		return string(data[:idx])
	}
	return strings.TrimRight(string(data), "\x00")
}
