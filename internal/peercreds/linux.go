//go:build linux

package peercreds

import (
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func get(conn io.Reader) (Info, error) {
	fd, ok := fdOf(conn)
	if !ok {
		return Info{}, io.EOF
	}

	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return Info{}, err
	}

	info := Info{
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

// fdOf extracts the underlying file descriptor from a net.UnixConn.
func fdOf(conn io.Reader) (int, bool) {
	type fileDescriptor interface {
		Fd() (fd uintptr, err error)
	}
	if fc, ok := conn.(fileDescriptor); ok {
		fp, err := fc.Fd()
		if err != nil {
			return 0, false
		}
		runtime.KeepAlive(fc)
		return int(fp), true
	}
	return 0, false
}
