//go:build darwin

package peercreds

import (
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func get(conn io.Reader) (Info, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Info{}, io.EOF
	}

	f, err := uc.File()
	if err != nil {
		return Info{}, err
	}
	defer f.Close()

	fd := int(f.Fd())

	// Read UID from LOCAL_PEERCRED (struct xucred).
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return Info{}, err
	}

	// Read PID from LOCAL_PEERPID socket option.
	pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	if err != nil {
		// Return UID — PID may be unavailable if socket is not connected.
		return Info{UID: cred.Uid}, nil
	}

	info := Info{
		PID: int32(pid),
		UID: cred.Uid,
	}

	// Resolve process name via ps(1).
	if pid > 0 {
		info.Process = processName(pid)
	}

	return info, nil
}

func processName(pid int) string {
	out, err := exec.Command("ps", "-o", "comm=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
