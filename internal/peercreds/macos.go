//go:build darwin

package peercreds

import (
	"io"
	"net"
	"os"
	"syscall"

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
	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return Info{}, err
	}

	return Info{
		PID: 0, // macOS Xucred does not carry PID
		UID: cred.Uid,
	}, nil
}

// suppress unused imports
var _ = os.Getpid()
var _ = syscall.Errno(0)
