//go:build darwin

package peercreds

import (
	"io"
	"runtime"

	"golang.org/x/sys/unix"
)

func get(conn io.Reader) (Info, error) {
	fd, ok := fdOf(conn)
	if !ok {
		return Info{}, io.EOF
	}

	cred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return Info{}, err
	}

	return Info{
		PID: 0, // macOS Xucred does not carry PID
		UID: cred.Uid,
	}, nil
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
