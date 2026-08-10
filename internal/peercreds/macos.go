//go:build darwin

package peercreds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func get(ctx context.Context, conn io.Reader) (info Info, retErr error) {
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
	if pid < 0 || pid > math.MaxInt32 {
		return Info{UID: cred.Uid}, fmt.Errorf("peer PID %d is outside the supported range", pid)
	}

	info = Info{
		PID: int32(pid),
		UID: cred.Uid,
	}

	// Resolve process name via ps(1).
	if pid > 0 {
		info.Process = processName(ctx, pid)
	}

	return info, nil
}

func processName(ctx context.Context, pid int) string {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	// pid comes from LOCAL_PEERPID and is converted to decimal before being
	// passed as one argument; exec.Command does not invoke a shell.
	//nolint:gosec // G204: the integer PID cannot inject additional arguments.
	out, err := exec.CommandContext(ctx, "ps", "-o", "comm=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
