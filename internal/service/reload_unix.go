//go:build linux || darwin

package service

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

func signalReload(pidValue string) error {
	pid, err := strconv.Atoi(pidValue)
	if err != nil || pid <= 0 {
		return fmt.Errorf("invalid process id %q", pidValue)
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Signal(syscall.SIGHUP)
}
