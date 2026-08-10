//go:build !linux && !darwin

package proxy

import "fmt"

func acquireSocketLock(socketPath string) (socketLock, error) {
	return nil, fmt.Errorf("socket locks are unsupported on this platform for %q", socketPath)
}
