//go:build !linux && !darwin

package service

import (
	"fmt"
	"runtime"
)

// New reports that managed-service mode is unsupported on this platform.
// The proxy can still be run directly with -foreground.
func New(cfgPath string) (Manager, error) {
	return nil, fmt.Errorf("service management is not supported on %s; run with -foreground", runtime.GOOS)
}
