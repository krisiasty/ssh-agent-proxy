//go:build !linux && !darwin

package app

import "github.com/krisiasty/ssh-agent-proxy/internal/config"

// holdSocketLocks is a no-op where the proxy takes no socket ownership locks.
func holdSocketLocks([]config.Group) (func(), error) {
	return func() {}, nil
}
