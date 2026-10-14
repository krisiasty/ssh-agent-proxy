// Package testutil provides helpers shared by tests in this module.
package testutil

import (
	"os"
	"testing"
)

// ShortSocketDir creates a temporary directory suitable for macOS Unix sockets.
func ShortSocketDir(t *testing.T) string {
	t.Helper()
	//nolint:usetesting // Unix socket paths on macOS cannot safely fit beneath t.TempDir().
	dir, err := os.MkdirTemp("/tmp", "ssh-agent-proxy-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("removing socket test directory: %v", err)
		}
	})
	return dir
}
