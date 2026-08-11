//go:build linux || darwin

package service

import "testing"

func TestSignalReloadRejectsInvalidPID(t *testing.T) {
	for _, pid := range []string{"", "not-a-pid", "0", "-1"} {
		if err := signalReload(pid); err == nil {
			t.Errorf("signalReload(%q) error = nil, want invalid pid error", pid)
		}
	}
}
