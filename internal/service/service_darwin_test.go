//go:build darwin

package service

import (
	"errors"
	"strings"
	"testing"
)

func TestLaunchctlCommandErrorAcceptsSilentSuccess(t *testing.T) {
	if err := launchctlCommandError([]string{"load", "test.plist"}, nil, nil); err != nil {
		t.Fatalf("launchctlCommandError() error = %v", err)
	}
}

func TestLaunchctlCommandErrorRejectsDiagnosticWithSuccessfulExit(t *testing.T) {
	err := launchctlCommandError(
		[]string{"load", "test.plist"},
		[]byte("Load failed: 5: Input/output error\n"),
		nil,
	)
	if err == nil {
		t.Fatal("launchctlCommandError() error = nil, want diagnostic error")
	}
	if !strings.Contains(err.Error(), "Load failed: 5") {
		t.Errorf("launchctlCommandError() = %q, want launchctl diagnostic", err)
	}
}

func TestLaunchctlCommandErrorIncludesOutputAndExitError(t *testing.T) {
	runErr := errors.New("exit status 1")
	err := launchctlCommandError([]string{"start", Label}, []byte("service unavailable\n"), runErr)
	if !errors.Is(err, runErr) {
		t.Errorf("launchctlCommandError() = %v, want wrapped run error", err)
	}
	if !strings.Contains(err.Error(), "service unavailable") {
		t.Errorf("launchctlCommandError() = %q, want command output", err)
	}
}
