//go:build darwin

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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

// launchctlCall is one fake launchctl result for fakeLaunchctl.
type launchctlCall struct {
	stdout string
	stderr string
	err    error
}

// exitStatusError mimics *exec.ExitError for a launchctl exit status.
type exitStatusError int

func (e exitStatusError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }
func (e exitStatusError) ExitCode() int { return int(e) }

// fakeLaunchctl answers launchctl invocations by their joined arguments and
// records every invocation in order.
type fakeLaunchctl struct {
	results map[string]launchctlCall
	calls   []string
}

func (f *fakeLaunchctl) run(_ context.Context, args ...string) ([]byte, []byte, error) {
	key := strings.Join(args, " ")
	f.calls = append(f.calls, key)
	result, ok := f.results[key]
	if !ok {
		return nil, []byte("unexpected launchctl call"), exitStatusError(1)
	}
	return []byte(result.stdout), []byte(result.stderr), result.err
}

const testUID = 501

// newTestLaunchdManager returns a manager with an installed plist whose
// launchctl calls and liveness checks are faked.
func newTestLaunchdManager(t *testing.T, fake *fakeLaunchctl, alive func(int) bool) *launchdManager {
	t.Helper()
	dir := t.TempDir()
	m := &launchdManager{
		cfgPath:   filepath.Join(dir, "config.yaml"),
		plistPath: filepath.Join(dir, Label+".plist"),
		logPath:   filepath.Join(dir, "proxy.log"),
		uid:       testUID,
		run:       fake.run,
		alive:     alive,
	}
	plist, err := renderLaunchdPlist(Label, []string{"/usr/local/bin/ssh-agent-proxy", "-config", m.cfgPath}, m.logPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.plistPath, plist, 0o600); err != nil {
		t.Fatal(err)
	}
	return m
}

func alwaysAlive(int) bool { return true }

var (
	guiKickstart  = fmt.Sprintf("kickstart -kp gui/%d/%s", testUID, Label)
	userKickstart = fmt.Sprintf("kickstart -kp user/%d/%s", testUID, Label)
	listJob       = "list " + Label
)

func TestLaunchdRestartReplacesRunningProcessInOneOperation(t *testing.T) {
	fake := &fakeLaunchctl{results: map[string]launchctlCall{
		listJob:      {stdout: "{\n\t\"PID\" = 100;\n};\n"},
		guiKickstart: {stdout: "200\n"},
	}}
	if err := newTestLaunchdManager(t, fake, alwaysAlive).Restart(); err != nil {
		t.Fatalf("Restart() error = %v", err)
	}
	want := []string{listJob, guiKickstart}
	if !reflect.DeepEqual(fake.calls, want) {
		t.Errorf("launchctl calls = %q, want %q (no separate stop and start)", fake.calls, want)
	}
}

func TestLaunchdRestartStartsStoppedJob(t *testing.T) {
	fake := &fakeLaunchctl{results: map[string]launchctlCall{
		listJob:      {stdout: "{\n\t\"LastExitStatus\" = 0;\n};\n"},
		guiKickstart: {stdout: "200\n"},
	}}
	if err := newTestLaunchdManager(t, fake, alwaysAlive).Restart(); err != nil {
		t.Fatalf("Restart() error = %v", err)
	}
}

func TestLaunchdRestartFallsBackToUserDomain(t *testing.T) {
	fake := &fakeLaunchctl{results: map[string]launchctlCall{
		listJob:       {stdout: "{\n\t\"PID\" = 100;\n};\n"},
		guiKickstart:  {stderr: "Could not find service", err: exitStatusError(launchctlServiceNotFound)},
		userKickstart: {stdout: "200\n"},
	}}
	if err := newTestLaunchdManager(t, fake, alwaysAlive).Restart(); err != nil {
		t.Fatalf("Restart() error = %v", err)
	}
	if want := []string{listJob, guiKickstart, userKickstart}; !reflect.DeepEqual(fake.calls, want) {
		t.Errorf("launchctl calls = %q, want %q", fake.calls, want)
	}
}

func TestLaunchdRestartFailures(t *testing.T) {
	notFound := launchctlCall{stderr: "Could not find service", err: exitStatusError(launchctlServiceNotFound)}
	for _, tc := range []struct {
		name    string
		results map[string]launchctlCall
		alive   func(int) bool
		want    string
	}{
		{
			name:    "job not loaded",
			results: map[string]launchctlCall{listJob: notFound, guiKickstart: notFound, userKickstart: notFound},
			want:    "run -reinstall",
		},
		{
			name: "kickstart error",
			results: map[string]launchctlCall{
				listJob:      {stdout: "{\n\t\"PID\" = 100;\n};\n"},
				guiKickstart: {stderr: "Operation not permitted", err: exitStatusError(1)},
			},
			want: "Operation not permitted",
		},
		{
			name: "process not replaced",
			results: map[string]launchctlCall{
				listJob:      {stdout: "{\n\t\"PID\" = 100;\n};\n"},
				guiKickstart: {stdout: "100\n"},
			},
			want: "did not replace",
		},
		{
			name: "replacement exited",
			results: map[string]launchctlCall{
				listJob:      {stdout: "{\n\t\"PID\" = 100;\n};\n"},
				guiKickstart: {stdout: "200\n"},
			},
			alive: func(int) bool { return false },
			want:  "exited immediately",
		},
		{
			name: "unexpected output",
			results: map[string]launchctlCall{
				listJob:      {stdout: "{\n\t\"PID\" = 100;\n};\n"},
				guiKickstart: {stdout: "started\n"},
			},
			want: "unexpected output",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alive := tc.alive
			if alive == nil {
				alive = alwaysAlive
			}
			err := newTestLaunchdManager(t, &fakeLaunchctl{results: tc.results}, alive).Restart()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Restart() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLaunchdRestartRequiresInstalledJob(t *testing.T) {
	notFound := launchctlCall{stderr: "Could not find service", err: exitStatusError(launchctlServiceNotFound)}
	fake := &fakeLaunchctl{results: map[string]launchctlCall{listJob: notFound}}
	m := newTestLaunchdManager(t, fake, alwaysAlive)
	if err := os.Remove(m.plistPath); err != nil {
		t.Fatal(err)
	}
	if err := m.Restart(); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Errorf("Restart() error = %v, want not installed", err)
	}
	for _, call := range fake.calls {
		if strings.HasPrefix(call, "kickstart") {
			t.Errorf("Restart() of an uninstalled job ran %q", call)
		}
	}
}

func TestLaunchdStatusReportsRunningJob(t *testing.T) {
	fake := &fakeLaunchctl{results: map[string]launchctlCall{listJob: {stdout: "{\n\t\"PID\" = 100;\n};\n"}}}
	st, err := newTestLaunchdManager(t, fake, alwaysAlive).Status()
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if !st.Installed || !st.Running || st.PID != "100" {
		t.Errorf("Status() = %+v, want installed and running with pid 100", st)
	}
}

func TestLaunchdStatusTreatsUnloadedJobAsStopped(t *testing.T) {
	fake := &fakeLaunchctl{results: map[string]launchctlCall{
		listJob: {stderr: "Could not find service", err: exitStatusError(launchctlServiceNotFound)},
	}}
	st, err := newTestLaunchdManager(t, fake, alwaysAlive).Status()
	if err != nil {
		t.Fatalf("Status() error = %v, want an unloaded job reported as stopped", err)
	}
	if !st.Installed || st.Running || st.PID != "" {
		t.Errorf("Status() = %+v, want installed and stopped", st)
	}
}

func TestLaunchdStatusPropagatesInspectionFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		call launchctlCall
		want string
	}{
		{name: "launchctl failure", call: launchctlCall{stderr: "Operation not permitted", err: exitStatusError(1)}, want: "Operation not permitted"},
		{name: "timeout", call: launchctlCall{err: context.DeadlineExceeded}, want: "timed out"},
		{name: "launchctl missing", call: launchctlCall{err: exec.ErrNotFound}, want: "executable file not found"},
		{name: "malformed output", call: launchctlCall{stdout: "{\n\t\"Program\" = \"bad\\q\";\n};\n"}, want: "launchd program"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeLaunchctl{results: map[string]launchctlCall{listJob: tc.call}}
			st, err := newTestLaunchdManager(t, fake, alwaysAlive).Status()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Status() error = %v, want %q", err, tc.want)
			}
			if st.Running {
				t.Errorf("Status() = %+v, want no running claim on failure", st)
			}
		})
	}
}

func TestLaunchdRestartStopsOnInspectionFailure(t *testing.T) {
	fake := &fakeLaunchctl{results: map[string]launchctlCall{
		listJob:      {stderr: "Operation not permitted", err: exitStatusError(1)},
		guiKickstart: {stdout: "200\n"},
	}}
	err := newTestLaunchdManager(t, fake, alwaysAlive).Restart()
	if err == nil || !strings.Contains(err.Error(), "Operation not permitted") {
		t.Fatalf("Restart() error = %v, want the inspection failure", err)
	}
	for _, call := range fake.calls {
		if strings.HasPrefix(call, "kickstart") {
			t.Errorf("Restart() acted on an unknown state: %q", call)
		}
	}
}
