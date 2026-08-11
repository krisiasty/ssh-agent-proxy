package service

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// fakeManager records the lifecycle calls made against it.
type fakeManager struct {
	installed bool
	running   bool
	pid       string
	statusErr error
	calls     []string
}

func (f *fakeManager) Install() error   { f.calls = append(f.calls, "install"); return nil }
func (f *fakeManager) Uninstall() error { f.calls = append(f.calls, "uninstall"); return nil }
func (f *fakeManager) Reinstall() error { return reinstall(f) }
func (f *fakeManager) Start() error     { return nil }
func (f *fakeManager) Stop() error      { return nil }
func (f *fakeManager) Restart() error   { return nil }
func (f *fakeManager) Reload() error    { return nil }
func (f *fakeManager) Status() (Status, error) {
	return Status{Installed: f.installed, Running: f.running, PID: f.pid}, f.statusErr
}
func (f *fakeManager) LogHint() string { return "" }

func TestReinstallSkipsUninstallWhenNotInstalled(t *testing.T) {
	f := &fakeManager{installed: false}
	if err := f.Reinstall(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"install"}; !reflect.DeepEqual(f.calls, want) {
		t.Errorf("calls = %v, want %v (uninstall must be skipped when not installed)", f.calls, want)
	}
}

func TestReinstallUninstallsWhenInstalled(t *testing.T) {
	f := &fakeManager{installed: true}
	if err := f.Reinstall(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"uninstall", "install"}; !reflect.DeepEqual(f.calls, want) {
		t.Errorf("calls = %v, want %v", f.calls, want)
	}
}

func TestReloadServiceSignalsRunningProcess(t *testing.T) {
	f := &fakeManager{installed: true, running: true, pid: "123"}
	var signaledPID string
	if err := reloadService(f, func(pid string) error {
		signaledPID = pid
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if signaledPID != "123" {
		t.Errorf("signaled pid = %q, want 123", signaledPID)
	}
}

func TestReloadServiceRequiresRunningInstalledProcess(t *testing.T) {
	tests := []struct {
		name string
		mgr  *fakeManager
		want string
	}{
		{name: "not installed", mgr: &fakeManager{}, want: "not installed"},
		{name: "stopped", mgr: &fakeManager{installed: true}, want: "not running"},
		{name: "missing pid", mgr: &fakeManager{installed: true, running: true}, want: "no process id"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			err := reloadService(test.mgr, func(string) error {
				called = true
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("reloadService() error = %v, want containing %q", err, test.want)
			}
			if called {
				t.Error("reloadService() signaled an invalid service state")
			}
		})
	}
}

func TestReloadServicePropagatesStatusAndSignalErrors(t *testing.T) {
	statusErr := errors.New("status failed")
	if err := reloadService(&fakeManager{statusErr: statusErr}, func(string) error { return nil }); !errors.Is(err, statusErr) {
		t.Errorf("reloadService() error = %v, want status error", err)
	}

	signalErr := errors.New("signal failed")
	err := reloadService(&fakeManager{installed: true, running: true, pid: "456"}, func(string) error { return signalErr })
	if !errors.Is(err, signalErr) {
		t.Errorf("reloadService() error = %v, want signal error", err)
	}
}
