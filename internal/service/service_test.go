package service

import (
	"errors"
	"os"
	"path/filepath"
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

// writeExecutable creates a file standing in for an executable at path, with
// its directories. Only its existence and identity matter to these tests.
func writeExecutable(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// linkBinary creates <prefix>/bin/<name> pointing at target, as Homebrew does.
func linkBinary(t *testing.T, prefix, target string) string {
	t.Helper()
	link := filepath.Join(prefix, "bin", filepath.Base(target))
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	return link
}

func TestStableExecutableUsesHomebrewBinLink(t *testing.T) {
	for _, layout := range []struct {
		name    string
		version string
	}{
		{name: "cask", version: "Caskroom/ssh-agent-proxy/1.2.3/ssh-agent-proxy"},
		{name: "formula", version: "Cellar/ssh-agent-proxy/1.2.3/bin/ssh-agent-proxy"},
	} {
		t.Run(layout.name, func(t *testing.T) {
			prefix := t.TempDir()
			versioned := writeExecutable(t, filepath.Join(prefix, layout.version))
			link := linkBinary(t, prefix, versioned)
			if got := stableExecutable(versioned); got != link {
				t.Errorf("stableExecutable(%q) = %q, want the upgrade-stable link %q", versioned, got, link)
			}
		})
	}
}

func TestStableExecutableKeepsVersionedPathWithoutMatchingLink(t *testing.T) {
	t.Run("no link", func(t *testing.T) {
		prefix := t.TempDir()
		versioned := writeExecutable(t, filepath.Join(prefix, "Caskroom/ssh-agent-proxy/1.2.3/ssh-agent-proxy"))
		if got := stableExecutable(versioned); got != versioned {
			t.Errorf("stableExecutable() = %q, want %q", got, versioned)
		}
	})
	t.Run("link to another version", func(t *testing.T) {
		prefix := t.TempDir()
		versioned := writeExecutable(t, filepath.Join(prefix, "Caskroom/ssh-agent-proxy/1.2.3/ssh-agent-proxy"))
		other := writeExecutable(t, filepath.Join(prefix, "Caskroom/ssh-agent-proxy/2.0.0/ssh-agent-proxy"))
		linkBinary(t, prefix, other)
		if got := stableExecutable(versioned); got != versioned {
			t.Errorf("stableExecutable() = %q, want the running version %q", got, versioned)
		}
	})
	t.Run("not a package layout", func(t *testing.T) {
		binary := writeExecutable(t, filepath.Join(t.TempDir(), "opt/tools/ssh-agent-proxy"))
		if got := stableExecutable(binary); got != binary {
			t.Errorf("stableExecutable() = %q, want %q", got, binary)
		}
	})
}

func TestCheckProgram(t *testing.T) {
	present := writeExecutable(t, filepath.Join(t.TempDir(), "ssh-agent-proxy"))
	missing := filepath.Join(t.TempDir(), "Caskroom/ssh-agent-proxy/0.9.0/ssh-agent-proxy")
	for _, tc := range []struct {
		name    string
		status  Status
		wantErr bool
	}{
		{name: "present", status: Status{Installed: true, Program: present}},
		{name: "not installed", status: Status{Program: missing}},
		{name: "unknown program", status: Status{Installed: true}},
		{name: "removed by upgrade", status: Status{Installed: true, Program: missing}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckProgram(tc.status)
			if (err != nil) != tc.wantErr {
				t.Fatalf("CheckProgram() error = %v, want error %t", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "-reinstall") {
				t.Errorf("CheckProgram() error = %q, want a -reinstall hint", err)
			}
		})
	}
}

func TestSamePathFollowsHomebrewLink(t *testing.T) {
	prefix := t.TempDir()
	versioned := writeExecutable(t, filepath.Join(prefix, "Caskroom/ssh-agent-proxy/1.2.3/ssh-agent-proxy"))
	link := linkBinary(t, prefix, versioned)
	if !SamePath(link, versioned) {
		t.Error("SamePath() = false for a link and its target")
	}
	other := writeExecutable(t, filepath.Join(prefix, "Caskroom/ssh-agent-proxy/2.0.0/ssh-agent-proxy"))
	if SamePath(link, other) {
		t.Error("SamePath() = true for different versions")
	}
}
