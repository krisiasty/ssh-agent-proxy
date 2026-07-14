package service

import (
	"reflect"
	"testing"
)

// fakeManager records the lifecycle calls made against it.
type fakeManager struct {
	installed bool
	calls     []string
}

func (f *fakeManager) Install() error          { f.calls = append(f.calls, "install"); return nil }
func (f *fakeManager) Uninstall() error        { f.calls = append(f.calls, "uninstall"); return nil }
func (f *fakeManager) Reinstall() error        { return reinstall(f) }
func (f *fakeManager) Start() error            { return nil }
func (f *fakeManager) Stop() error             { return nil }
func (f *fakeManager) Restart() error          { return nil }
func (f *fakeManager) Status() (Status, error) { return Status{Installed: f.installed}, nil }
func (f *fakeManager) LogHint() string         { return "" }

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
