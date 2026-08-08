package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunDoesNotLogForegroundConfigError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")

	stdout := os.Stdout
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = write
	t.Cleanup(func() {
		os.Stdout = stdout
	})

	runErr := Run(path, true, Version{Version: "test", Commit: "none", Date: "unknown"})
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(read)
	if err != nil {
		t.Fatal(err)
	}
	if err := read.Close(); err != nil {
		t.Fatal(err)
	}

	if runErr == nil {
		t.Fatal("Run() error = nil, want a configuration error")
	}
	if len(output) != 0 {
		t.Errorf("Run() logged foreground error %q, want no output", output)
	}
}

func TestRunReturnsForegroundProxyStartupError(t *testing.T) {
	path := writeRuntimeConfig(t, filepath.Join(t.TempDir(), "missing-agent.sock"))

	err := run(t.Context(), path, true, Version{Version: "test", Commit: "none", Date: "unknown"})
	if err == nil {
		t.Fatal("run() error = nil, want proxy startup error")
	}
}

func TestRunServiceIdlesAfterProxyStartupError(t *testing.T) {
	path := writeRuntimeConfig(t, filepath.Join(t.TempDir(), "missing-agent.sock"))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, path, false, Version{Version: "test", Commit: "none", Date: "unknown"})
	}()

	select {
	case err := <-done:
		t.Fatalf("run() returned before cancellation with error %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run() error after cancellation = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not stop after context cancellation")
	}
}

func writeRuntimeConfig(t *testing.T, upstream string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := fmt.Sprintf("upstream: %q\ngroups:\n  - name: test\n    socket: %q\n", upstream, filepath.Join(dir, "group.sock"))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
