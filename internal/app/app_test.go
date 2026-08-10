package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/krisiasty/ssh-agent-proxy/internal/proxy"
)

func TestShouldReturnProxyError(t *testing.T) {
	listenerErr := fmt.Errorf("runtime failure: %w", proxy.ErrListenerFailure)
	if !shouldReturnProxyError(t.Context(), false, listenerErr) {
		t.Error("listener failure should be returned so the service supervisor can restart")
	}
	if shouldReturnProxyError(t.Context(), false, errors.New("startup failure")) {
		t.Error("managed-service startup failure should idle")
	}
	if !shouldReturnProxyError(t.Context(), true, errors.New("foreground failure")) {
		t.Error("foreground failure should be returned")
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if !shouldReturnProxyError(ctx, false, errors.New("shutdown failure")) {
		t.Error("failure during context cancellation should be returned")
	}
}

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

	runErr := Run(path, true, 3*time.Second, Version{Version: "test", Commit: "none", Date: "unknown"})
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

	err := run(t.Context(), path, true, 3*time.Second, Version{Version: "test", Commit: "none", Date: "unknown"})
	if err == nil {
		t.Fatal("run() error = nil, want proxy startup error")
	}
}

func TestRunLogsConfigBeforeUpstream(t *testing.T) {
	upstream := filepath.Join(t.TempDir(), "missing-agent.sock")
	path := writeRuntimeConfig(t, upstream)

	stdout := os.Stdout
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = write
	t.Cleanup(func() {
		os.Stdout = stdout
	})

	runErr := run(t.Context(), path, true, 3*time.Second, Version{Version: "test", Commit: "none", Date: "unknown"})
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
		t.Fatal("run() error = nil, want proxy startup error")
	}

	lines := bytes.Split(bytes.TrimSpace(output), []byte{'\n'})
	if len(lines) != 3 {
		t.Fatalf("startup emitted %d log lines, want 3:\n%s", len(lines), output)
	}
	entries := make([]map[string]any, 0, len(lines))
	for i, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("startup log line %d is not valid JSON: %v\n%s", i+1, err, line)
		}
		entries = append(entries, entry)
	}
	configLog := entries[1]
	if configLog["msg"] != "configuration loaded" ||
		configLog["config"] != path ||
		configLog["groups"] != float64(1) {
		t.Errorf("config log = %v, want configuration path and group count", configLog)
	}
	if _, ok := configLog["upstream"]; ok {
		t.Errorf("config log unexpectedly contains upstream: %v", configLog)
	}
	upstreamLog := entries[2]
	if upstreamLog["msg"] != "starting" || upstreamLog["upstream"] != upstream || upstreamLog["cache_seconds"] != float64(3) ||
		upstreamLog["telemetry_sample_interval"] != "1s" || upstreamLog["telemetry_report_interval"] != "10m0s" {
		t.Errorf("upstream log = %v, want starting and upstream path", upstreamLog)
	}
	if _, ok := upstreamLog["config"]; ok {
		t.Errorf("upstream log unexpectedly contains config: %v", upstreamLog)
	}
}

func TestRunServiceIdlesAfterProxyStartupError(t *testing.T) {
	path := writeRuntimeConfig(t, filepath.Join(t.TempDir(), "missing-agent.sock"))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, path, false, 3*time.Second, Version{Version: "test", Commit: "none", Date: "unknown"})
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
