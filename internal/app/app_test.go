package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/krisiasty/ssh-agent-proxy/internal/config"
	"github.com/krisiasty/ssh-agent-proxy/internal/proxy"
	"github.com/krisiasty/ssh-agent-proxy/internal/testutil"
	"golang.org/x/crypto/ssh/agent"
)

func TestShouldReturnProxyError(t *testing.T) {
	listenerErr := fmt.Errorf("runtime failure: %w", proxy.ErrListenerFailure)
	if !shouldReturnProxyError(false, listenerErr) {
		t.Error("listener failure should be returned so the service supervisor can restart")
	}
	if shouldReturnProxyError(false, errors.New("startup failure")) {
		t.Error("managed-service startup failure should idle")
	}
	if !shouldReturnProxyError(true, errors.New("foreground failure")) {
		t.Error("foreground failure should be returned")
	}
}

func TestRunDoesNotLogForegroundConfigError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")

	_, finish := captureRuntimeLogs(t)
	runErr := Run(path, true, 3*time.Second, Version{Version: "test", Commit: "none", Date: "unknown"})
	entries := finish()

	if runErr == nil {
		t.Fatal("Run() error = nil, want a configuration error")
	}
	if len(entries) != 0 {
		t.Errorf("Run() logged foreground error %v, want no output", entries)
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

	_, finish := captureRuntimeLogs(t)
	runErr := run(t.Context(), path, true, 3*time.Second, Version{Version: "test", Commit: "none", Date: "unknown"})
	if runErr == nil {
		t.Fatal("run() error = nil, want proxy startup error")
	}
	entries := finish()
	if len(entries) != 3 {
		t.Fatalf("startup emitted %d log lines, want 3: %v", len(entries), entries)
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
		upstreamLog["telemetry_sample"] != "1s" || upstreamLog["telemetry_report"] != "10m0s" {
		t.Errorf("upstream log = %v, want starting and upstream path", upstreamLog)
	}
	if _, ok := upstreamLog["config"]; ok {
		t.Errorf("upstream log unexpectedly contains config: %v", upstreamLog)
	}
}

func TestRunServiceIdlesAfterProxyStartupError(t *testing.T) {
	events, _ := captureRuntimeLogs(t)
	path := writeRuntimeConfig(t, filepath.Join(t.TempDir(), "missing-agent.sock"))
	ctx, cancel := context.WithCancel(t.Context())
	done := testutil.RunAsync(func() error {
		return run(ctx, path, false, 3*time.Second, Version{Version: "test", Commit: "none", Date: "unknown"})
	})
	t.Cleanup(func() { cancel(); testutil.WaitForAsyncStop(t, done, "runtime") })
	waitForRuntimeLog(t, events, "proxy startup error")
	waitForRuntimeLog(t, events, "idling until stopped or reloaded; fix the upstream agent and send SIGHUP")
	select {
	case <-done.Done():
		t.Fatalf("run() returned before cancellation with error %v", done.Err())
	default:
	}
	cancel()
	if testutil.WaitForAsyncStop(t, done, "runtime") && done.Err() != nil {
		t.Fatalf("run() error after cancellation = %v, want nil", done.Err())
	}
}

func TestRunReloadsConfigurationAndKeepsServingAfterInvalidReload(t *testing.T) {
	dir := testutil.ShortSocketDir(t)

	upstream := testutil.StartAgent(t, filepath.Join(dir, "upstream.sock"), testutil.NewKeyring(t))
	configPath := filepath.Join(dir, "config.yaml")
	firstSocket := filepath.Join(dir, "first.sock")
	secondSocket := filepath.Join(dir, "second.sock")
	writeReloadConfig(t, configPath, upstream, "first", firstSocket)

	ctx, cancel := context.WithCancel(t.Context())
	reload := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- runWithReload(ctx, reload, configPath, true, 0, Version{Version: "test", Commit: "none", Date: "unknown"})
	}()
	waitForAgentSocket(t, firstSocket)
	var dialer net.Dialer
	persistentConn, err := dialer.DialContext(t.Context(), "unix", firstSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = persistentConn.Close() }()
	if _, err := agent.NewClient(persistentConn).List(); err != nil {
		t.Fatalf("listing through persistent pre-reload connection: %v", err)
	}

	if err := os.WriteFile(configPath, []byte("not: valid: yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reload <- syscall.SIGHUP
	time.Sleep(100 * time.Millisecond)
	waitForAgentSocket(t, firstSocket)

	writeReloadConfig(t, configPath, upstream, "second", secondSocket)
	reload <- syscall.SIGHUP
	waitForAgentSocket(t, secondSocket)
	waitForPathRemoval(t, firstSocket)
	waitForConnectionClose(t, persistentConn)

	secondConn, err := dialer.DialContext(t.Context(), "unix", secondSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = secondConn.Close() }()
	if _, err := agent.NewClient(secondConn).List(); err != nil {
		t.Fatalf("listing through second persistent connection: %v", err)
	}
	failedSocket := filepath.Join(dir, "failed.sock")
	writeReloadConfig(t, configPath, filepath.Join(dir, "missing-upstream.sock"), "failed", failedSocket)
	reload <- syscall.SIGHUP
	waitForConnectionClose(t, secondConn)
	waitForAgentSocket(t, secondSocket)
	if _, err := os.Lstat(failedSocket); !os.IsNotExist(err) {
		t.Errorf("failed replacement left socket %q behind: %v", failedSocket, err)
	}

	cancel()
	if err, ok := testutil.Receive(t, done, "runtime to stop"); ok {
		if err != nil {
			t.Fatalf("runWithReload() error = %v", err)
		}
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

func TestRunReloadInterruptsBlockedUpstreamRequest(t *testing.T) {
	dir := testutil.ShortSocketDir(t)
	backend := testutil.NewBlockingAgent(t, testutil.NewKeyring(t))
	upstream := testutil.StartAgent(t, filepath.Join(dir, "blocked.sock"), backend)
	healthy := testutil.StartAgent(t, filepath.Join(dir, "healthy.sock"), testutil.NewKeyring(t))
	configPath := filepath.Join(dir, "config.yaml")
	socket := filepath.Join(dir, "group.sock")
	writeReloadConfig(t, configPath, upstream, "first", socket)
	ctx, cancel := context.WithCancel(t.Context())
	reload := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- runWithReload(ctx, reload, configPath, false, 0, Version{Version: "test"})
	}()
	t.Cleanup(func() {
		cancel()
		backend.Release()
		if err, ok := testutil.Receive(t, done, "runtime to stop"); ok {
			if err != nil {
				t.Errorf("runWithReload() shutdown error = %v", err)
			}
		}
	})
	waitForAgentSocket(t, socket)
	var dialer net.Dialer
	conn, err := dialer.DialContext(t.Context(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	backend.BlockLists()
	request := make(chan error, 1)
	go func() {
		_, err := agent.NewClient(conn).List()
		request <- err
	}()
	if !testutil.WaitForEvent(t, backend.Started(), "stalled upstream request") {
		return
	}

	// Reuse the same socket to verify that reload releases its ownership lock.
	writeReloadConfig(t, configPath, healthy, "replacement", socket)
	reload <- syscall.SIGHUP
	waitForAgentSocket(t, socket)
	if err, ok := testutil.Receive(t, request, "client request"); ok {
		if err == nil {
			t.Error("blocked request unexpectedly succeeded")
		}
	}
	waitForConnectionClose(t, conn)
}

func TestRunReloadInterruptsBlockedStartup(t *testing.T) {
	for _, replacing := range []bool{false, true} {
		name := "initial startup"
		if replacing {
			name = "replacement startup"
		}
		t.Run(name, func(t *testing.T) {
			dir := testutil.ShortSocketDir(t)
			blocked := testutil.StartAgent(t, filepath.Join(dir, "blocked.sock"), testutil.NewKeyring(t))
			healthy := testutil.StartAgent(t, filepath.Join(dir, "healthy.sock"), testutil.NewKeyring(t))
			gate := newStartupGate(t, blocked)
			gate.Block()
			configPath := filepath.Join(dir, "config.yaml")
			socket := filepath.Join(dir, "group.sock")
			initial := blocked
			if replacing {
				initial = healthy
			}
			writeReloadConfig(t, configPath, initial, "initial", socket)
			ctx, cancel := context.WithCancel(t.Context())
			reload := make(chan os.Signal, 1)
			done := make(chan error, 1)
			go func() {
				done <- runWithServers(ctx, reload, configPath, false, 0, Version{Version: "test"}, gate.newServer)
			}()
			t.Cleanup(func() {
				cancel()
				gate.Release()
				if err, ok := testutil.Receive(t, done, "runtime to stop"); ok {
					if err != nil {
						t.Errorf("runtime shutdown: %v", err)
					}
				}
			})
			if replacing {
				waitForAgentSocket(t, socket)
				writeReloadConfig(t, configPath, blocked, "blocked", socket)
				reload <- syscall.SIGHUP
			}
			if !testutil.WaitForEvent(t, gate.Started(), "stalled runtime startup") {
				return
			}
			writeReloadConfig(t, configPath, healthy, "recovered", socket)
			reload <- syscall.SIGHUP
			// The stalled startup stays blocked until cleanup. Recovery must
			// stop it and serve the new configuration.
			waitForAgentSocket(t, socket)
		})
	}
}

func TestInvalidReloadRestoresLastReadyConfiguration(t *testing.T) {
	events, _ := captureRuntimeLogs(t)
	dir := testutil.ShortSocketDir(t)
	blocked := testutil.StartAgent(t, filepath.Join(dir, "blocked.sock"), testutil.NewKeyring(t))
	healthy := testutil.StartAgent(t, filepath.Join(dir, "healthy.sock"), testutil.NewKeyring(t))
	gate := newStartupGate(t, blocked)
	gate.Block()
	path, socket := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "group.sock")
	writeReloadConfig(t, path, healthy, "ready", socket)
	ctx, cancel := context.WithCancel(t.Context())
	reload, done := make(chan os.Signal, 1), make(chan error, 1)
	go func() { done <- runWithServers(ctx, reload, path, false, 0, Version{Version: "test"}, gate.newServer) }()
	t.Cleanup(func() {
		cancel()
		gate.Release()
		if err, ok := testutil.Receive(t, done, "runtime to stop"); ok {
			if err != nil {
				t.Errorf("shutdown: %v", err)
			}
		}
	})
	waitForAgentSocket(t, socket)
	writeReloadConfig(t, path, blocked, "never-ready", socket)
	reload <- syscall.SIGHUP
	if !testutil.WaitForEvent(t, gate.Started(), "stalled replacement startup") {
		return
	}
	if err := os.WriteFile(path, []byte("not: valid: yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reload <- syscall.SIGHUP
	waitForRuntimeLog(t, events, "previous configuration restored")
	waitForAgentSocket(t, socket)
}

func TestUnreadyInitialConfigurationIsNeverRestored(t *testing.T) {
	for _, foreground := range []bool{false, true} {
		name := "managed"
		if foreground {
			name = "foreground"
		}
		t.Run(name, func(t *testing.T) {
			events, _ := captureRuntimeLogs(t)
			dir := testutil.ShortSocketDir(t)
			blocked := testutil.StartAgent(t, filepath.Join(dir, "blocked.sock"), testutil.NewKeyring(t))
			gate := newStartupGate(t, blocked)
			gate.Block()
			path, socket := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "group.sock")
			writeReloadConfig(t, path, blocked, "never-ready", socket)
			ctx, cancel := context.WithCancel(t.Context())
			reload, done := make(chan os.Signal, 1), make(chan error, 1)
			go func() {
				done <- runWithServers(ctx, reload, path, foreground, 0, Version{Version: "test"}, gate.newServer)
			}()
			finished := false
			t.Cleanup(func() {
				cancel()
				gate.Release()
				if finished {
					return
				}
				if err, ok := testutil.Receive(t, done, "runtime to stop"); ok {
					if err != nil {
						t.Errorf("shutdown: %v", err)
					}
				}
			})
			if !testutil.WaitForEvent(t, gate.Started(), "stalled runtime startup") {
				return
			}
			writeReloadConfig(t, path, filepath.Join(dir, "missing.sock"), "failed", socket)
			reload <- syscall.SIGHUP
			if foreground {
				if err, ok := testutil.Receive(t, done, "runtime to stop"); ok {
					finished = true
					if err == nil {
						t.Error("foreground reload failure returned nil")
					}
				}
			} else {
				waitForRuntimeLog(t, events, "idling until stopped or reloaded; fix the upstream agent and send SIGHUP")
			}
			if stalls := gate.Stalls(); stalls != 1 {
				t.Errorf("unready config was relaunched: stalled startups = %d, want 1", stalls)
			}
		})
	}
}

func TestShutdownPrecedesPendingReload(t *testing.T) {
	_, finish := captureRuntimeLogs(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	reload := make(chan os.Signal, 1)
	reload <- syscall.SIGHUP
	path := writeRuntimeConfig(t, filepath.Join(t.TempDir(), "missing.sock"))
	if err := runWithReload(ctx, reload, path, true, 0, Version{Version: "test"}); err != nil {
		t.Errorf("shutdown error = %v", err)
	}
	if entries := finish(); len(entries) != 0 {
		t.Errorf("canceled startup processed pending work: %v", entries)
	}
}

func TestInvalidReloadKeepsInitialStartup(t *testing.T) {
	for _, foreground := range []bool{false, true} {
		name := "managed"
		if foreground {
			name = "foreground"
		}
		t.Run(name, func(t *testing.T) {
			events, finish := captureRuntimeLogs(t)
			dir := testutil.ShortSocketDir(t)
			upstream := testutil.StartAgent(t, filepath.Join(dir, "upstream.sock"), testutil.NewKeyring(t))
			gate := newStartupGate(t, upstream)
			gate.Block()
			path, socket := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "group.sock")
			writeReloadConfig(t, path, upstream, "initial", socket)
			ctx, cancel := context.WithCancel(t.Context())
			reload := make(chan os.Signal, 1)
			done := testutil.RunAsync(func() error {
				return runWithServers(ctx, reload, path, foreground, 0, Version{Version: "test"}, gate.newServer)
			})
			t.Cleanup(func() {
				cancel()
				gate.Release()
				if testutil.WaitForAsyncStop(t, done, "runtime") && done.Err() != nil {
					t.Errorf("shutdown: %v", done.Err())
				}
			})
			if !testutil.WaitForEvent(t, gate.Started(), "stalled runtime startup") {
				return
			}
			if err := os.WriteFile(path, []byte("not: valid: yaml\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			reload <- syscall.SIGHUP
			waitForRuntimeLog(t, events, "configuration reload failed; keeping current configuration")
			// Readiness must still come from the original runtime, even though
			// the config on disk is invalid and cannot be loaded again.
			gate.Release()
			waitForAgentSocket(t, socket)
			cancel()
			if !testutil.WaitForAsyncStop(t, done, "runtime") {
				return
			}
			for _, entry := range finish() {
				if entry["msg"] == "configuration reloaded" || entry["msg"] == "configuration reload requested" {
					t.Errorf("invalid reload logged a successful reload: %v", entry)
				}
			}
		})
	}
}

func TestInvalidReloadLeavesFailedRollbackIdle(t *testing.T) {
	events, finish := captureRuntimeLogs(t)
	dir := testutil.ShortSocketDir(t)
	upstream := testutil.StartAgent(t, filepath.Join(dir, "upstream.sock"), testutil.NewKeyring(t))
	path, socket := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "group.sock")
	writeReloadConfig(t, path, upstream, "ready", socket)
	ctx, cancel := context.WithCancel(t.Context())
	reload, done := make(chan os.Signal, 1), make(chan error, 1)
	go func() { done <- runWithReload(ctx, reload, path, false, 0, Version{Version: "test"}) }()
	finished := false
	t.Cleanup(func() {
		cancel()
		if !finished {
			if err, ok := testutil.Receive(t, done, "runtime to stop"); ok && err != nil {
				t.Errorf("shutdown: %v", err)
			}
		}
	})
	waitForAgentSocket(t, socket)
	// Keep the existing upstream connection alive but prevent rollback from
	// dialing it again. Both the candidate and the single rollback fail.
	if err := os.Remove(upstream); err != nil {
		t.Fatal(err)
	}
	writeReloadConfig(t, path, filepath.Join(dir, "missing.sock"), "failed", socket)
	reload <- syscall.SIGHUP
	waitForRuntimeLog(t, events, "restoring previous configuration failed")
	waitForRuntimeLog(t, events, "idling until stopped or reloaded; fix the problem and send SIGHUP")
	if err := os.WriteFile(path, []byte("not: valid: yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reload <- syscall.SIGHUP
	waitForRuntimeLog(t, events, "configuration reload failed; remaining idle")
	cancel()
	if err, ok := testutil.Receive(t, done, "runtime to stop"); ok {
		finished = true
		if err != nil {
			t.Errorf("shutdown: %v", err)
		}
	}
	launches := 0
	for _, entry := range finish() {
		if entry["msg"] == "configuration loaded" {
			launches++
		}
	}
	if launches != 3 {
		t.Errorf("runtime launches = %d, want initial, candidate and one rollback", launches)
	}
}

func TestInvalidReloadKeepsPendingRollback(t *testing.T) {
	for _, scenario := range []struct {
		name         string
		failRollback bool
		foreground   bool
	}{
		{name: "restored"},
		{name: "failed managed rollback", failRollback: true},
		{name: "failed foreground rollback", failRollback: true, foreground: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			events, finish := captureRuntimeLogs(t)
			dir := testutil.ShortSocketDir(t)
			upstream := testutil.StartAgent(t, filepath.Join(dir, "upstream.sock"), testutil.NewKeyring(t))
			gate := newStartupGate(t, upstream)
			path, socket := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "group.sock")
			writeReloadConfig(t, path, upstream, "original", socket)
			ctx, cancel := context.WithCancel(t.Context())
			reload := make(chan os.Signal, 1)
			done := testutil.RunAsync(func() error {
				return runWithServers(ctx, reload, path, scenario.foreground, 0, Version{Version: "test"}, gate.newServer)
			})
			t.Cleanup(func() {
				cancel()
				gate.Release()
				testutil.WaitForAsyncStop(t, done, "runtime")
			})
			waitForAgentSocket(t, socket)
			gate.Block()
			missing := filepath.Join(dir, "failed-candidate.sock")
			writeReloadConfig(t, path, missing, "failed", socket)
			reload <- syscall.SIGHUP
			if !testutil.WaitForEvent(t, gate.Started(), "rollback startup") {
				return
			}
			if err := os.WriteFile(path, []byte("not: valid: yaml\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			reload <- syscall.SIGHUP
			waitForRuntimeLog(t, events, "configuration reload failed; keeping current configuration")
			if scenario.failRollback {
				// Startup is still blocked, so take the released group socket to
				// force a distinct rollback error after the invalid reload.
				var lc net.ListenConfig
				listener, err := lc.Listen(t.Context(), "unix", socket)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
			}
			gate.Release()
			if !scenario.failRollback {
				waitForRuntimeLog(t, events, "previous configuration restored")
				waitForAgentSocket(t, socket)
			} else if !scenario.foreground {
				waitForRuntimeLog(t, events, "restoring previous configuration failed")
			}
			if !scenario.foreground {
				cancel()
			}
			if !testutil.WaitForAsyncStop(t, done, "runtime") {
				return
			}
			if scenario.foreground {
				if err := done.Err(); !errors.Is(err, proxy.ErrSocketInUse) || !strings.Contains(err.Error(), missing) {
					t.Errorf("rollback error = %v, want both candidate dial and rollback bind failures", err)
				}
			} else if err := done.Err(); err != nil {
				t.Errorf("shutdown: %v", err)
			}
			launches, rollbackErrors := 0, 0
			for _, entry := range finish() {
				switch entry["msg"] {
				case "configuration loaded":
					launches++
				case "restoring previous configuration failed":
					rollbackErrors++
					if cause, ok := entry["err"].(string); !ok || !strings.Contains(cause, missing) {
						t.Errorf("rollback log lost the candidate failure: %v", entry)
					}
				}
			}
			if launches != 3 {
				t.Errorf("runtime launches = %d, want initial, candidate and one rollback", launches)
			}
			if scenario.failRollback && !scenario.foreground && rollbackErrors != 1 {
				t.Errorf("rollback failure logs = %d, want 1", rollbackErrors)
			}
		})
	}
}

func TestStalledRollbackStaysInterruptible(t *testing.T) {
	for _, exit := range []string{"shutdown", "repeated invalid reload", "valid reload"} {
		t.Run(exit, func(t *testing.T) {
			events, _ := captureRuntimeLogs(t)
			dir := testutil.ShortSocketDir(t)
			shared := testutil.StartAgent(t, filepath.Join(dir, "shared.sock"), testutil.NewKeyring(t))
			healthy := testutil.StartAgent(t, filepath.Join(dir, "healthy.sock"), testutil.NewKeyring(t))
			gate := newStartupGate(t, shared)
			path, socket := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "group.sock")
			writeReloadConfig(t, path, shared, "original", socket)
			ctx, cancel := context.WithCancel(t.Context())
			reload := make(chan os.Signal, 1)
			done := testutil.RunAsync(func() error {
				return runWithServers(ctx, reload, path, false, 0, Version{Version: "test"}, gate.newServer)
			})
			t.Cleanup(func() {
				cancel()
				gate.Release()
				testutil.WaitForAsyncStop(t, done, "runtime")
			})

			// The replacement and the restored rollback share the upstream, so
			// both stall in startup.
			waitForAgentSocket(t, socket)
			gate.Block()
			writeReloadConfig(t, path, shared, "replacement", socket)
			reload <- syscall.SIGHUP
			if !testutil.WaitForEvent(t, gate.Started(), "stalled replacement startup") {
				return
			}
			if err := os.WriteFile(path, []byte("not: valid: yaml\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			reload <- syscall.SIGHUP
			waitForRuntimeLog(t, events, "restoring previous configuration")
			const stalled = 2
			deadline := time.Now().Add(testutil.WaitTimeout)
			for gate.Stalls() < stalled && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if stalls := gate.Stalls(); stalls != stalled {
				t.Fatalf("restored rollback did not stall in startup: stalled startups = %d, want %d", stalls, stalled)
			}

			switch exit {
			case "repeated invalid reload":
				for range 3 {
					reload <- syscall.SIGHUP
					waitForRuntimeLog(t, events, "configuration reload failed; keeping current configuration")
				}
				if stalls := gate.Stalls(); stalls != stalled {
					t.Errorf("invalid reload relaunched the rollback: stalled startups = %d, want %d", stalls, stalled)
				}
			case "valid reload":
				writeReloadConfig(t, path, healthy, "recovered", socket)
				reload <- syscall.SIGHUP
				waitForRuntimeLog(t, events, "configuration reloaded")
				waitForAgentSocket(t, socket)
			}

			// Shut down while the rollback is still stalled.
			cancel()
			if !testutil.WaitForAsyncStop(t, done, "runtime with stalled startup") {
				return
			}
			if err := done.Err(); err != nil {
				t.Errorf("shutdown: %v", err)
			}
		})
	}
}

func TestHungUpstreamDoesNotDelayReload(t *testing.T) {
	events, _ := captureRuntimeLogs(t)
	dir := testutil.ShortSocketDir(t)
	backend := testutil.NewBlockingAgent(t, testutil.NewKeyring(t))
	backend.BlockLists()
	hung := testutil.StartAgent(t, filepath.Join(dir, "hung.sock"), backend)
	healthy := testutil.StartAgent(t, filepath.Join(dir, "healthy.sock"), testutil.NewKeyring(t))
	path, socket := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "group.sock")
	writeReloadConfig(t, path, healthy, "original", socket)
	ctx, cancel := context.WithCancel(t.Context())
	reload := make(chan os.Signal, 1)
	done := testutil.RunAsync(func() error {
		return runWithReload(ctx, reload, path, false, 0, Version{Version: "test"})
	})
	t.Cleanup(func() {
		cancel()
		backend.Release()
		testutil.WaitForAsyncStop(t, done, "runtime")
	})
	waitForAgentSocket(t, socket)

	// The replacement binds its socket and becomes the last ready
	// configuration while its startup key listing is still unanswered.
	writeReloadConfig(t, path, hung, "hung", socket)
	reload <- syscall.SIGHUP
	waitForRuntimeLog(t, events, "configuration reloaded")
	if !testutil.WaitForEvent(t, backend.Started(), "unanswered startup listing") {
		return
	}
	if info, err := os.Lstat(socket); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("group socket while the upstream is hung: info=%v err=%v", info, err)
	}
	cancel()
	if testutil.WaitForAsyncStop(t, done, "runtime with hung upstream") && done.Err() != nil {
		t.Errorf("shutdown: %v", done.Err())
	}
}

func TestRuntimeLogCaptureRetainsBufferedEvents(t *testing.T) {
	events, finish := captureRuntimeLogs(t)
	encoder := json.NewEncoder(os.Stdout)
	for range 256 {
		if err := encoder.Encode(map[string]any{"msg": "startup detail"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := encoder.Encode(map[string]any{"msg": "previous configuration restored"}); err != nil {
		t.Fatal(err)
	}
	// Finish decoding before waiting so the old bounded event buffer would
	// deterministically have dropped the target event.
	if entries := finish(); len(entries) != 257 {
		t.Fatalf("captured %d entries, want 257", len(entries))
	}
	waitForRuntimeLog(t, events, "previous configuration restored")
}

// startupGate holds runtimes for one upstream in startup until Release, or
// until the runtime is stopped. A hung upstream no longer delays readiness, so
// the gate stands in for a runtime whose startup is slow, such as an upstream
// dial that takes its full timeout. Like such a runtime, a held runtime owns
// its group socket locks: a replacement launched before it stopped would fail
// to take them.
type startupGate struct {
	upstream    string
	blocked     atomic.Bool
	stalls      atomic.Int64
	started     chan struct{}
	release     chan struct{}
	startOnce   sync.Once
	releaseOnce sync.Once
}

// newStartupGate returns a gate for runtimes that use upstream. It holds
// nothing until Block is called; pass its newServer to runWithServers.
func newStartupGate(t *testing.T, upstream string) *startupGate {
	t.Helper()
	gate := &startupGate{upstream: upstream, started: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(gate.Release)
	return gate
}

// newServer is a serverFactory that gates runtimes using the gate's upstream.
func (g *startupGate) newServer(ctx context.Context, upstream string, cacheTTL time.Duration, log *slog.Logger) runtimeServer {
	srv := newProxyServer(ctx, upstream, cacheTTL, log)
	if upstream != g.upstream {
		return srv
	}
	return &gatedServer{runtimeServer: srv, gate: g}
}

// Block holds every later startup until Release.
func (g *startupGate) Block() { g.blocked.Store(true) }

// Started is closed when the first startup is held.
func (g *startupGate) Started() <-chan struct{} { return g.started }

// Release lets held and later startups continue. It is safe to call repeatedly.
func (g *startupGate) Release() { g.releaseOnce.Do(func() { close(g.release) }) }

// Stalls reports how many startups the gate has held.
func (g *startupGate) Stalls() int64 { return g.stalls.Load() }

type gatedServer struct {
	runtimeServer
	gate *startupGate
}

func (s *gatedServer) Run(ctx context.Context, groups []config.Group) error {
	if !s.gate.blocked.Load() {
		return s.runtimeServer.Run(ctx, groups)
	}
	releaseLocks, err := holdSocketLocks(groups)
	if err != nil {
		return err
	}
	s.gate.stalls.Add(1)
	s.gate.startOnce.Do(func() { close(s.gate.started) })
	select {
	case <-s.gate.release:
		releaseLocks()
	case <-ctx.Done():
		releaseLocks()
		return nil
	}
	return s.runtimeServer.Run(ctx, groups)
}

type runtimeLogCapture struct {
	mu      sync.Mutex
	entries []map[string]any
	next    int
	changed chan struct{}
}

func captureRuntimeLogs(t *testing.T) (*runtimeLogCapture, func() []map[string]any) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = writer
	events := &runtimeLogCapture{changed: make(chan struct{}, 1)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		decoder := json.NewDecoder(reader)
		for {
			var entry map[string]any
			if err := decoder.Decode(&entry); err != nil {
				if !errors.Is(err, io.EOF) {
					t.Errorf("decoding runtime log: %v", err)
				}
				return
			}
			events.mu.Lock()
			events.entries = append(events.entries, entry)
			events.mu.Unlock()
			select {
			case events.changed <- struct{}{}:
			default:
			}
		}
	}()
	var once sync.Once
	finish := func() []map[string]any {
		once.Do(func() {
			os.Stdout = original
			if err := writer.Close(); err != nil {
				t.Error(err)
			}
			<-done
			if err := reader.Close(); err != nil {
				t.Error(err)
			}
		})
		return events.entries
	}
	t.Cleanup(func() { finish() })
	return events, finish
}

func waitForRuntimeLog(t *testing.T, events *runtimeLogCapture, message string) {
	t.Helper()
	timer := time.NewTimer(testutil.WaitTimeout)
	defer timer.Stop()
	for {
		events.mu.Lock()
		for events.next < len(events.entries) {
			entry := events.entries[events.next]
			events.next++
			if entry["msg"] == message {
				events.mu.Unlock()
				return
			}
		}
		events.mu.Unlock()
		select {
		case <-events.changed:
		case <-timer.C:
			t.Fatalf("timed out waiting for runtime log %q", message)
		}
	}
}

func writeReloadConfig(t *testing.T, path, upstream, group, socket string) {
	t.Helper()
	body := fmt.Sprintf("upstream: %q\ngroups:\n  - name: %q\n    socket: %q\n", upstream, group, socket)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitForAgentSocket(t *testing.T, socket string) {
	t.Helper()
	deadline := time.Now().Add(testutil.WaitTimeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		_, err := proxy.ListAgentKeys(ctx, socket)
		cancel()
		if err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("agent socket %q did not become ready", socket)
}

func waitForPathRemoval(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(testutil.WaitTimeout)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("path %q was not removed", path)
}

func waitForConnectionClose(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(testutil.WaitTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("pre-reload client connection remained open")
	} else {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatal("pre-reload client connection was not closed")
		}
	}
}
