package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

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

	upstream := startTestAgent(t, filepath.Join(dir, "upstream.sock"))
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

func startTestAgent(t *testing.T, socket string) string {
	t.Helper()
	return startTestAgentWithBackend(t, socket, agent.NewKeyring())
}

func startTestAgentWithBackend(t *testing.T, socket string, backend agent.Agent) string {
	t.Helper()
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(t.Context(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(agentConn net.Conn) {
				defer func() { _ = agentConn.Close() }()
				_ = agent.ServeAgent(backend, agentConn)
			}(conn)
		}
	}()
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("closing test agent: %v", err)
		}
		<-done
	})
	return socket
}

func TestRunReloadInterruptsBlockedUpstreamRequest(t *testing.T) {
	dir := testutil.ShortSocketDir(t)
	backend := &reloadBlockingAgent{Agent: agent.NewKeyring(), blocked: make(chan struct{}), release: make(chan struct{})}
	upstream := startTestAgentWithBackend(t, filepath.Join(dir, "blocked.sock"), backend)
	healthy := startTestAgent(t, filepath.Join(dir, "healthy.sock"))
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
		close(backend.release)
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
	backend.stall.Store(true)
	request := make(chan error, 1)
	go func() {
		_, err := agent.NewClient(conn).List()
		request <- err
	}()
	if !testutil.WaitForEvent(t, backend.blocked, "stalled upstream request") {
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
			backend := &reloadBlockingAgent{Agent: agent.NewKeyring(), blocked: make(chan struct{}), release: make(chan struct{})}
			backend.stall.Store(true)
			blocked := startTestAgentWithBackend(t, filepath.Join(dir, "blocked.sock"), backend)
			healthy := startTestAgent(t, filepath.Join(dir, "healthy.sock"))
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
				done <- runWithReload(ctx, reload, configPath, false, 0, Version{Version: "test"})
			}()
			t.Cleanup(func() {
				cancel()
				close(backend.release)
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
			if !testutil.WaitForEvent(t, backend.blocked, "stalled upstream request") {
				return
			}
			writeReloadConfig(t, configPath, healthy, "recovered", socket)
			reload <- syscall.SIGHUP
			// The stalled agent stays blocked until cleanup. Recovery must use
			// the new configuration and release the previous socket lock.
			waitForAgentSocket(t, socket)
		})
	}
}

type reloadBlockingAgent struct {
	agent.Agent
	listCalls atomic.Int32
	stall     atomic.Bool
	blocked   chan struct{}
	release   chan struct{}
	blockOnce sync.Once
}

func (a *reloadBlockingAgent) List() ([]*agent.Key, error) {
	a.listCalls.Add(1)
	if a.stall.Load() {
		a.blockOnce.Do(func() { close(a.blocked) })
		<-a.release
	}
	return a.Agent.List()
}

func TestInvalidReloadRestoresLastReadyConfiguration(t *testing.T) {
	events, _ := captureRuntimeLogs(t)
	dir := testutil.ShortSocketDir(t)
	backend := &reloadBlockingAgent{Agent: agent.NewKeyring(), blocked: make(chan struct{}), release: make(chan struct{})}
	backend.stall.Store(true)
	blocked := startTestAgentWithBackend(t, filepath.Join(dir, "blocked.sock"), backend)
	healthy := startTestAgent(t, filepath.Join(dir, "healthy.sock"))
	path, socket := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "group.sock")
	writeReloadConfig(t, path, healthy, "ready", socket)
	ctx, cancel := context.WithCancel(t.Context())
	reload, done := make(chan os.Signal, 1), make(chan error, 1)
	go func() { done <- runWithReload(ctx, reload, path, false, 0, Version{Version: "test"}) }()
	t.Cleanup(func() {
		cancel()
		close(backend.release)
		if err, ok := testutil.Receive(t, done, "runtime to stop"); ok {
			if err != nil {
				t.Errorf("shutdown: %v", err)
			}
		}
	})
	waitForAgentSocket(t, socket)
	writeReloadConfig(t, path, blocked, "never-ready", socket)
	reload <- syscall.SIGHUP
	if !testutil.WaitForEvent(t, backend.blocked, "stalled upstream request") {
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
			backend := &reloadBlockingAgent{Agent: agent.NewKeyring(), blocked: make(chan struct{}), release: make(chan struct{})}
			backend.stall.Store(true)
			blocked := startTestAgentWithBackend(t, filepath.Join(dir, "blocked.sock"), backend)
			path, socket := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "group.sock")
			writeReloadConfig(t, path, blocked, "never-ready", socket)
			ctx, cancel := context.WithCancel(t.Context())
			reload, done := make(chan os.Signal, 1), make(chan error, 1)
			go func() { done <- runWithReload(ctx, reload, path, foreground, 0, Version{Version: "test"}) }()
			finished := false
			t.Cleanup(func() {
				cancel()
				close(backend.release)
				if finished {
					return
				}
				if err, ok := testutil.Receive(t, done, "runtime to stop"); ok {
					if err != nil {
						t.Errorf("shutdown: %v", err)
					}
				}
			})
			if !testutil.WaitForEvent(t, backend.blocked, "stalled upstream request") {
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
			if calls := backend.listCalls.Load(); calls != 1 {
				t.Errorf("unready config was retried: List calls = %d, want 1", calls)
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
			backend := &reloadBlockingAgent{Agent: agent.NewKeyring(), blocked: make(chan struct{}), release: make(chan struct{})}
			backend.stall.Store(true)
			upstream := startTestAgentWithBackend(t, filepath.Join(dir, "upstream.sock"), backend)
			path, socket := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "group.sock")
			writeReloadConfig(t, path, upstream, "initial", socket)
			ctx, cancel := context.WithCancel(t.Context())
			reload := make(chan os.Signal, 1)
			done := testutil.RunAsync(func() error { return runWithReload(ctx, reload, path, foreground, 0, Version{Version: "test"}) })
			var release sync.Once
			t.Cleanup(func() {
				cancel()
				release.Do(func() { close(backend.release) })
				if testutil.WaitForAsyncStop(t, done, "runtime") && done.Err() != nil {
					t.Errorf("shutdown: %v", done.Err())
				}
			})
			if !testutil.WaitForEvent(t, backend.blocked, "stalled upstream request") {
				return
			}
			if err := os.WriteFile(path, []byte("not: valid: yaml\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			reload <- syscall.SIGHUP
			waitForRuntimeLog(t, events, "configuration reload failed; keeping current configuration")
			// Readiness must still come from the original runtime, even though
			// the config on disk is invalid and cannot be loaded again.
			release.Do(func() { close(backend.release) })
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
	upstream := startTestAgent(t, filepath.Join(dir, "upstream.sock"))
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
			backend := &reloadBlockingAgent{Agent: agent.NewKeyring(), blocked: make(chan struct{}), release: make(chan struct{})}
			upstream := startTestAgentWithBackend(t, filepath.Join(dir, "upstream.sock"), backend)
			path, socket := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "group.sock")
			writeReloadConfig(t, path, upstream, "original", socket)
			ctx, cancel := context.WithCancel(t.Context())
			reload := make(chan os.Signal, 1)
			done := testutil.RunAsync(func() error {
				return runWithReload(ctx, reload, path, scenario.foreground, 0, Version{Version: "test"})
			})
			var release sync.Once
			t.Cleanup(func() {
				cancel()
				release.Do(func() { close(backend.release) })
				testutil.WaitForAsyncStop(t, done, "runtime")
			})
			waitForAgentSocket(t, socket)
			backend.stall.Store(true)
			missing := filepath.Join(dir, "failed-candidate.sock")
			writeReloadConfig(t, path, missing, "failed", socket)
			reload <- syscall.SIGHUP
			if !testutil.WaitForEvent(t, backend.blocked, "rollback startup") {
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
			release.Do(func() { close(backend.release) })
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
