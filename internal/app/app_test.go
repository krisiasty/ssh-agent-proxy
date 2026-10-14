package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/krisiasty/ssh-agent-proxy/internal/proxy"
	"golang.org/x/crypto/ssh/agent"
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
		upstreamLog["telemetry_sample"] != "1s" || upstreamLog["telemetry_report"] != "10m0s" {
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

func TestRunReloadsConfigurationAndKeepsServingAfterInvalidReload(t *testing.T) {
	dir := shortSocketDir(t)

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
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runWithReload() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runWithReload() did not stop after cancellation")
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
	dir := shortSocketDir(t)
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
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("runWithReload() shutdown error = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("runtime did not stop during cleanup")
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
	select {
	case <-backend.blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("client did not reach stalled upstream")
	}

	// Reuse the same socket to verify that reload releases its ownership lock.
	writeReloadConfig(t, configPath, healthy, "replacement", socket)
	reload <- syscall.SIGHUP
	waitForAgentSocket(t, socket)
	select {
	case err := <-request:
		if err == nil {
			t.Error("blocked request unexpectedly succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reload did not interrupt the old upstream request")
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
			dir := shortSocketDir(t)
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
				select {
				case err := <-done:
					if err != nil {
						t.Errorf("runtime shutdown: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Error("runtime did not stop during cleanup")
				}
			})
			if replacing {
				waitForAgentSocket(t, socket)
				writeReloadConfig(t, configPath, blocked, "blocked", socket)
				reload <- syscall.SIGHUP
			}
			select {
			case <-backend.blocked:
			case <-time.After(5 * time.Second):
				t.Fatal("startup did not reach the stalled upstream")
			}
			writeReloadConfig(t, configPath, healthy, "recovered", socket)
			reload <- syscall.SIGHUP
			// The stalled agent stays blocked until cleanup. Recovery must use
			// the new configuration and release the previous socket lock.
			waitForAgentSocket(t, socket)
		})
	}
}

func TestRuntimeWaitReadyRejectsAbortedStartup(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		canceled bool
		ready    bool
	}{
		{name: "nil exit before readiness"},
		{name: "canceled before readiness", canceled: true},
		{name: "cancellation races readiness", canceled: true, ready: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ready := make(chan struct{})
			if scenario.ready {
				close(ready)
			}
			if scenario.canceled {
				cancel()
			}
			instance := &runtimeInstance{cancel: func() {}, done: make(chan error, 1), log: slog.New(slog.DiscardHandler)}
			instance.done <- nil
			err := instance.waitReady(ctx, ready, nil)
			if err == nil {
				t.Fatal("aborted startup reported successful readiness")
			}
			if scenario.canceled && !errors.Is(err, context.Canceled) {
				t.Errorf("startup error = %v, want cancellation", err)
			}
			if err := instance.stop(); err != nil {
				t.Errorf("clean aborted runtime stop = %v", err)
			}
		})
	}
}

type reloadBlockingAgent struct {
	agent.Agent
	stall     atomic.Bool
	blocked   chan struct{}
	release   chan struct{}
	blockOnce sync.Once
}

func (a *reloadBlockingAgent) List() ([]*agent.Key, error) {
	if a.stall.Load() {
		a.blockOnce.Do(func() { close(a.blocked) })
		<-a.release
	}
	return a.Agent.List()
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
	deadline := time.Now().Add(5 * time.Second)
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
	deadline := time.Now().Add(5 * time.Second)
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
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
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

func shortSocketDir(t *testing.T) string {
	t.Helper()
	//nolint:usetesting // Unix socket paths on macOS cannot safely fit beneath t.TempDir().
	dir, err := os.MkdirTemp("/tmp", "ssh-agent-proxy-reload-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("removing test directory: %v", err)
		}
	})
	return dir
}
