package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krisiasty/ssh-agent-proxy/internal/config"
	"github.com/krisiasty/ssh-agent-proxy/internal/testutil"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestAcceptLoopTreatsShutdownClosureAsClean(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv := NewServer(t.Context(), "unused", 0, log)
	listener := newScriptedListener(net.ErrClosed)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := srv.acceptLoop(ctx, listener, config.Group{Name: "work", Socket: "/tmp/work.sock"}, nil, nil)
	if err != nil {
		t.Fatalf("acceptLoop() error = %v, want nil", err)
	}
	if output.Len() != 0 {
		t.Errorf("shutdown closure logged %q, want no output", output.String())
	}
}

func TestAcceptLoopRetriesTemporaryFailure(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv := NewServer(t.Context(), "unused", 0, log)
	temporaryErr := &injectedTemporaryError{err: errors.New("file descriptor pressure")}
	listener := newScriptedListener(temporaryErr, net.ErrClosed)

	err := srv.acceptLoop(t.Context(), listener, config.Group{Name: "work", Socket: "/tmp/work.sock"}, nil, nil)
	if err != nil {
		t.Fatalf("acceptLoop() error = %v, want nil", err)
	}
	if got := listener.AcceptCalls(); got != 2 {
		t.Fatalf("Accept() calls = %d, want 2", got)
	}
	entries := decodeDebugLogs(t, output.Bytes())
	if len(entries) != 1 {
		t.Fatalf("temporary failure logs = %d, want 1: %v", len(entries), entries)
	}
	entry := entries[0]
	if entry["level"] != "WARN" || entry["msg"] != "temporary listener accept failure; retrying" ||
		entry["group"] != "work" || entry["socket"] != "/tmp/work.sock" || entry["retry_in"] != "5ms" {
		t.Errorf("temporary failure log = %v", entry)
	}
}

func TestAcceptLoopReportsTerminalFailure(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv := NewServer(t.Context(), "unused", 0, log)
	terminalErr := errors.New("terminal accept error")
	listener := newScriptedListener(terminalErr)

	err := srv.acceptLoop(t.Context(), listener, config.Group{Name: "home", Socket: "/tmp/home.sock"}, nil, nil)
	if !errors.Is(err, ErrListenerFailure) {
		t.Fatalf("acceptLoop() error = %v, want ErrListenerFailure", err)
	}
	if !errors.Is(err, terminalErr) {
		t.Fatalf("acceptLoop() error = %v, want wrapped terminal error", err)
	}
	entries := decodeDebugLogs(t, output.Bytes())
	if len(entries) != 1 {
		t.Fatalf("terminal failure logs = %d, want 1: %v", len(entries), entries)
	}
	entry := entries[0]
	if entry["level"] != "ERROR" || entry["msg"] != "listener accept failure" ||
		entry["group"] != "home" || entry["socket"] != "/tmp/home.sock" || entry["err"] != terminalErr.Error() {
		t.Errorf("terminal failure log = %v", entry)
	}
}

func TestServerRunPropagatesTerminalAcceptFailure(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	srv := NewServer(t.Context(), "unused", 0, log)
	terminalErr := errors.New("terminal accept error")
	listener := newScriptedListener(terminalErr)
	srv.listen = func(context.Context, string) (net.Listener, error) {
		return listener, nil
	}

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		if err := serverConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("closing upstream server connection: %v", err)
		}
	})
	srv.newUpstreamClient = func(ctx context.Context, _ string, logger *slog.Logger, telemetry *proxyTelemetry) (*reconnectClient, error) {
		rc := newTestReconnectClient(ctx, logger, telemetry, &upstreamConn{client: testutil.NewKeyring(t), conn: clientConn})
		return rc, nil
	}

	socket := filepath.Join(t.TempDir(), "group.sock")
	err := srv.Run(t.Context(), []config.Group{{Name: "work", Socket: socket}})
	if !errors.Is(err, ErrListenerFailure) {
		t.Fatalf("Server.Run() error = %v, want ErrListenerFailure", err)
	}
	if !errors.Is(err, terminalErr) {
		t.Fatalf("Server.Run() error = %v, want wrapped terminal error", err)
	}
	if !listener.Closed() {
		t.Error("Server.Run() did not close listeners after terminal failure")
	}
}

type injectedTemporaryError struct {
	err error
}

func (e *injectedTemporaryError) Error() string   { return e.err.Error() }
func (e *injectedTemporaryError) Unwrap() error   { return e.err }
func (e *injectedTemporaryError) Temporary() bool { return true }

type scriptedListener struct {
	mu          sync.Mutex
	errs        []error
	acceptCalls int
	closed      bool
}

func newScriptedListener(errs ...error) *scriptedListener {
	return &scriptedListener{errs: append([]error(nil), errs...)}
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.acceptCalls++
	if len(l.errs) == 0 {
		return nil, net.ErrClosed
	}
	err := l.errs[0]
	l.errs = l.errs[1:]
	return nil, err
}

func (l *scriptedListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return nil
}

func (l *scriptedListener) Addr() net.Addr {
	return &net.UnixAddr{Name: "injected", Net: "unix"}
}

func (l *scriptedListener) AcceptCalls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.acceptCalls
}

func (l *scriptedListener) Closed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

func TestFormatKeysUsesSingleFieldEntries(t *testing.T) {
	key := &agent.Key{
		Format:  "ssh-test",
		Blob:    []byte("public key"),
		Comment: `work "laptop"`,
	}
	want := fmt.Sprintf("[1] ssh-test\n  - comment: %s\n  - sha256: %s\n  - md5: %s\n",
		strconv.Quote(key.Comment),
		strconv.Quote(ssh.FingerprintSHA256(key)),
		strconv.Quote("MD5:"+ssh.FingerprintLegacyMD5(key)),
	)

	if got := formatKeys([]*agent.Key{key}); got != want {
		t.Errorf("formatKeys() = %q, want %q", got, want)
	}
}

func TestServerRunWithoutEnabledGroupsDoesNotDialUpstream(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	missingUpstream := filepath.Join(t.TempDir(), "missing-agent.sock")
	srv := NewServer(t.Context(), missingUpstream, 0, slog.New(slog.DiscardHandler))

	t.Run("no groups", func(t *testing.T) {
		t.Parallel()

		if err := srv.Run(ctx, nil); err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
	})

	t.Run("all groups disabled", func(t *testing.T) {
		t.Parallel()

		disabled := false
		groups := []config.Group{{
			Name:    "disabled",
			Enabled: &disabled,
			Socket:  filepath.Join(t.TempDir(), "disabled.sock"),
		}}
		if err := srv.Run(ctx, groups); err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
	})
}

func TestServerRunSignalsReadyWithoutEnabledGroups(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	srv := NewServer(t.Context(), "unused", 0, slog.New(slog.DiscardHandler))
	var readyCalls atomic.Int64
	srv.SetReadyCallback(func() {
		readyCalls.Add(1)
	})

	if err := srv.Run(ctx, nil); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if got := readyCalls.Load(); got != 1 {
		t.Fatalf("ready callback calls = %d, want 1", got)
	}
}

func TestServerServesBeforeUpstreamAgentStarts(t *testing.T) {
	dir := testutil.ShortSocketDir(t)
	upstream := filepath.Join(dir, "upstream.sock")
	socket := filepath.Join(dir, "group.sock")
	var output lockedBuffer
	log := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv := NewServer(t.Context(), upstream, 0, log)
	ready := make(chan struct{})
	srv.SetReadyCallback(func() { close(ready) })
	ctx, cancel := context.WithCancel(t.Context())
	done := testutil.RunAsync(func() error { return srv.Run(ctx, []config.Group{{Name: "test", Socket: socket}}) })
	t.Cleanup(func() {
		cancel()
		if testutil.WaitForAsyncStop(t, done, "proxy server") && done.Err() != nil {
			t.Errorf("Run() error = %v, want clean shutdown", done.Err())
		}
	})

	// No agent is listening yet: the socket is still served, and resolution
	// is deferred until a client request.
	if !testutil.WaitForEvent(t, ready, "readiness without an upstream agent") {
		return
	}
	waitForLogMessage(t, &output, "initial config key resolution failed; deferring until client request")

	// Once the agent starts, the next client request connects to it.
	testutil.StartAgent(t, upstream, testutil.NewKeyring(t))
	var dialer net.Dialer
	conn, err := dialer.DialContext(t.Context(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := agent.NewClient(conn).List(); err != nil {
		t.Fatalf("client List() after the agent started: %v", err)
	}
	waitForLogMessage(t, &output, "upstream connected")
}

func TestServerRunReportsForeignCancellationError(t *testing.T) {
	t.Parallel()

	srv := NewServer(t.Context(), "unused", 0, slog.New(slog.DiscardHandler))
	foreign := fmt.Errorf("dependency gave up: %w", context.Canceled)
	srv.newUpstreamClient = func(context.Context, string, *slog.Logger, *proxyTelemetry) (*reconnectClient, error) {
		return nil, foreign
	}
	groups := []config.Group{{Name: "test", Socket: filepath.Join(testutil.ShortSocketDir(t), "group.sock")}}

	// Run's own context is live, so context.Canceled from a dependency is a
	// startup failure, not a clean shutdown.
	if err := srv.Run(t.Context(), groups); !errors.Is(err, foreign) {
		t.Fatalf("Run() error = %v, want %v", err, foreign)
	}
}

func TestServerRunResolvesGroupsWithSingleStartupList(t *testing.T) {
	var output lockedBuffer
	log := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv := NewServer(t.Context(), "unused", 0, log)
	srv.SetReadyCallback(func() {
		log.Info("server ready callback")
	})
	keyring := testutil.NewKeyring(t)
	first := addAgentKey(t, keyring, "shared")
	addAgentKey(t, keyring, "shared")
	up := &countingListAgent{ExtendedAgent: keyring}
	clientConn, serverConn := net.Pipe()
	srv.newUpstreamClient = func(ctx context.Context, _ string, log *slog.Logger, telemetry *proxyTelemetry) (*reconnectClient, error) {
		rc := newTestReconnectClient(ctx, log, telemetry, &upstreamConn{client: up, conn: clientConn})
		return rc, nil
	}

	ctx, cancel := context.WithCancel(t.Context())
	var done *testutil.AsyncResult
	t.Cleanup(func() {
		cancel()
		if done != nil {
			testutil.WaitForAsyncStop(t, done, "proxy server")
		}
		if err := serverConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("closing upstream server connection: %v", err)
		}
	})

	socket := filepath.Join(testutil.ShortSocketDir(t), "group.sock")
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	cfgData := fmt.Sprintf(`upstream: /tmp/upstream.sock
groups:
  - name: test
    socket: %s
    keys:
      - comment: shared
      - sha256: %s
      - comment: missing
      - md5: MD5:00:00
`, strconv.Quote(socket), strconv.Quote(ssh.FingerprintSHA256(first)))
	if err := os.WriteFile(cfgPath, []byte(cfgData), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	done = testutil.RunAsync(func() error { return srv.Run(ctx, cfg.Groups) })
	waitForSocket(t, socket, done, nil)
	waitForLogMessage(t, &output, "group keys resolved")
	if got := up.listCalls.Load(); got != 1 {
		t.Errorf("upstream List() calls during startup = %d, want 1", got)
	}

	cancel()
	if err := done.Err(); err != nil {
		t.Fatalf("Server.Run() error = %v, want nil", err)
	}
	if err := serverConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closing upstream server connection: %v", err)
	}

	entries := decodeDebugLogs(t, output.Bytes())
	resolved := findDebugLog(t, entries, "group keys resolved", "")
	if resolved["group"] != "test" || resolved["keys"] != float64(2) {
		t.Errorf("group keys resolved log = %v, want 2 distinct matched keys", resolved)
	}
	resolution := findDebugLog(t, entries, "config keys resolved", "")
	if resolution["trigger"] != "startup" || resolution["configured_keys"] != float64(4) ||
		resolution["upstream_keys"] != float64(2) || resolution["resolved_keys"] != float64(2) {
		t.Errorf("startup resolution log = %v", resolution)
	}
	servingIndex, readyIndex, resolvedIndex, readyCalls := -1, -1, -1, 0
	for i, entry := range entries {
		switch entry["msg"] {
		case "serving group":
			servingIndex = i
		case "server ready callback":
			readyIndex = i
			readyCalls++
		case "group keys resolved":
			resolvedIndex = i
		}
	}
	if readyCalls != 1 || readyIndex <= servingIndex {
		t.Errorf("ready callback calls = %d at index %d, serving group index = %d", readyCalls, readyIndex, servingIndex)
	}
	if resolvedIndex <= servingIndex {
		t.Errorf("group keys resolved at index %d, want after serving group at index %d", resolvedIndex, servingIndex)
	}

	warnings := make(map[float64]string)
	for _, entry := range entries {
		if entry["msg"] != "configured key selector matched no upstream key" {
			continue
		}
		if entry["group"] != "test" {
			t.Errorf("unmatched selector warning group = %v, want test", entry["group"])
		}
		if _, ok := entry["selector_value"]; ok {
			t.Errorf("unmatched selector warning leaks selector value: %v", entry)
		}
		index, indexOK := entry["config_index"].(float64)
		selectorType, typeOK := entry["selector_type"].(string)
		if !indexOK || !typeOK {
			t.Errorf("unmatched selector warning has invalid attributes: %v", entry)
			continue
		}
		warnings[index] = selectorType
	}
	wantWarnings := map[float64]string{3: "comment", 4: "md5"}
	if !reflect.DeepEqual(warnings, wantWarnings) {
		t.Errorf("unmatched selector warnings = %v, want %v", warnings, wantWarnings)
	}
}

func TestServerRunDefersResolutionAfterStartupListFailure(t *testing.T) {
	var output lockedBuffer
	log := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv := NewServer(t.Context(), "unused", 0, log)
	keyring := testutil.NewKeyring(t)
	up := &toggleListAgent{ExtendedAgent: keyring}
	up.fail.Store(true)
	clientConn, serverConn := net.Pipe()
	srv.newUpstreamClient = func(ctx context.Context, _ string, logger *slog.Logger, telemetry *proxyTelemetry) (*reconnectClient, error) {
		rc := newTestReconnectClient(ctx, logger, telemetry, &upstreamConn{client: up, conn: clientConn})
		return rc, nil
	}

	ctx, cancel := context.WithCancel(t.Context())
	var done *testutil.AsyncResult
	t.Cleanup(func() {
		cancel()
		if done != nil {
			testutil.WaitForAsyncStop(t, done, "proxy server")
		}
		if err := serverConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("closing upstream server connection: %v", err)
		}
	})
	socket := filepath.Join(testutil.ShortSocketDir(t), "group.sock")
	done = testutil.RunAsync(func() error { return srv.Run(ctx, []config.Group{{Name: "test", Socket: socket}}) })
	waitForSocket(t, socket, done, nil)
	waitForLogMessage(t, &output, "initial config key resolution failed; deferring until client request")
	if got := up.listCalls.Load(); got != 1 {
		t.Errorf("upstream List() calls during failed startup resolution = %d, want 1", got)
	}

	up.fail.Store(false)
	var clientDialer net.Dialer
	conn, err := clientDialer.DialContext(t.Context(), "unix", socket)
	if err != nil {
		cancel()
		t.Fatalf("dialing group socket: %v", err)
	}
	listed, listErr := agent.NewClient(conn).List()
	if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
		t.Errorf("closing group client: %v", closeErr)
	}
	if listErr != nil {
		cancel()
		t.Fatalf("client List() after upstream recovery: %v", listErr)
	}
	if len(listed) != 0 {
		t.Errorf("client List() keys = %d, want empty group", len(listed))
	}
	if got := up.listCalls.Load(); got != 2 {
		t.Errorf("upstream List() calls after client retry = %d, want 2", got)
	}

	cancel()
	if err := done.Err(); err != nil {
		t.Fatalf("Server.Run() error = %v, want nil", err)
	}
	if err := serverConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closing upstream server connection: %v", err)
	}

	if got := srv.telemetry.upstreamCalls.Load(); got != 3 {
		t.Errorf("injected client upstream calls = %d, want failed list, successful list and close", got)
	}
	if got := srv.telemetry.upstreamErrors.Load(); got != 1 {
		t.Errorf("injected client upstream errors = %d, want 1", got)
	}

	entries := decodeDebugLogs(t, output.Bytes())
	warning := findDebugLog(t, entries, "initial config key resolution failed; deferring until client request", "")
	if _, ok := warning["err"].(string); !ok {
		t.Errorf("startup resolution warning = %v, want error", warning)
	}
	serving := findDebugLog(t, entries, "serving group", "")
	if _, ok := serving["keys"]; ok {
		t.Errorf("serving group log reports a key count after failed resolution: %v", serving)
	}
}

// waitForLogMessage waits until output holds a JSON log entry with message.
// Startup key resolution logs from the background, after readiness.
func waitForLogMessage(t *testing.T, output *lockedBuffer, message string) {
	t.Helper()
	deadline := time.Now().Add(testutil.WaitTimeout)
	for time.Now().Before(deadline) {
		for _, entry := range decodeDebugLogs(t, output.Bytes()) {
			if entry["msg"] == message {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for log %q", message)
}

// lockedBuffer allows tests to inspect logs while asynchronous connection
// handlers may still be finishing their final log writes.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buf.Bytes())
}

type countingListAgent struct {
	agent.ExtendedAgent
	listCalls atomic.Int64
}

func (a *countingListAgent) List() ([]*agent.Key, error) {
	a.listCalls.Add(1)
	return a.ExtendedAgent.List()
}

// waitForSocket waits until path is a socket and fails early if its owner
// stops first. diagnostic, when non-nil, adds context to failure messages.
func waitForSocket(t *testing.T, path string, owner *testutil.AsyncResult, diagnostic func() string) {
	t.Helper()
	details := func() string {
		if diagnostic == nil {
			return ""
		}
		return "\n" + diagnostic()
	}
	deadline := time.NewTimer(testutil.WaitTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		} else if err != nil && !os.IsNotExist(err) {
			t.Fatalf("inspecting socket %q: %v", path, err)
		}
		select {
		case <-owner.Done():
			t.Fatalf("socket owner stopped before serving %q: %v%s", path, owner.Err(), details())
		case <-deadline.C:
			t.Fatalf("timed out waiting for socket %q%s", path, details())
		case <-ticker.C:
		}
	}
}

func TestListenRefusesLiveSocket(t *testing.T) {
	dir := testutil.ShortSocketDir(t)
	path := filepath.Join(dir, "group.sock")
	live := listenUnix(t, path)

	srv := NewServer(t.Context(), "unused", 0, slog.New(slog.DiscardHandler))
	ln, err := srv.listen(t.Context(), path)
	if ln != nil {
		closeListener(t, ln)
		t.Fatal("listen() returned a listener for an already-live socket")
	}
	if !errors.Is(err, ErrSocketInUse) {
		t.Fatalf("listen() error = %v, want ErrSocketInUse", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("live socket was removed: %v", err)
	}

	closeListener(t, live)
	removeSocket(t, path)
}

func TestListenReplacesOnlyStaleSocket(t *testing.T) {
	dir := testutil.ShortSocketDir(t)
	path := filepath.Join(dir, "group.sock")
	stale := listenUnix(t, path)
	closeListener(t, stale)
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("creating stale socket: %v", err)
	}

	srv := NewServer(t.Context(), "unused", 0, slog.New(slog.DiscardHandler))
	ln, err := srv.listen(t.Context(), path)
	if err != nil {
		t.Fatalf("listen() error = %v, want nil", err)
	}
	closeListener(t, ln)
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("owned socket remains after close: %v", err)
	}
}

func TestListenerClosePreservesReplacementSocket(t *testing.T) {
	dir := testutil.ShortSocketDir(t)
	path := filepath.Join(dir, "group.sock")
	srv := NewServer(t.Context(), "unused", 0, slog.New(slog.DiscardHandler))

	owned, err := srv.listen(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		closeListener(t, owned)
		t.Fatalf("removing original socket path: %v", err)
	}
	replacement := listenUnix(t, path)

	closeListener(t, owned)
	conn, err := dialer.DialContext(t.Context(), "unix", path)
	if err != nil {
		closeListener(t, replacement)
		removeSocket(t, path)
		t.Fatalf("replacement socket was removed or stopped: %v", err)
	}
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("closing replacement probe: %v", err)
	}
	closeListener(t, replacement)
	removeSocket(t, path)
}

func TestSecondServerProcessCannotTakeOverSocket(t *testing.T) {
	dir := testutil.ShortSocketDir(t)
	path := filepath.Join(dir, "group.sock")
	lock, err := acquireSocketLock(path)
	if err != nil {
		t.Fatal(err)
	}
	lockHeld := true
	t.Cleanup(func() {
		if lockHeld {
			if err := lock.Close(); err != nil {
				t.Errorf("closing parent socket lock during cleanup: %v", err)
			}
		}
	})

	runSocketLockHelper(t, path, "blocked")
	if err := lock.Close(); err != nil {
		t.Fatalf("closing parent socket lock: %v", err)
	}
	lockHeld = false
	runSocketLockHelper(t, path, "available")
}

func TestSocketLockHelper(t *testing.T) {
	path := os.Getenv("SSH_AGENT_PROXY_TEST_LOCK_PATH")
	want := os.Getenv("SSH_AGENT_PROXY_TEST_LOCK_EXPECT")
	if path == "" || want == "" {
		t.Skip("subprocess helper")
	}

	switch want {
	case "blocked":
		srv := NewServer(t.Context(), "unused", 0, slog.New(slog.DiscardHandler))
		upstreamCalled := false
		srv.newUpstreamClient = func(context.Context, string, *slog.Logger, *proxyTelemetry) (*reconnectClient, error) {
			upstreamCalled = true
			return nil, errors.New("upstream constructor must not run while socket is locked")
		}
		err := srv.Run(t.Context(), []config.Group{{Name: "test", Socket: path}})
		if !errors.Is(err, ErrSocketInUse) {
			t.Fatalf("second Server.Run() error = %v, want ErrSocketInUse", err)
		}
		if upstreamCalled {
			t.Fatal("second Server.Run() contacted upstream before acquiring its socket lock")
		}
	case "available":
		lock, err := acquireSocketLock(path)
		if err != nil {
			t.Fatalf("acquireSocketLock() error = %v, want nil", err)
		}
		if lock == nil {
			t.Fatal("acquireSocketLock() lock = nil, want a lock")
		}
		if closeErr := lock.Close(); closeErr != nil {
			t.Fatalf("closing acquired lock: %v", closeErr)
		}
	default:
		t.Fatalf("unknown helper expectation %q", want)
	}
}

func runSocketLockHelper(t *testing.T, path, expectation string) {
	t.Helper()
	//nolint:gosec // G204: the executable is the current test binary and every argument is fixed.
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSocketLockHelper$")
	cmd.Env = append(os.Environ(),
		"SSH_AGENT_PROXY_TEST_LOCK_PATH="+path,
		"SSH_AGENT_PROXY_TEST_LOCK_EXPECT="+expectation,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("socket lock subprocess failed: %v\n%s", err, output)
	}
}

func listenUnix(t *testing.T, path string) net.Listener {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	unixListener, ok := ln.(*net.UnixListener)
	if !ok {
		closeListener(t, ln)
		t.Fatalf("net.Listen() returned %T, want *net.UnixListener", ln)
	}
	unixListener.SetUnlinkOnClose(false)
	return unixListener
}

func closeListener(t *testing.T, ln net.Listener) {
	t.Helper()
	if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("closing listener: %v", err)
	}
}

func removeSocket(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Errorf("removing socket: %v", err)
	}
}
