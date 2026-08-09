package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krisiasty/ssh-agent-proxy/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

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
	srv := NewServer(missingUpstream, 0, slog.New(slog.DiscardHandler))

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

func TestServerRunReturnsInitialDialError(t *testing.T) {
	t.Parallel()

	missingUpstream := filepath.Join(t.TempDir(), "missing-agent.sock")
	srv := NewServer(missingUpstream, 0, slog.New(slog.DiscardHandler))
	groups := []config.Group{{Name: "test", Socket: filepath.Join(t.TempDir(), "group.sock")}}

	err := srv.Run(t.Context(), groups)
	if err == nil {
		t.Fatal("Run() error = nil, want initial dial error")
	}
	if !strings.Contains(err.Error(), "initial upstream connection") {
		t.Fatalf("Run() error = %q, want initial upstream connection context", err)
	}
}

func TestServerRunDoesNotListUpstreamAtStartup(t *testing.T) {
	srv := NewServer("unused", 0, slog.New(slog.DiscardHandler))
	keyring, ok := agent.NewKeyring().(agent.ExtendedAgent)
	if !ok {
		t.Fatal("agent.NewKeyring does not implement agent.ExtendedAgent")
	}
	up := &countingListAgent{ExtendedAgent: keyring}
	clientConn, serverConn := net.Pipe()
	srv.newUpstreamClient = func(_ context.Context, _ string, log *slog.Logger) (*reconnectClient, error) {
		rc := &reconnectClient{upstream: "unused", log: log}
		rc.current.Store(&upstreamConn{client: up, conn: clientConn})
		return rc, nil
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	stopped := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Error("Server.Run() did not stop during cleanup")
		}
		if err := serverConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("closing upstream server connection: %v", err)
		}
	})

	socket := filepath.Join(shortSocketDir(t), "group.sock")
	groups := []config.Group{{Name: "test", Socket: socket}}
	go func() {
		done <- srv.Run(ctx, groups)
		close(stopped)
	}()
	waitForSocket(t, socket, done)
	if got := up.listCalls.Load(); got != 0 {
		t.Errorf("upstream List() calls during startup = %d, want 0", got)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Server.Run() error = %v, want nil", err)
	}
	if err := serverConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closing upstream server connection: %v", err)
	}
}

type countingListAgent struct {
	agent.ExtendedAgent
	listCalls atomic.Int64
}

func (a *countingListAgent) List() ([]*agent.Key, error) {
	a.listCalls.Add(1)
	return a.ExtendedAgent.List()
}

func waitForSocket(t *testing.T, path string, done <-chan error) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		} else if err != nil && !os.IsNotExist(err) {
			t.Fatalf("inspecting group socket: %v", err)
		}
		select {
		case err := <-done:
			t.Fatalf("Server.Run() returned before serving a socket: %v", err)
		case <-deadline.C:
			t.Fatal("timed out waiting for group socket")
		case <-ticker.C:
		}
	}
}

func TestListenRefusesLiveSocket(t *testing.T) {
	dir := shortSocketDir(t)
	path := filepath.Join(dir, "group.sock")
	live := listenUnix(t, path)

	srv := NewServer("unused", 0, slog.New(slog.DiscardHandler))
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
	dir := shortSocketDir(t)
	path := filepath.Join(dir, "group.sock")
	stale := listenUnix(t, path)
	closeListener(t, stale)
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("creating stale socket: %v", err)
	}

	srv := NewServer("unused", 0, slog.New(slog.DiscardHandler))
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
	dir := shortSocketDir(t)
	path := filepath.Join(dir, "group.sock")
	srv := NewServer("unused", 0, slog.New(slog.DiscardHandler))

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
	dir := shortSocketDir(t)
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
		srv := NewServer("unused", 0, slog.New(slog.DiscardHandler))
		upstreamCalled := false
		srv.newUpstreamClient = func(context.Context, string, *slog.Logger) (*reconnectClient, error) {
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

func shortSocketDir(t *testing.T) string {
	t.Helper()
	//nolint:usetesting // Unix socket paths on macOS cannot safely fit beneath t.TempDir().
	dir, err := os.MkdirTemp("/tmp", "ssh-agent-proxy-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("removing socket test directory: %v", err)
		}
	})
	return dir
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
