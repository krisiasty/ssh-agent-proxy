package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/krisiasty/ssh-agent-proxy/internal/config"
	"github.com/krisiasty/ssh-agent-proxy/internal/testutil"
	"golang.org/x/crypto/ssh/agent"
)

// startupFixture runs a Server against a test agent with one group that
// exposes the key commented "allowed".
type startupFixture struct {
	srv    *Server
	socket string
	ready  chan struct{}
	logs   *lockedBuffer
}

func startStartupFixture(t *testing.T, backend *testutil.BlockingAgent, timeout time.Duration) *startupFixture {
	t.Helper()
	dir := testutil.ShortSocketDir(t)
	upstream := testutil.StartAgent(t, filepath.Join(dir, "upstream.sock"), backend)
	f := &startupFixture{socket: filepath.Join(dir, "group.sock"), ready: make(chan struct{}), logs: &lockedBuffer{}}
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	body := fmt.Sprintf("upstream: %q\ngroups:\n  - name: test\n    socket: %q\n    keys:\n      - comment: allowed\n", upstream, f.socket)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	log := slog.New(slog.NewJSONHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f.srv = NewServer(ctx, upstream, 0, log)
	f.srv.startupTimeout = timeout
	f.srv.SetReadyCallback(func() { close(f.ready) })
	result := testutil.RunAsync(func() error { return f.srv.Run(ctx, cfg.Groups) })
	t.Cleanup(func() {
		cancel()
		if testutil.WaitForAsyncStop(t, result, "proxy server") && result.Err() != nil {
			t.Errorf("Run() error = %v, want clean shutdown", result.Err())
		}
	})
	return f
}

func (f *startupFixture) dial(t *testing.T) agent.ExtendedAgent {
	t.Helper()
	var dialer net.Dialer
	conn, err := dialer.DialContext(t.Context(), "unix", f.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return agent.NewClient(conn)
}

func TestServerServesAfterStartupListTimeout(t *testing.T) {
	backend := testutil.NewBlockingAgent(t, testutil.NewKeyring(t))
	addAgentKey(t, backend.ExtendedAgent, "allowed")
	backend.BlockListFrom(1)
	f := startStartupFixture(t, backend, 100*time.Millisecond)

	if !testutil.WaitForEvent(t, f.ready, "readiness after startup listing timeout") {
		return
	}
	if info, err := os.Lstat(f.socket); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("group socket after startup timeout: info=%v err=%v", info, err)
	}
	if got := backend.ListCalls(); got != 1 {
		t.Errorf("startup List requests = %d, want 1 without retry", got)
	}
	if got := f.srv.telemetry.upstreamReconnects.Load(); got != 1 {
		t.Errorf("upstream reconnects = %d, want the timed-out connection replaced once", got)
	}
	warning := findDebugLog(t, decodeDebugLogs(t, f.logs.Bytes()), "initial key listing timed out; deferring until client request", "")
	if warning["timeout"] != "100ms" {
		t.Errorf("timeout warning = %v, want timeout=100ms", warning)
	}

	// Once the agent answers, the first client request resolves the group over
	// the replacement connection.
	backend.Release()
	keys, err := f.dial(t).List()
	if err != nil {
		t.Fatalf("client List() after agent recovery: %v", err)
	}
	if len(keys) != 1 || keys[0].Comment != "allowed" {
		t.Errorf("client List() = %v, want the allowed key", keys)
	}
	if got := backend.ListCalls(); got != 2 {
		t.Errorf("upstream List requests after client List = %d, want 2", got)
	}
}

func TestStartupListTimeoutDoesNotBoundSigning(t *testing.T) {
	backend := testutil.NewBlockingAgent(t, testutil.NewKeyring(t))
	pub := addAgentKey(t, backend.ExtendedAgent, "allowed")
	backend.BlockSign()
	const timeout = 50 * time.Millisecond
	f := startStartupFixture(t, backend, timeout)
	if !testutil.WaitForEvent(t, f.ready, "proxy readiness") {
		return
	}

	client := f.dial(t)
	sign := testutil.RunAsync(func() error {
		_, err := client.Sign(pub, []byte("payload"))
		return err
	})
	if !testutil.WaitForEvent(t, backend.Started(), "stalled signing request") {
		return
	}
	select {
	case <-sign.Done():
		t.Fatalf("signing finished while the agent was still waiting: %v", sign.Err())
	case <-time.After(4 * timeout):
	}
	backend.Release()
	if testutil.WaitForAsyncStop(t, sign, "signing request") && sign.Err() != nil {
		t.Errorf("signing after a wait longer than the startup timeout: %v", sign.Err())
	}
}

// startListWithinClient connects a reconnectClient to backend. The returned
// context is the client's parent, as Server.Run's context is in production;
// canceling it models shutdown.
func startListWithinClient(t *testing.T, backend agent.Agent) (*reconnectClient, *proxyTelemetry, context.Context, context.CancelFunc) {
	t.Helper()
	socket := testutil.StartAgent(t, filepath.Join(testutil.ShortSocketDir(t), "upstream.sock"), backend)
	ctx, cancel := context.WithCancel(t.Context())
	telemetry := &proxyTelemetry{}
	client, err := newReconnectClientWithTelemetry(ctx, socket, slog.New(slog.DiscardHandler), telemetry)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = client.Close(t.Context()) })
	return client, telemetry, ctx, cancel
}

func TestListWithinKeepsAnsweredConnection(t *testing.T) {
	keyring := testutil.NewKeyring(t)
	addAgentKey(t, keyring, "allowed")
	client, telemetry, ctx, _ := startListWithinClient(t, keyring)
	original := client.current.Load()

	keys, err := client.listWithin(ctx, testutil.WaitTimeout)
	if err != nil || len(keys) != 1 {
		t.Fatalf("listWithin() = %v, %v; want one key", keys, err)
	}
	// Releasing the timeout after the answer must not expire the connection.
	if _, err := client.List(); err != nil {
		t.Fatalf("List() after listWithin: %v", err)
	}
	if client.current.Load() != original || telemetry.upstreamReconnects.Load() != 0 {
		t.Error("an answered listing replaced the connection")
	}
}

func TestListWithinReplacesConnectionAfterDeadline(t *testing.T) {
	backend := testutil.NewBlockingAgent(t, testutil.NewKeyring(t))
	backend.BlockListFrom(1)
	client, telemetry, ctx, _ := startListWithinClient(t, backend)
	original := client.current.Load()

	if _, err := client.listWithin(ctx, 50*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("listWithin() error = %v, want deadline exceeded", err)
	}
	if got := backend.ListCalls(); got != 1 {
		t.Errorf("List requests = %d, want 1 without retry", got)
	}
	if client.current.Load() == original || telemetry.upstreamReconnects.Load() != 1 {
		t.Error("the timed-out connection was not replaced")
	}

	backend.Release()
	if _, err := client.List(); err != nil {
		t.Errorf("List() on the replacement connection: %v", err)
	}
}

func TestListWithinDoesNotReplaceConnectionOnShutdown(t *testing.T) {
	backend := testutil.NewBlockingAgent(t, testutil.NewKeyring(t))
	backend.BlockListFrom(1)
	client, telemetry, ctx, shutdown := startListWithinClient(t, backend)
	original := client.current.Load()

	result := testutil.RunAsync(func() error {
		_, err := client.listWithin(ctx, testutil.WaitTimeout)
		return err
	})
	if !testutil.WaitForEvent(t, backend.Started(), "stalled startup listing") {
		return
	}
	shutdown()
	if !testutil.WaitForAsyncStop(t, result, "listing during shutdown") {
		return
	}
	// Either the connection's lifetime hook or the listing deadline interrupts
	// the request first; both must end it without a replacement connection.
	if result.Err() == nil {
		t.Error("listWithin() succeeded during shutdown")
	}
	if client.current.Load() != original || telemetry.upstreamReconnects.Load() != 0 {
		t.Error("shutdown dialed a replacement connection")
	}
}
