package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

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
	cancel context.CancelFunc
	result *testutil.AsyncResult
	// joined is closed when the first client waits for a refresh in flight.
	joined chan struct{}
}

func startStartupFixture(t *testing.T, backend *testutil.BlockingAgent) *startupFixture {
	t.Helper()
	dir := testutil.ShortSocketDir(t)
	upstream := testutil.StartAgent(t, filepath.Join(dir, "upstream.sock"), backend)
	f := &startupFixture{
		socket: filepath.Join(dir, "group.sock"),
		ready:  make(chan struct{}),
		logs:   &lockedBuffer{},
		joined: make(chan struct{}),
	}
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
	f.cancel = cancel
	log := slog.New(slog.NewJSONHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f.srv = NewServer(ctx, upstream, 0, log)
	f.srv.SetReadyCallback(func() { close(f.ready) })
	var joinOnce sync.Once
	f.srv.refreshJoined = func() { joinOnce.Do(func() { close(f.joined) }) }
	f.result = testutil.RunAsync(func() error { return f.srv.Run(ctx, cfg.Groups) })
	t.Cleanup(func() {
		cancel()
		if testutil.WaitForAsyncStop(t, f.result, "proxy server") && f.result.Err() != nil {
			t.Errorf("Run() error = %v, want clean shutdown", f.result.Err())
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

func TestServerServesWhileStartupListingIsUnanswered(t *testing.T) {
	backend := testutil.NewBlockingAgent(t, testutil.NewKeyring(t))
	addAgentKey(t, backend.ExtendedAgent, "allowed")
	backend.BlockListFrom(1)
	f := startStartupFixture(t, backend)

	if !testutil.WaitForEvent(t, backend.Started(), "unanswered startup listing") {
		return
	}
	if !testutil.WaitForEvent(t, f.ready, "readiness while the startup listing is unanswered") {
		return
	}
	if info, err := os.Lstat(f.socket); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("group socket while the startup listing is unanswered: info=%v err=%v", info, err)
	}

	// A client that arrives first, for example while the agent shows an unlock
	// prompt, waits for the startup listing instead of sending its own.
	client := f.dial(t)
	var keys []*agent.Key
	request := testutil.RunAsync(func() error {
		var err error
		keys, err = client.List()
		return err
	})
	if !testutil.WaitForEvent(t, f.joined, "client waiting for the startup listing") {
		return
	}
	backend.Release()
	if !testutil.WaitForAsyncStop(t, request, "client List") {
		return
	}
	if err := request.Err(); err != nil {
		t.Fatalf("client List() after the agent answered: %v", err)
	}
	if len(keys) != 1 || keys[0].Comment != "allowed" {
		t.Errorf("client List() = %v, want the allowed key", keys)
	}
	if got := backend.ListCalls(); got != 1 {
		t.Errorf("upstream List requests = %d, want the client to share the startup listing", got)
	}
	waitForLogMessage(t, f.logs, "group keys resolved")
}

func TestShutdownDuringStartupListingIsNotAnUpstreamFailure(t *testing.T) {
	backend := testutil.NewBlockingAgent(t, testutil.NewKeyring(t))
	addAgentKey(t, backend.ExtendedAgent, "allowed")
	backend.BlockListFrom(1)
	f := startStartupFixture(t, backend)
	if !testutil.WaitForEvent(t, f.ready, "proxy readiness") {
		return
	}
	if !testutil.WaitForEvent(t, backend.Started(), "unanswered startup listing") {
		return
	}
	client := f.dial(t)
	request := testutil.RunAsync(func() error {
		_, err := client.List()
		return err
	})
	if !testutil.WaitForEvent(t, f.joined, "client waiting for the startup listing") {
		return
	}

	// Shutdown interrupts the listing, which must still complete the startup
	// refresh: a client left waiting for it would keep Run from returning.
	f.cancel()
	if !testutil.WaitForAsyncStop(t, f.result, "proxy server with unanswered startup listing") {
		return
	}
	if err := f.result.Err(); err != nil {
		t.Errorf("Run() error = %v, want clean shutdown", err)
	}
	if testutil.WaitForAsyncStop(t, request, "client waiting for the startup listing") && request.Err() == nil {
		t.Error("client List() succeeded although the startup listing was interrupted")
	}
	for _, entry := range decodeDebugLogs(t, f.logs.Bytes()) {
		if entry["msg"] == "initial config key resolution failed; deferring until client request" {
			t.Errorf("interrupted startup listing was logged as an upstream failure: %v", entry)
		}
	}
}
