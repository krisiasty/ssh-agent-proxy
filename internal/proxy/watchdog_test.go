package proxy

import (
	"log/slog"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krisiasty/ssh-agent-proxy/internal/testutil"
	"golang.org/x/crypto/ssh/agent"
)

func startWatchdogClient(t *testing.T, backend agent.Agent, timeout time.Duration) (*reconnectClient, *proxyTelemetry) {
	t.Helper()
	socket := testutil.StartAgent(t, filepath.Join(testutil.ShortSocketDir(t), "upstream.sock"), backend)
	telemetry := &proxyTelemetry{}
	client, err := newReconnectClientWithTelemetry(t.Context(), socket, slog.New(slog.DiscardHandler), telemetry)
	if err != nil {
		t.Fatal(err)
	}
	client.requestTimeout = timeout
	t.Cleanup(func() { _ = client.Close(t.Context()) })
	return client, telemetry
}

func wantUnanswered(t *testing.T, err error, request string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "left a request unanswered") {
		t.Errorf("%s error = %v, want unanswered-request error", request, err)
	}
}

func TestWatchdogDropsConnectionWithUnansweredList(t *testing.T) {
	backend := testutil.NewBlockingAgent(t, testutil.NewKeyring(t))
	addAgentKey(t, backend.ExtendedAgent, "allowed")
	backend.BlockListFrom(1)
	client, telemetry := startWatchdogClient(t, backend, 50*time.Millisecond)
	first, err := client.connection()
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.List()
	wantUnanswered(t, err, "List()")
	if got := backend.ListCalls(); got != 1 {
		t.Errorf("List requests = %d, want 1 without retry", got)
	}
	if client.current.Load() != nil || telemetry.upstreamReconnects.Load() != 0 {
		t.Error("the stuck connection was not dropped for a later dial")
	}

	// Once the agent answers again, the next request dials a fresh connection.
	backend.Release()
	keys, err := client.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("List() after the agent recovered = %v, %v; want one key", keys, err)
	}
	if current := client.current.Load(); current == nil || current == first {
		t.Error("recovery did not use a new connection")
	}
}

func TestWatchdogFailsRequestsQueuedBehindUnansweredOne(t *testing.T) {
	backend := testutil.NewBlockingAgent(t, testutil.NewKeyring(t))
	backend.BlockListFrom(1)
	client, _ := startWatchdogClient(t, backend, 500*time.Millisecond)
	if _, err := client.connection(); err != nil {
		t.Fatal(err)
	}
	stuck := testutil.RunAsync(func() error {
		_, err := client.List()
		return err
	})
	if !testutil.WaitForEvent(t, backend.Started(), "unanswered request") {
		return
	}
	queued := testutil.RunAsync(func() error {
		_, err := client.List()
		return err
	})
	if !testutil.WaitForAsyncStop(t, stuck, "unanswered request") || !testutil.WaitForAsyncStop(t, queued, "queued request") {
		return
	}
	wantUnanswered(t, stuck.Err(), "unanswered List()")
	wantUnanswered(t, queued.Err(), "queued List()")
	// The agent serves a connection in order and never read the queued request.
	if got := backend.ListCalls(); got != 1 {
		t.Errorf("List requests that reached the agent = %d, want 1", got)
	}
}

func TestWatchdogDropsConnectionWithUnansweredSign(t *testing.T) {
	backend := testutil.NewBlockingAgent(t, testutil.NewKeyring(t))
	pub := addAgentKey(t, backend.ExtendedAgent, "allowed")
	backend.BlockSign()
	client, telemetry := startWatchdogClient(t, backend, 50*time.Millisecond)

	_, err := client.SignWithFlags(pub, []byte("payload"), 0)
	wantUnanswered(t, err, "SignWithFlags()")
	if client.current.Load() != nil || telemetry.upstreamReconnects.Load() != 0 {
		t.Error("the stuck connection was not dropped for a later dial")
	}

	backend.Release()
	if _, err := client.SignWithFlags(pub, []byte("payload"), 0); err != nil {
		t.Errorf("SignWithFlags() after the agent recovered: %v", err)
	}
}

func TestWatchdogLeavesAnsweredConnectionAlone(t *testing.T) {
	client, _ := startWatchdogClient(t, testutil.NewKeyring(t), 50*time.Millisecond)
	if _, err := client.List(); err != nil {
		t.Fatal(err)
	}
	first := client.current.Load()
	time.Sleep(150 * time.Millisecond)
	if current := client.current.Load(); current != first || current.unanswered.Load() {
		t.Error("the watchdog dropped a connection whose request was answered")
	}
}

// firstListStallAgent never answers its first List request but serves later
// ones, like an agent that dropped one request on an old connection and
// answers new connections normally.
type firstListStallAgent struct {
	agent.ExtendedAgent
	calls   atomic.Int64
	started chan struct{}
	release chan struct{}
}

func (a *firstListStallAgent) List() ([]*agent.Key, error) {
	if a.calls.Add(1) == 1 {
		close(a.started)
		<-a.release
	}
	return a.ExtendedAgent.List()
}

func TestServerRecoversWhenAgentAnswersNewConnections(t *testing.T) {
	keyring := testutil.NewKeyring(t)
	addAgentKey(t, keyring, "allowed")
	backend := &firstListStallAgent{ExtendedAgent: keyring, started: make(chan struct{}), release: make(chan struct{})}
	f := startStartupFixture(t, backend, 100*time.Millisecond)
	// Registered after the fixture, so the stuck handler is released before
	// the test agent waits for its handlers.
	t.Cleanup(func() { close(backend.release) })

	if !testutil.WaitForEvent(t, backend.started, "unanswered startup listing") {
		return
	}
	if !testutil.WaitForEvent(t, f.ready, "proxy readiness") {
		return
	}
	waitForLogMessage(t, f.logs, "upstream request unanswered; dropping connection")
	waitForLogMessage(t, f.logs, "initial config key resolution failed; deferring until client request")

	// The first request is still unanswered, yet a client is served over a
	// fresh connection without operator action.
	keys, err := f.dial(t).List()
	if err != nil {
		t.Fatalf("client List() after the stuck connection was dropped: %v", err)
	}
	if len(keys) != 1 || keys[0].Comment != "allowed" {
		t.Errorf("client List() = %v, want the allowed key", keys)
	}
}
