package proxy

import (
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

func TestCachedAgentCachesListUntilTTLExpires(t *testing.T) {
	upstream := &countingKeyring{ExtendedAgent: newTestKeyring(t)}
	now := time.Unix(1_000, 0)
	telemetry := &proxyTelemetry{}
	cached := newCachedAgent(upstream, 3*time.Second, slog.New(slog.DiscardHandler), telemetry)
	cached.now = func() time.Time { return now }

	if _, err := cached.List(); err != nil {
		t.Fatal(err)
	}
	if _, err := cached.List(); err != nil {
		t.Fatal(err)
	}
	if got := upstream.listCalls.Load(); got != 1 {
		t.Fatalf("upstream List() calls before expiry = %d, want 1", got)
	}

	now = now.Add(3 * time.Second)
	if _, err := cached.List(); err != nil {
		t.Fatal(err)
	}
	if got := upstream.listCalls.Load(); got != 2 {
		t.Fatalf("upstream List() calls after expiry = %d, want 2", got)
	}
	if hits, misses, refreshes := telemetry.cacheHits.Load(), telemetry.cacheMisses.Load(), telemetry.cacheRefreshes.Load(); hits != 1 || misses != 2 || refreshes != 2 {
		t.Fatalf("cache telemetry = hits:%d misses:%d refreshes:%d", hits, misses, refreshes)
	}
}

func TestCachedAgentZeroTTLDisablesCaching(t *testing.T) {
	upstream := &countingKeyring{ExtendedAgent: newTestKeyring(t)}
	telemetry := &proxyTelemetry{}
	cached := newCachedAgent(upstream, 0, slog.New(slog.DiscardHandler), telemetry)

	for range 2 {
		if _, err := cached.List(); err != nil {
			t.Fatal(err)
		}
	}
	if got := upstream.listCalls.Load(); got != 2 {
		t.Fatalf("upstream List() calls = %d, want 2", got)
	}
	if hits, misses, refreshes := telemetry.cacheHits.Load(), telemetry.cacheMisses.Load(), telemetry.cacheRefreshes.Load(); hits != 0 || misses != 2 || refreshes != 2 {
		t.Fatalf("cache telemetry = hits:%d misses:%d refreshes:%d", hits, misses, refreshes)
	}
}

func TestCachedAgentSharesSnapshotAcrossGroups(t *testing.T) {
	upstream := &countingKeyring{ExtendedAgent: newTestKeyring(t)}
	cached := newCachedAgent(upstream, 3*time.Second, slog.New(slog.DiscardHandler), nil)
	log := slog.New(slog.DiscardHandler)
	first := newGroupAuthorization("first", nil, log)
	second := newGroupAuthorization("second", nil, log)

	if _, err := first.list(cached); err != nil {
		t.Fatal(err)
	}
	if _, err := second.list(cached); err != nil {
		t.Fatal(err)
	}
	if got := upstream.listCalls.Load(); got != 1 {
		t.Fatalf("upstream List() calls across groups = %d, want 1", got)
	}
}

func TestCachedAgentCoalescesConcurrentRefreshes(t *testing.T) {
	upstream := &blockingListAgent{
		ExtendedAgent: newTestKeyring(t),
		started:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	cached := newCachedAgent(upstream, 3*time.Second, slog.New(slog.DiscardHandler), nil)

	const clients = 128
	start := make(chan struct{})
	errs := make(chan error, clients)
	var ready sync.WaitGroup
	ready.Add(clients)
	for range clients {
		go func() {
			ready.Done()
			<-start
			_, err := cached.List()
			errs <- err
		}()
	}
	ready.Wait()
	close(start)
	<-upstream.started
	close(upstream.release)

	for range clients {
		if err := <-errs; err != nil {
			t.Errorf("cached List() failed: %v", err)
		}
	}
	if got := upstream.listCalls.Load(); got != 1 {
		t.Errorf("upstream List() calls = %d, want 1", got)
	}
}

func TestCachedAgentServesStaleSnapshotAfterRefreshFailure(t *testing.T) {
	upstream := &toggleListAgent{ExtendedAgent: newTestKeyring(t)}
	now := time.Unix(1_000, 0)
	cached := newCachedAgent(upstream, 3*time.Second, slog.New(slog.DiscardHandler), nil)
	cached.now = func() time.Time { return now }

	if _, err := cached.List(); err != nil {
		t.Fatal(err)
	}
	upstream.fail.Store(true)
	now = now.Add(3 * time.Second)
	if _, err := cached.List(); err != nil {
		t.Fatalf("List() with stale snapshot returned error: %v", err)
	}
	if _, err := cached.List(); err != nil {
		t.Fatalf("cached stale List() returned error: %v", err)
	}
	if got := upstream.listCalls.Load(); got != 2 {
		t.Errorf("upstream List() calls = %d, want 2", got)
	}
}

func TestCachedAgentCachesInitialFailure(t *testing.T) {
	wantErr := errors.New("upstream locked")
	upstream := &failingListAgent{ExtendedAgent: newTestKeyring(t), err: wantErr}
	cached := newCachedAgent(upstream, 3*time.Second, slog.New(slog.DiscardHandler), nil)

	for range 2 {
		if _, err := cached.List(); !errors.Is(err, wantErr) {
			t.Errorf("List() error = %v, want %v", err, wantErr)
		}
	}
	if got := upstream.listCalls.Load(); got != 1 {
		t.Errorf("upstream List() calls = %d, want 1", got)
	}
}

type countingKeyring struct {
	agent.ExtendedAgent
	listCalls atomic.Int64
}

func (a *countingKeyring) List() ([]*agent.Key, error) {
	a.listCalls.Add(1)
	return a.ExtendedAgent.List()
}

type failingListAgent struct {
	agent.ExtendedAgent
	err       error
	listCalls atomic.Int64
}

func (a *failingListAgent) List() ([]*agent.Key, error) {
	a.listCalls.Add(1)
	return nil, a.err
}

func newTestKeyring(t *testing.T) agent.ExtendedAgent {
	t.Helper()
	keyring, ok := agent.NewKeyring().(agent.ExtendedAgent)
	if !ok {
		t.Fatal("agent.NewKeyring does not implement agent.ExtendedAgent")
	}
	return keyring
}
