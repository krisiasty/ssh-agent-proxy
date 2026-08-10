package proxy

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
)

// proxyTelemetry collects inexpensive process-wide activity counters. Request
// paths use atomics; the mutex is used only when client connections open,
// close, or a report resets the interval peak.
type proxyTelemetry struct {
	log *slog.Logger

	clientsMu        sync.Mutex
	activeClients    uint64
	maxActiveClients uint64

	clientConnections atomic.Uint64
	clientErrors      atomic.Uint64
	listRequests      atomic.Uint64
	listErrors        atomic.Uint64
	signRequests      atomic.Uint64
	signErrors        atomic.Uint64

	upstreamCalls      atomic.Uint64
	upstreamErrors     atomic.Uint64
	upstreamReconnects atomic.Uint64

	cacheHits      atomic.Uint64
	cacheMisses    atomic.Uint64
	cacheRefreshes atomic.Uint64
	cacheWaits     atomic.Uint64
}

func newProxyTelemetry(log *slog.Logger) *proxyTelemetry {
	if !log.Enabled(context.Background(), slog.LevelDebug) {
		return nil
	}
	return &proxyTelemetry{log: log}
}

func (t *proxyTelemetry) clientConnected() {
	if t == nil {
		return
	}
	t.clientConnections.Add(1)
	t.clientsMu.Lock()
	t.activeClients++
	t.maxActiveClients = max(t.maxActiveClients, t.activeClients)
	t.clientsMu.Unlock()
}

func (t *proxyTelemetry) clientDisconnected() {
	if t == nil {
		return
	}
	t.clientsMu.Lock()
	if t.activeClients > 0 {
		t.activeClients--
	}
	t.clientsMu.Unlock()
}

func (t *proxyTelemetry) clientSnapshot() (current, maximum uint64) {
	t.clientsMu.Lock()
	defer t.clientsMu.Unlock()
	current, maximum = t.activeClients, t.maxActiveClients
	t.maxActiveClients = current
	return current, maximum
}

func (t *proxyTelemetry) upstreamCall(err error) {
	if t == nil {
		return
	}
	t.upstreamCalls.Add(1)
	if err != nil {
		t.upstreamErrors.Add(1)
	}
}

func (t *proxyTelemetry) logReport() {
	if t == nil {
		return
	}
	activeClients, maxActiveClients := t.clientSnapshot()
	t.log.Debug("telemetry clients",
		"active_clients", activeClients,
		"max_active_clients", maxActiveClients,
		"connections", t.clientConnections.Swap(0),
		"connection_errors", t.clientErrors.Swap(0),
		"list_requests", t.listRequests.Swap(0),
		"list_errors", t.listErrors.Swap(0),
		"sign_requests", t.signRequests.Swap(0),
		"sign_errors", t.signErrors.Swap(0))
	t.log.Debug("telemetry upstream",
		"calls", t.upstreamCalls.Swap(0),
		"errors", t.upstreamErrors.Swap(0),
		"reconnects", t.upstreamReconnects.Swap(0))
	t.log.Debug("telemetry cache",
		"hits", t.cacheHits.Swap(0),
		"misses", t.cacheMisses.Swap(0),
		"refreshes", t.cacheRefreshes.Swap(0),
		"waits", t.cacheWaits.Swap(0))
}
