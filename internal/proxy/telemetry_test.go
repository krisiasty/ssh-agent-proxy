package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
)

func TestProxyTelemetryLogsAndResetsInterval(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	telemetry := newProxyTelemetry(log)
	telemetry.clientConnected()
	telemetry.clientConnected()
	telemetry.clientDisconnected()
	telemetry.clientErrors.Add(1)
	telemetry.listRequests.Add(4)
	telemetry.listErrors.Add(1)
	telemetry.signRequests.Add(3)
	telemetry.signErrors.Add(2)
	telemetry.upstreamCall(nil)
	telemetry.upstreamCall(errors.New("upstream failure"))
	telemetry.upstreamReconnects.Add(1)
	telemetry.cacheHits.Add(5)
	telemetry.cacheMisses.Add(2)
	telemetry.cacheRefreshes.Add(1)
	telemetry.cacheWaits.Add(1)

	telemetry.logReport()
	events := decodeTelemetryEvents(t, &output)
	assertProxyTelemetryEvent(t, events[0], "telemetry clients", map[string]any{
		"active_clients": float64(1), "max_active_clients": float64(2),
		"connections": float64(2), "connection_errors": float64(1),
		"list_requests": float64(4), "list_errors": float64(1),
		"sign_requests": float64(3), "sign_errors": float64(2),
	})
	assertProxyTelemetryEvent(t, events[1], "telemetry upstream", map[string]any{
		"calls": float64(2), "errors": float64(1), "reconnects": float64(1),
	})
	assertProxyTelemetryEvent(t, events[2], "telemetry cache", map[string]any{
		"hits": float64(5), "misses": float64(2), "refreshes": float64(1), "waits": float64(1),
	})

	output.Reset()
	telemetry.logReport()
	events = decodeTelemetryEvents(t, &output)
	assertProxyTelemetryEvent(t, events[0], "telemetry clients", map[string]any{
		"active_clients": float64(1), "max_active_clients": float64(1),
		"connections": float64(0), "connection_errors": float64(0),
		"list_requests": float64(0), "list_errors": float64(0),
		"sign_requests": float64(0), "sign_errors": float64(0),
	})
}

func TestProxyTelemetryDisabledWithoutDebugLogging(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	if telemetry := newProxyTelemetry(log); telemetry != nil {
		t.Fatalf("proxy telemetry = %p, want nil at info level", telemetry)
	}
}

func TestProxyTelemetryTracksConcurrentClientPeak(t *testing.T) {
	telemetry := &proxyTelemetry{log: slog.New(slog.DiscardHandler)}
	const clients = 100
	connected := make(chan struct{}, clients)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for range clients {
		wg.Go(func() {
			telemetry.clientConnected()
			connected <- struct{}{}
			<-release
			telemetry.clientDisconnected()
		})
	}
	for range clients {
		<-connected
	}
	current, maximum := telemetry.clientSnapshot()
	if current != clients || maximum != clients {
		t.Fatalf("client snapshot = current:%d max:%d, want %d", current, maximum, clients)
	}
	close(release)
	wg.Wait()
	current, maximum = telemetry.clientSnapshot()
	if current != 0 || maximum != clients {
		t.Fatalf("completed client snapshot = current:%d max:%d, want current:0 max:%d", current, maximum, clients)
	}
}

func decodeTelemetryEvents(t *testing.T, output *bytes.Buffer) []map[string]any {
	t.Helper()
	decoder := json.NewDecoder(output)
	events := make([]map[string]any, 3)
	for i := range events {
		if err := decoder.Decode(&events[i]); err != nil {
			t.Fatalf("decode proxy telemetry event %d: %v", i+1, err)
		}
	}
	var extra map[string]any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("unexpected trailing telemetry data: event=%v err=%v", extra, err)
	}
	return events
}

func assertProxyTelemetryEvent(t *testing.T, event map[string]any, message string, want map[string]any) {
	t.Helper()
	if event["level"] != "DEBUG" || event["msg"] != message {
		t.Fatalf("event = %v, want DEBUG %q", event, message)
	}
	for _, key := range []string{"time", "level", "msg"} {
		delete(event, key)
	}
	if len(event) != len(want) {
		t.Fatalf("%s fields = %v, want %v", message, event, want)
	}
	for key, value := range want {
		if event[key] != value {
			t.Errorf("%s.%s = %v, want %v", message, key, event[key], value)
		}
	}
}
