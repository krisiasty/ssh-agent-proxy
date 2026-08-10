package app

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRuntimeTelemetrySamplesImmediately(t *testing.T) {
	telemetry := newRuntimeTelemetry(slog.New(slog.DiscardHandler))
	telemetry.mu.RLock()
	initialized := telemetry.initialized
	current := telemetry.current
	maximum := telemetry.maximum
	telemetry.mu.RUnlock()

	if !initialized {
		t.Fatal("telemetry was not initialized by its constructor")
	}
	if current.goroutines == 0 || maximum.goroutines == 0 {
		t.Fatalf("initial sample = current:%+v maximum:%+v", current, maximum)
	}
}

func TestRuntimeTelemetryTracksAndResetsIntervalMaxima(t *testing.T) {
	startedAt := time.Unix(1_700_000_000, 0)
	now := startedAt.Add(time.Second)
	values := []runtimeValues{
		{
			goroutines:           10,
			osThreads:            4,
			heapAllocBytes:       100,
			heapInuseBytes:       220,
			stackInuseBytes:      50,
			runtimeReservedBytes: 500,
			heapObjects:          20,
		},
		{
			goroutines:           8,
			osThreads:            6,
			heapAllocBytes:       140,
			heapInuseBytes:       200,
			stackInuseBytes:      70,
			runtimeReservedBytes: 480,
			heapObjects:          25,
		},
	}
	next := 0
	telemetry := &runtimeTelemetry{
		logger:    slog.New(slog.DiscardHandler),
		startedAt: startedAt,
		now:       func() time.Time { return now },
		read: func() runtimeValues {
			value := values[next]
			next++
			return value
		},
	}

	telemetry.sample()
	now = startedAt.Add(6 * time.Second)
	telemetry.sample()

	current, maximum := telemetry.current, telemetry.maximum
	if current != (runtimeValues{
		uptime:               6 * time.Second,
		goroutines:           8,
		osThreads:            6,
		heapAllocBytes:       140,
		heapInuseBytes:       200,
		stackInuseBytes:      70,
		runtimeReservedBytes: 480,
		heapObjects:          25,
	}) {
		t.Fatalf("current values = %+v", current)
	}
	if maximum != (runtimeValues{
		uptime:               6 * time.Second,
		goroutines:           10,
		osThreads:            6,
		heapAllocBytes:       140,
		heapInuseBytes:       220,
		stackInuseBytes:      70,
		runtimeReservedBytes: 500,
		heapObjects:          25,
	}) {
		t.Fatalf("maximum values = %+v", maximum)
	}

	reportedCurrent, reportedMaximum := telemetry.takeReport()
	if reportedCurrent != current || reportedMaximum != maximum {
		t.Fatalf("report = (%+v, %+v), want (%+v, %+v)", reportedCurrent, reportedMaximum, current, maximum)
	}
	if telemetry.maximum != current {
		t.Fatalf("maximum after report = %+v, want current %+v", telemetry.maximum, current)
	}
}

func TestRuntimeTelemetryLogContainsCurrentAndMaximumGroups(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	startedAt := time.Unix(1_700_000_000, 0)
	telemetry := &runtimeTelemetry{
		logger:    logger,
		startedAt: startedAt,
		now:       func() time.Time { return startedAt.Add(10 * time.Second) },
		read: func() runtimeValues {
			return runtimeValues{
				goroutines: 7, osThreads: 3, heapAllocBytes: 100, heapInuseBytes: 150,
				stackInuseBytes: 20, runtimeReservedBytes: 300, heapObjects: 11,
			}
		},
		maximum: runtimeValues{
			goroutines: 9, osThreads: 4, heapAllocBytes: 120, heapInuseBytes: 180,
			stackInuseBytes: 25, runtimeReservedBytes: 350, heapObjects: 13,
		},
		initialized: true,
	}

	telemetry.logReport()

	var event map[string]any
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatalf("decode telemetry log: %v", err)
	}
	if event["level"] != "INFO" || event["msg"] != "runtime telemetry" {
		t.Fatalf("event = %v", event)
	}
	current, ok := event["current"].(map[string]any)
	if !ok {
		t.Fatalf("current group = %#v", event["current"])
	}
	maximum, ok := event["max"].(map[string]any)
	if !ok {
		t.Fatalf("max group = %#v", event["max"])
	}
	wantCurrent := map[string]any{
		"uptime_seconds": float64(10),
		"goroutines":     float64(7), "os_threads": float64(3),
		"heap_alloc_bytes": float64(100), "heap_inuse_bytes": float64(150),
		"stack_inuse_bytes": float64(20), "runtime_reserved_bytes": float64(300),
		"heap_objects": float64(11),
	}
	wantMaximum := map[string]any{
		"uptime_seconds": float64(10),
		"goroutines":     float64(9), "os_threads": float64(4),
		"heap_alloc_bytes": float64(120), "heap_inuse_bytes": float64(180),
		"stack_inuse_bytes": float64(25), "runtime_reserved_bytes": float64(350),
		"heap_objects": float64(13),
	}
	assertTelemetryGroup(t, "current", current, wantCurrent)
	assertTelemetryGroup(t, "max", maximum, wantMaximum)
}

func TestRuntimeMetricsReaderReadsValues(t *testing.T) {
	values := newRuntimeMetricsReader().read()
	if values.goroutines == 0 {
		t.Error("goroutine count is zero")
	}
	if values.osThreads == 0 {
		t.Error("OS thread count is zero")
	}
	if values.heapAllocBytes == 0 || values.heapObjects == 0 {
		t.Errorf("heap values = %+v", values)
	}
	if values.heapInuseBytes < values.heapAllocBytes {
		t.Errorf("heap in use %d is below allocated heap %d", values.heapInuseBytes, values.heapAllocBytes)
	}
	if values.runtimeReservedBytes < values.heapInuseBytes+values.stackInuseBytes {
		t.Errorf("runtime reserved bytes are inconsistent: %+v", values)
	}
}

func TestRuntimeMetricsReaderReusesSampleBuffer(t *testing.T) {
	reader := newRuntimeMetricsReader()
	reader.read() // Initialize runtime metrics before measuring the steady state.

	allocations := testing.AllocsPerRun(1000, func() {
		_ = reader.read()
	})
	if allocations != 0 {
		t.Fatalf("runtime metrics read allocations = %v, want 0", allocations)
	}
}

func TestRuntimeMetricsReaderConcurrentSafe(t *testing.T) {
	reader := newRuntimeMetricsReader()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				values := reader.read()
				if values.goroutines == 0 || values.osThreads == 0 {
					t.Errorf("invalid concurrent runtime values: %+v", values)
					return
				}
			}
		})
	}
	wg.Wait()
}

func TestTelemetrySamplingAndReportingAreConcurrentSafe(t *testing.T) {
	var value atomic.Uint64
	telemetry := &runtimeTelemetry{
		logger:    slog.New(slog.DiscardHandler),
		startedAt: time.Now(),
		now:       time.Now,
		read: func() runtimeValues {
			n := value.Add(1)
			return runtimeValues{
				goroutines: n, osThreads: n, heapAllocBytes: n, heapInuseBytes: n,
				stackInuseBytes: n, runtimeReservedBytes: n, heapObjects: n,
			}
		},
	}
	telemetry.sample()

	var wg sync.WaitGroup
	wg.Go(func() {
		for range 100 {
			telemetry.sample()
		}
	})
	wg.Go(func() {
		for range 100 {
			telemetry.takeReport()
		}
	})
	wg.Wait()

	telemetry.mu.RLock()
	current, maximum := telemetry.current, telemetry.maximum
	telemetry.mu.RUnlock()
	for _, field := range []struct {
		name             string
		current, maximum uint64
	}{
		{"goroutines", current.goroutines, maximum.goroutines},
		{"os_threads", current.osThreads, maximum.osThreads},
		{"heap_alloc_bytes", current.heapAllocBytes, maximum.heapAllocBytes},
		{"heap_inuse_bytes", current.heapInuseBytes, maximum.heapInuseBytes},
		{"stack_inuse_bytes", current.stackInuseBytes, maximum.stackInuseBytes},
		{"runtime_reserved_bytes", current.runtimeReservedBytes, maximum.runtimeReservedBytes},
		{"heap_objects", current.heapObjects, maximum.heapObjects},
	} {
		if field.maximum < field.current {
			t.Errorf("%s: maximum %d is behind current %d", field.name, field.maximum, field.current)
		}
	}
}

func TestRuntimeTelemetryStopsOnCancellation(t *testing.T) {
	telemetry := newRuntimeTelemetry(slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		telemetry.run(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("telemetry did not stop after context cancellation")
	}
}

func TestTelemetryIntervals(t *testing.T) {
	if telemetrySampleInterval != time.Second {
		t.Fatalf("sample interval = %v", telemetrySampleInterval)
	}
	if telemetryReportInterval != 10*time.Minute {
		t.Fatalf("report interval = %v", telemetryReportInterval)
	}
}

func assertTelemetryGroup(t *testing.T, name string, got, want map[string]any) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s fields = %v, want %v", name, got, want)
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s.%s = %v, want %v", name, key, got[key], value)
		}
	}
}
