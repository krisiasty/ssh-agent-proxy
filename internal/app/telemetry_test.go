package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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
	values := []runtimeSample{
		{
			values: runtimeValues{
				goroutines:           10,
				osThreads:            4,
				heapAllocBytes:       100,
				heapInuseBytes:       220,
				heapLiveBytes:        80,
				heapGoalBytes:        400,
				stackInuseBytes:      50,
				runtimeReservedBytes: 500,
				heapObjects:          20,
			},
			counters: runtimeCounters{
				heapAllocatedBytes:   1_000,
				heapAllocatedObjects: 200,
				gcCycles:             3,
			},
		},
		{
			values: runtimeValues{
				goroutines:           8,
				osThreads:            6,
				heapAllocBytes:       140,
				heapInuseBytes:       200,
				heapLiveBytes:        90,
				heapGoalBytes:        380,
				stackInuseBytes:      70,
				runtimeReservedBytes: 480,
				heapObjects:          25,
			},
			counters: runtimeCounters{
				heapAllocatedBytes:   1_300,
				heapAllocatedObjects: 220,
				gcCycles:             4,
			},
		},
	}
	next := 0
	telemetry := &runtimeTelemetry{
		logger:    slog.New(slog.DiscardHandler),
		startedAt: startedAt,
		now:       func() time.Time { return now },
		read: func() runtimeSample {
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
		heapLiveBytes:        90,
		heapGoalBytes:        380,
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
		heapLiveBytes:        90,
		heapGoalBytes:        400,
		stackInuseBytes:      70,
		runtimeReservedBytes: 500,
		heapObjects:          25,
	}) {
		t.Fatalf("maximum values = %+v", maximum)
	}

	reportedCurrent, reportedMaximum, interval := telemetry.takeReport()
	if reportedCurrent != current || reportedMaximum != maximum {
		t.Fatalf("report = (%+v, %+v), want (%+v, %+v)", reportedCurrent, reportedMaximum, current, maximum)
	}
	if interval != (runtimeInterval{heapAllocatedBytes: 300, heapAllocatedObjects: 20, gcCycles: 1}) {
		t.Fatalf("interval = %+v", interval)
	}
	if telemetry.maximum != current {
		t.Fatalf("maximum after report = %+v, want current %+v", telemetry.maximum, current)
	}
}

func TestRuntimeTelemetryLogsCurrentMaximumAndIntervalEvents(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	startedAt := time.Unix(1_700_000_000, 0)
	telemetry := &runtimeTelemetry{
		logger:    logger,
		startedAt: startedAt,
		now:       func() time.Time { return startedAt.Add(10 * time.Second) },
		read: func() runtimeSample {
			return runtimeSample{
				values: runtimeValues{
					goroutines: 7, osThreads: 3, heapAllocBytes: 100, heapInuseBytes: 150,
					heapLiveBytes: 90, heapGoalBytes: 400,
					stackInuseBytes: 20, runtimeReservedBytes: 300, heapObjects: 11,
				},
				counters: runtimeCounters{
					heapAllocatedBytes: 1_300, heapAllocatedObjects: 220, gcCycles: 4,
				},
			}
		},
		maximum: runtimeValues{
			goroutines: 9, osThreads: 4, heapAllocBytes: 120, heapInuseBytes: 180,
			heapLiveBytes: 95, heapGoalBytes: 420,
			stackInuseBytes: 25, runtimeReservedBytes: 350, heapObjects: 13,
		},
		intervalAt: runtimeCounters{
			heapAllocatedBytes: 1_000, heapAllocatedObjects: 200, gcCycles: 3,
		},
		initialized: true,
	}

	telemetry.logReport()

	decoder := json.NewDecoder(&output)
	events := make([]map[string]any, 3)
	for i := range events {
		if err := decoder.Decode(&events[i]); err != nil {
			t.Fatalf("decode telemetry log %d: %v", i+1, err)
		}
		if events[i]["level"] != "INFO" {
			t.Fatalf("event %d = %v", i+1, events[i])
		}
	}
	var extra map[string]any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("unexpected trailing telemetry data: event=%v err=%v", extra, err)
	}
	wantCurrent := map[string]any{
		"uptime_seconds": float64(10),
		"goroutines":     float64(7), "os_threads": float64(3),
		"heap_alloc_bytes": float64(100), "heap_inuse_bytes": float64(150),
		"heap_live_bytes": float64(90), "heap_goal_bytes": float64(400),
		"stack_inuse_bytes": float64(20), "runtime_reserved_bytes": float64(300),
		"heap_objects": float64(11),
	}
	wantMaximum := map[string]any{
		"uptime_seconds": float64(10),
		"goroutines":     float64(9), "os_threads": float64(4),
		"heap_alloc_bytes": float64(120), "heap_inuse_bytes": float64(180),
		"heap_live_bytes": float64(95), "heap_goal_bytes": float64(420),
		"stack_inuse_bytes": float64(25), "runtime_reserved_bytes": float64(350),
		"heap_objects": float64(13),
	}
	wantInterval := map[string]any{
		"heap_allocated_bytes": float64(300), "heap_allocated_objects": float64(20),
		"gc_cycles": float64(1),
	}
	assertTelemetryEvent(t, events[0], "telemetry current", wantCurrent)
	assertTelemetryEvent(t, events[1], "telemetry max", wantMaximum)
	assertTelemetryEvent(t, events[2], "telemetry interval", wantInterval)
}

func TestRuntimeCounterDeltaDoesNotUnderflow(t *testing.T) {
	if delta := counterDelta(2, 3); delta != 0 {
		t.Fatalf("counter delta after regression = %d, want 0", delta)
	}
}

func TestRuntimeMetricsReaderReadsValues(t *testing.T) {
	sample := newRuntimeMetricsReader().read()
	values := sample.values
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
	if values.heapGoalBytes < values.heapLiveBytes {
		t.Errorf("heap goal %d is below live heap %d", values.heapGoalBytes, values.heapLiveBytes)
	}
	if values.runtimeReservedBytes < values.heapInuseBytes+values.stackInuseBytes {
		t.Errorf("runtime reserved bytes are inconsistent: %+v", values)
	}
	if sample.counters.heapAllocatedBytes < values.heapAllocBytes ||
		sample.counters.heapAllocatedObjects < values.heapObjects {
		t.Errorf("runtime counters are inconsistent: %+v", sample)
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
				values := reader.read().values
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
		read: func() runtimeSample {
			n := value.Add(1)
			return runtimeSample{
				values: runtimeValues{
					goroutines: n, osThreads: n, heapAllocBytes: n, heapInuseBytes: n,
					heapLiveBytes: n, heapGoalBytes: n,
					stackInuseBytes: n, runtimeReservedBytes: n, heapObjects: n,
				},
				counters: runtimeCounters{
					heapAllocatedBytes: n, heapAllocatedObjects: n, gcCycles: n,
				},
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
		{"heap_live_bytes", current.heapLiveBytes, maximum.heapLiveBytes},
		{"heap_goal_bytes", current.heapGoalBytes, maximum.heapGoalBytes},
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

func assertTelemetryEvent(t *testing.T, event map[string]any, message string, want map[string]any) {
	t.Helper()
	if event["msg"] != message {
		t.Fatalf("event message = %v, want %q", event["msg"], message)
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
