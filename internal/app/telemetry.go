package app

import (
	"context"
	"log/slog"
	runtimemetrics "runtime/metrics"
	"sync"
	"time"
)

const (
	telemetrySampleInterval = time.Second
	telemetryReportInterval = 10 * time.Minute
)

// runtimeValues is one point-in-time view of the process. The maximum held by
// runtimeTelemetry covers the current reporting interval and is reset after it
// is logged.
type runtimeValues struct {
	uptime               time.Duration
	goroutines           uint64
	osThreads            uint64
	heapAllocBytes       uint64
	heapInuseBytes       uint64
	stackInuseBytes      uint64
	runtimeReservedBytes uint64
	heapObjects          uint64
}

func (v runtimeValues) maxima(other runtimeValues) runtimeValues {
	return runtimeValues{
		uptime:               max(v.uptime, other.uptime),
		goroutines:           max(v.goroutines, other.goroutines),
		osThreads:            max(v.osThreads, other.osThreads),
		heapAllocBytes:       max(v.heapAllocBytes, other.heapAllocBytes),
		heapInuseBytes:       max(v.heapInuseBytes, other.heapInuseBytes),
		stackInuseBytes:      max(v.stackInuseBytes, other.stackInuseBytes),
		runtimeReservedBytes: max(v.runtimeReservedBytes, other.runtimeReservedBytes),
		heapObjects:          max(v.heapObjects, other.heapObjects),
	}
}

func (v runtimeValues) logAttrs() []any {
	return []any{
		"uptime_seconds", v.uptime.Seconds(),
		"goroutines", v.goroutines,
		"os_threads", v.osThreads,
		"heap_alloc_bytes", v.heapAllocBytes,
		"heap_inuse_bytes", v.heapInuseBytes,
		"stack_inuse_bytes", v.stackInuseBytes,
		"runtime_reserved_bytes", v.runtimeReservedBytes,
		"heap_objects", v.heapObjects,
	}
}

// runtimeTelemetry samples often enough to retain short-lived peaks while
// keeping logging volume fixed at one event every ten minutes.
type runtimeTelemetry struct {
	logger    *slog.Logger
	startedAt time.Time
	now       func() time.Time
	read      func() runtimeValues

	mu          sync.RWMutex
	current     runtimeValues
	maximum     runtimeValues
	initialized bool
}

func newRuntimeTelemetry(logger *slog.Logger) *runtimeTelemetry {
	t := &runtimeTelemetry{
		logger:    logger,
		startedAt: time.Now(),
		now:       time.Now,
		read:      readRuntimeValues,
	}
	t.sample()
	return t
}

func (t *runtimeTelemetry) run(ctx context.Context) {
	sampleTicker := time.NewTicker(telemetrySampleInterval)
	reportTicker := time.NewTicker(telemetryReportInterval)
	defer sampleTicker.Stop()
	defer reportTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sampleTicker.C:
			t.sample()
		case <-reportTicker.C:
			t.logReport()
		}
	}
}

func (t *runtimeTelemetry) sample() {
	values := t.read()
	values.uptime = max(t.now().Sub(t.startedAt), 0)

	t.mu.Lock()
	defer t.mu.Unlock()
	t.current = values
	if !t.initialized {
		t.maximum = values
		t.initialized = true
		return
	}
	t.maximum = t.maximum.maxima(values)
}

// takeReport returns a consistent interval and starts the next interval at the
// current values.
func (t *runtimeTelemetry) takeReport() (runtimeValues, runtimeValues) {
	t.mu.Lock()
	defer t.mu.Unlock()
	current, maximum := t.current, t.maximum
	t.maximum = current
	return current, maximum
}

func (t *runtimeTelemetry) logReport() {
	// Make the logged current values current at report time rather than up to one
	// sample interval old.
	t.sample()
	current, maximum := t.takeReport()
	t.logger.Info("runtime telemetry",
		slog.Group("current", current.logAttrs()...),
		slog.Group("max", maximum.logAttrs()...),
	)
}

func readRuntimeValues() runtimeValues {
	samples := [...]runtimemetrics.Sample{
		{Name: "/sched/goroutines:goroutines"},
		{Name: "/sched/threads/total:threads"},
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/memory/classes/heap/unused:bytes"},
		{Name: "/memory/classes/heap/stacks:bytes"},
		{Name: "/memory/classes/total:bytes"},
		{Name: "/gc/heap/objects:objects"},
	}
	runtimemetrics.Read(samples[:])

	heapAlloc := samples[2].Value.Uint64()
	return runtimeValues{
		goroutines:           samples[0].Value.Uint64(),
		osThreads:            samples[1].Value.Uint64(),
		heapAllocBytes:       heapAlloc,
		heapInuseBytes:       heapAlloc + samples[3].Value.Uint64(),
		stackInuseBytes:      samples[4].Value.Uint64(),
		runtimeReservedBytes: samples[5].Value.Uint64(),
		heapObjects:          samples[6].Value.Uint64(),
	}
}
