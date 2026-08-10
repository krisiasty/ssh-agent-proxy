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
	reader := newRuntimeMetricsReader()
	t := &runtimeTelemetry{
		logger:    logger,
		startedAt: time.Now(),
		now:       time.Now,
		read:      reader.read,
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

const (
	runtimeMetricGoroutines = iota
	runtimeMetricOSThreads
	runtimeMetricHeapObjectsBytes
	runtimeMetricHeapUnusedBytes
	runtimeMetricStackInuseBytes
	runtimeMetricReservedBytes
	runtimeMetricHeapObjects
	runtimeMetricCount
)

// runtimeMetricsReader owns and reuses its sample buffer. runtime/metrics.Read
// recommends reuse for efficiency; allocating this array for every one-second
// sample otherwise creates a steady allocation baseline in the metrics being
// observed. The mutex keeps reuse safe if reads are invoked concurrently.
type runtimeMetricsReader struct {
	mu      sync.Mutex
	samples [runtimeMetricCount]runtimemetrics.Sample
}

func newRuntimeMetricsReader() *runtimeMetricsReader {
	return &runtimeMetricsReader{samples: [...]runtimemetrics.Sample{
		runtimeMetricGoroutines:       {Name: "/sched/goroutines:goroutines"},
		runtimeMetricOSThreads:        {Name: "/sched/threads/total:threads"},
		runtimeMetricHeapObjectsBytes: {Name: "/memory/classes/heap/objects:bytes"},
		runtimeMetricHeapUnusedBytes:  {Name: "/memory/classes/heap/unused:bytes"},
		runtimeMetricStackInuseBytes:  {Name: "/memory/classes/heap/stacks:bytes"},
		runtimeMetricReservedBytes:    {Name: "/memory/classes/total:bytes"},
		runtimeMetricHeapObjects:      {Name: "/gc/heap/objects:objects"},
	}}
}

func (r *runtimeMetricsReader) read() runtimeValues {
	r.mu.Lock()
	defer r.mu.Unlock()

	runtimemetrics.Read(r.samples[:])

	heapAlloc := r.samples[runtimeMetricHeapObjectsBytes].Value.Uint64()
	return runtimeValues{
		goroutines:           r.samples[runtimeMetricGoroutines].Value.Uint64(),
		osThreads:            r.samples[runtimeMetricOSThreads].Value.Uint64(),
		heapAllocBytes:       heapAlloc,
		heapInuseBytes:       heapAlloc + r.samples[runtimeMetricHeapUnusedBytes].Value.Uint64(),
		stackInuseBytes:      r.samples[runtimeMetricStackInuseBytes].Value.Uint64(),
		runtimeReservedBytes: r.samples[runtimeMetricReservedBytes].Value.Uint64(),
		heapObjects:          r.samples[runtimeMetricHeapObjects].Value.Uint64(),
	}
}
