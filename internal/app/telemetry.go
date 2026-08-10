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
	heapLiveBytes        uint64
	heapGoalBytes        uint64
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
		heapLiveBytes:        max(v.heapLiveBytes, other.heapLiveBytes),
		heapGoalBytes:        max(v.heapGoalBytes, other.heapGoalBytes),
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
		"heap_live_bytes", v.heapLiveBytes,
		"heap_goal_bytes", v.heapGoalBytes,
		"stack_inuse_bytes", v.stackInuseBytes,
		"runtime_reserved_bytes", v.runtimeReservedBytes,
		"heap_objects", v.heapObjects,
	}
}

// runtimeCounters contains monotonically increasing process counters. Reports
// expose their change since the previous report rather than their absolute
// values, which are not meaningful interval maxima.
type runtimeCounters struct {
	heapAllocatedBytes   uint64
	heapAllocatedObjects uint64
	gcCycles             uint64
}

func (c runtimeCounters) since(previous runtimeCounters) runtimeInterval {
	return runtimeInterval{
		heapAllocatedBytes:   counterDelta(c.heapAllocatedBytes, previous.heapAllocatedBytes),
		heapAllocatedObjects: counterDelta(c.heapAllocatedObjects, previous.heapAllocatedObjects),
		gcCycles:             counterDelta(c.gcCycles, previous.gcCycles),
	}
}

func counterDelta(current, previous uint64) uint64 {
	if current < previous {
		return 0
	}
	return current - previous
}

type runtimeInterval struct {
	heapAllocatedBytes   uint64
	heapAllocatedObjects uint64
	gcCycles             uint64
}

func (v runtimeInterval) logAttrs() []any {
	return []any{
		"heap_allocated_bytes", v.heapAllocatedBytes,
		"heap_allocated_objects", v.heapAllocatedObjects,
		"gc_cycles", v.gcCycles,
	}
}

type runtimeSample struct {
	values   runtimeValues
	counters runtimeCounters
}

// runtimeTelemetry samples often enough to retain short-lived peaks while
// keeping logging volume fixed at one three-event report every ten minutes.
type runtimeTelemetry struct {
	logger    *slog.Logger
	startedAt time.Time
	now       func() time.Time
	read      func() runtimeSample

	mu          sync.RWMutex
	current     runtimeValues
	maximum     runtimeValues
	counters    runtimeCounters
	intervalAt  runtimeCounters
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
	sample := t.read()
	values := sample.values
	values.uptime = max(t.now().Sub(t.startedAt), 0)

	t.mu.Lock()
	defer t.mu.Unlock()
	t.current = values
	t.counters = sample.counters
	if !t.initialized {
		t.maximum = values
		t.intervalAt = sample.counters
		t.initialized = true
		return
	}
	t.maximum = t.maximum.maxima(values)
}

// takeReport returns a consistent interval and starts the next interval at the
// current values.
func (t *runtimeTelemetry) takeReport() (runtimeValues, runtimeValues, runtimeInterval) {
	t.mu.Lock()
	defer t.mu.Unlock()
	current, maximum := t.current, t.maximum
	interval := t.counters.since(t.intervalAt)
	t.maximum = current
	t.intervalAt = t.counters
	return current, maximum, interval
}

func (t *runtimeTelemetry) logReport() {
	// Make the logged current values current at report time rather than up to one
	// sample interval old.
	t.sample()
	current, maximum, interval := t.takeReport()
	t.logger.Info("telemetry current", current.logAttrs()...)
	t.logger.Info("telemetry max", maximum.logAttrs()...)
	t.logger.Info("telemetry interval", interval.logAttrs()...)
}

const (
	runtimeMetricGoroutines = iota
	runtimeMetricOSThreads
	runtimeMetricHeapObjectsBytes
	runtimeMetricHeapUnusedBytes
	runtimeMetricHeapLiveBytes
	runtimeMetricHeapGoalBytes
	runtimeMetricStackInuseBytes
	runtimeMetricReservedBytes
	runtimeMetricHeapObjects
	runtimeMetricHeapAllocatedBytes
	runtimeMetricHeapAllocatedObjects
	runtimeMetricGCCycles
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
		runtimeMetricHeapLiveBytes:    {Name: "/gc/heap/live:bytes"},
		runtimeMetricHeapGoalBytes:    {Name: "/gc/heap/goal:bytes"},
		runtimeMetricStackInuseBytes:  {Name: "/memory/classes/heap/stacks:bytes"},
		runtimeMetricReservedBytes:    {Name: "/memory/classes/total:bytes"},
		runtimeMetricHeapObjects:      {Name: "/gc/heap/objects:objects"},
		runtimeMetricHeapAllocatedBytes: {
			Name: "/gc/heap/allocs:bytes",
		},
		runtimeMetricHeapAllocatedObjects: {
			Name: "/gc/heap/allocs:objects",
		},
		runtimeMetricGCCycles: {Name: "/gc/cycles/total:gc-cycles"},
	}}
}

func (r *runtimeMetricsReader) read() runtimeSample {
	r.mu.Lock()
	defer r.mu.Unlock()

	runtimemetrics.Read(r.samples[:])

	heapAlloc := r.samples[runtimeMetricHeapObjectsBytes].Value.Uint64()
	return runtimeSample{
		values: runtimeValues{
			goroutines:           r.samples[runtimeMetricGoroutines].Value.Uint64(),
			osThreads:            r.samples[runtimeMetricOSThreads].Value.Uint64(),
			heapAllocBytes:       heapAlloc,
			heapInuseBytes:       heapAlloc + r.samples[runtimeMetricHeapUnusedBytes].Value.Uint64(),
			heapLiveBytes:        r.samples[runtimeMetricHeapLiveBytes].Value.Uint64(),
			heapGoalBytes:        r.samples[runtimeMetricHeapGoalBytes].Value.Uint64(),
			stackInuseBytes:      r.samples[runtimeMetricStackInuseBytes].Value.Uint64(),
			runtimeReservedBytes: r.samples[runtimeMetricReservedBytes].Value.Uint64(),
			heapObjects:          r.samples[runtimeMetricHeapObjects].Value.Uint64(),
		},
		counters: runtimeCounters{
			heapAllocatedBytes:   r.samples[runtimeMetricHeapAllocatedBytes].Value.Uint64(),
			heapAllocatedObjects: r.samples[runtimeMetricHeapAllocatedObjects].Value.Uint64(),
			gcCycles:             r.samples[runtimeMetricGCCycles].Value.Uint64(),
		},
	}
}
