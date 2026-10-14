// Package app wires config, logging and the proxy server into the service
// runtime shared by foreground and managed-service execution.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/krisiasty/ssh-agent-proxy/internal/config"
	"github.com/krisiasty/ssh-agent-proxy/internal/logging"
	"github.com/krisiasty/ssh-agent-proxy/internal/proxy"
)

// maxProcs caps the number of OS threads the runtime uses for running
// goroutines. The proxy is I/O-bound with light load, so a small value keeps
// the thread/memory footprint down without affecting throughput.
const maxProcs = 2

// Version holds the build metadata logged at startup — equivalent to the
// output of --version.
type Version struct {
	Version string
	Commit  string
	Date    string
}

// String returns the version line in the same format as --version.
func (v Version) String() string {
	return fmt.Sprintf("ssh-agent-proxy %s (commit %s, built %s)", v.Version, v.Commit, v.Date)
}

// Run loads the config and serves the group sockets until terminated by
// SIGINT/SIGTERM. SIGHUP validates and activates the selected config again.
//
// If configuration or proxy startup fails and foreground is false, Run logs the
// error and idles until terminated instead of exiting, so the service manager
// does not restart it in a tight loop. In foreground mode the error is returned
// to the caller (which exits non-zero).
func Run(cfgPath string, foreground bool, cacheTTL time.Duration, version Version) error {
	// Cap parallelism unless the operator set GOMAXPROCS explicitly.
	if os.Getenv("GOMAXPROCS") == "" {
		runtime.GOMAXPROCS(maxProcs)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(reload)
	return runWithReload(ctx, reload, cfgPath, foreground, cacheTTL, version)
}

func run(ctx context.Context, cfgPath string, foreground bool, cacheTTL time.Duration, version Version) error {
	return runWithReload(ctx, nil, cfgPath, foreground, cacheTTL, version)
}

func runWithReload(
	ctx context.Context,
	reload <-chan os.Signal,
	cfgPath string,
	foreground bool,
	cacheTTL time.Duration,
	version Version,
) error {
	log := logging.Setup(false)
	var current *runtimeInstance
	var lastGood, next *config.Config
	var rollbackCause error
	reloadPending, suppressReloadLog := true, true

	stopCurrent := func() error {
		if current == nil {
			return nil
		}
		err := current.stop()
		current = nil
		return err
	}
	observeReadiness := func() {
		if current == nil || current.started || ctx.Err() != nil {
			return
		}
		select {
		case <-current.ready:
			current.started = true
			lastGood = current.cfg
			switch {
			case rollbackCause != nil:
				log.Info("previous configuration restored", "config", cfgPath, "groups", len(lastGood.Groups))
			case !suppressReloadLog:
				log.Info("configuration reloaded", "config", cfgPath, "groups", len(lastGood.Groups))
			}
			rollbackCause = nil
		default:
		}
	}

	for {
		// Every startup, reload, and rollback passes this shutdown check.
		if ctx.Err() != nil {
			return stopCurrent()
		}
		observeReadiness()
		if reloadPending {
			reloadPending = false
			candidate, loadErr := config.Load(cfgPath)
			if ctx.Err() != nil {
				return stopCurrent()
			}
			observeReadiness()
			switch {
			case loadErr == nil:
				if !suppressReloadLog {
					log.Info("configuration reload requested", "config", cfgPath)
				}
				next, rollbackCause = candidate, nil
			case current != nil && (current.started || lastGood == nil):
				log.Error("configuration reload failed; keeping current configuration", "err", loadErr)
				continue
			case current != nil && lastGood != nil:
				log.Error("configuration reload failed", "err", loadErr)
				log.Warn("restoring previous configuration")
				next, rollbackCause = lastGood, loadErr
			case lastGood != nil:
				log.Error("configuration reload failed; remaining idle", "err", loadErr)
				continue
			default:
				stopErr := stopCurrent()
				if ctx.Err() != nil {
					return stopErr
				}
				if stopErr != nil {
					loadErr = errors.Join(loadErr, stopErr)
				}
				if foreground {
					return loadErr
				}
				log.Error("configuration error", "err", loadErr)
				log.Error("idling until stopped or reloaded; fix the config and send SIGHUP")
				continue
			}
		}
		if next != nil {
			stopErr := stopCurrent()
			if ctx.Err() != nil {
				return stopErr
			}
			if stopErr != nil {
				log.Warn("stopping current runtime for reload", "err", stopErr)
			}
			current = launchRuntime(ctx, cfgPath, next, cacheTTL, version)
			log = current.log
			next = nil
		}

		var ready <-chan struct{}
		var done <-chan error
		if current != nil {
			done = current.done
			if !current.started {
				ready = current.ready
			}
		}
		select {
		case <-ctx.Done():
			continue
		case <-reload:
			reloadPending = true
			suppressReloadLog = false
		case <-ready:
			// Commit the configuration at the top of the loop, after checking
			// shutdown, rather than treating a clean early exit as readiness.
			continue
		case runtimeErr := <-done:
			observeReadiness()
			current.finished = true
			current.runErr = runtimeErr
			current.cancel()
			if ctx.Err() != nil {
				return stopCurrent()
			}
			started := current.started
			current = nil
			if runtimeErr == nil {
				runtimeErr = errors.New("proxy runtime stopped unexpectedly")
			}
			if !started && lastGood != nil && rollbackCause == nil {
				log.Error("configuration reload failed", "err", runtimeErr)
				log.Warn("restoring previous configuration")
				next, rollbackCause = lastGood, runtimeErr
				continue
			}
			if rollbackCause != nil {
				runtimeErr = errors.Join(rollbackCause, fmt.Errorf("restoring previous configuration: %w", runtimeErr))
			}
			if shouldReturnProxyError(ctx, foreground, runtimeErr) {
				return runtimeErr
			}
			if !started && lastGood == nil {
				log.Error("proxy startup error", "err", runtimeErr)
				log.Error("idling until stopped or reloaded; fix the upstream agent and send SIGHUP")
			} else {
				log.Error("proxy runtime error", "err", runtimeErr)
				log.Error("idling until stopped or reloaded; fix the problem and send SIGHUP")
			}
		}
	}
}

type runtimeInstance struct {
	cfg      *config.Config
	ready    <-chan struct{}
	started  bool
	cancel   context.CancelFunc
	done     chan error
	log      *slog.Logger
	finished bool
	runErr   error
}

func launchRuntime(
	parent context.Context,
	cfgPath string,
	cfg *config.Config,
	cacheTTL time.Duration,
	version Version,
) *runtimeInstance {
	ctx, cancel := context.WithCancel(parent)
	log := logging.Setup(cfg.Debug)
	srv := proxy.NewServer(ctx, cfg.Upstream, cacheTTL, log)
	ready := make(chan struct{})
	var readyOnce sync.Once
	markReady := func() {
		readyOnce.Do(func() { close(ready) })
	}

	telemetryCtx, stopTelemetry := context.WithCancel(ctx)
	var telemetryWG sync.WaitGroup
	if cfg.Debug {
		telemetry := newRuntimeTelemetry(log)
		logTelemetry := func() {
			telemetry.logReport()
			srv.LogTelemetry()
		}
		telemetryWG.Go(func() {
			telemetry.run(telemetryCtx, logTelemetry)
		})
		srv.SetReadyCallback(func() {
			logTelemetry()
			markReady()
		})
	} else {
		srv.SetReadyCallback(markReady)
	}

	log.Info("ssh-agent-proxy", "version", version.Version, "commit", version.Commit, "built", version.Date)
	log.Info("configuration loaded", "config", cfgPath, "groups", len(cfg.Groups))
	log.Info("starting",
		"upstream", cfg.Upstream,
		"cache_seconds", int64(cacheTTL/time.Second),
		"telemetry_sample", telemetrySampleInterval.String(),
		"telemetry_report", telemetryReportInterval.String())

	instance := &runtimeInstance{
		cfg:    cfg,
		ready:  ready,
		cancel: cancel,
		done:   make(chan error, 1),
		log:    log,
	}
	go func() {
		runErr := srv.Run(ctx, cfg.Groups)
		stopTelemetry()
		telemetryWG.Wait()
		instance.done <- runErr
	}()

	return instance
}

func (r *runtimeInstance) stop() error {
	if r.finished {
		return r.runErr
	}
	r.cancel()
	r.runErr = <-r.done
	r.finished = true
	return r.runErr
}

func shouldReturnProxyError(ctx context.Context, foreground bool, err error) bool {
	return foreground || ctx.Err() != nil || errors.Is(err, proxy.ErrListenerFailure)
}
