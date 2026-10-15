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
	return runWithServers(ctx, reload, cfgPath, foreground, cacheTTL, version, newProxyServer)
}

// runWithServers is runWithReload with the factory that builds each runtime's
// proxy server, so tests can hold a runtime in startup.
func runWithServers(
	ctx context.Context,
	reload <-chan os.Signal,
	cfgPath string,
	foreground bool,
	cacheTTL time.Duration,
	version Version,
	newServer serverFactory,
) error {
	log := logging.Setup(false)
	var current *runtimeInstance
	var lastGood *config.Config

	stopCurrent := func() error {
		if current == nil {
			return nil
		}
		err := current.stop()
		current = nil
		return err
	}
	observeReadiness := func() {
		if current.state() == runtimeIdle || current.state() == runtimeServing || ctx.Err() != nil {
			return
		}
		select {
		case <-current.ready:
			restored := current.state() == runtimeRollingBack
			current.serving = true
			current.rollbackCause = nil
			lastGood = current.cfg
			switch {
			case restored:
				log.Info("previous configuration restored", "config", cfgPath, "groups", len(lastGood.Groups))
			case current.reloaded:
				log.Info("configuration reloaded", "config", cfgPath, "groups", len(lastGood.Groups))
			}
		default:
		}
	}
	start := func(cfg *config.Config, rollbackCause error, reloaded bool) error {
		stopErr := stopCurrent()
		if ctx.Err() != nil {
			return stopErr
		}
		if stopErr != nil {
			log.Warn("stopping current runtime for reload", "err", stopErr)
		}
		current = launchRuntime(ctx, newServer, cfgPath, cfg, cacheTTL, version)
		current.reloaded = reloaded
		current.rollbackCause = rollbackCause
		log = current.log
		return nil
	}
	loadConfiguration := func(initial bool) error {
		if ctx.Err() != nil {
			return stopCurrent()
		}
		candidate, loadErr := config.Load(cfgPath)
		if ctx.Err() != nil {
			return stopCurrent()
		}
		observeReadiness()
		if loadErr == nil {
			if !initial {
				log.Info("configuration reload requested", "config", cfgPath)
			}
			return start(candidate, nil, !initial)
		}

		switch current.state() {
		case runtimeStarting:
			if lastGood != nil {
				log.Error("configuration reload failed", "err", loadErr)
				log.Warn("restoring previous configuration")
				return start(lastGood, loadErr, true)
			}
			log.Error("configuration reload failed; keeping current configuration", "err", loadErr)
		case runtimeRollingBack, runtimeServing:
			log.Error("configuration reload failed; keeping current configuration", "err", loadErr)
		case runtimeIdle:
			switch {
			case lastGood != nil:
				log.Error("configuration reload failed; remaining idle", "err", loadErr)
			case foreground:
				return loadErr
			default:
				log.Error("configuration error", "err", loadErr)
				log.Error("idling until stopped or reloaded; fix the config and send SIGHUP")
			}
		}
		return nil
	}

	if err := loadConfiguration(true); err != nil {
		return err
	}
	for {
		// Every startup, reload, and rollback passes this shutdown check.
		if ctx.Err() != nil {
			return stopCurrent()
		}
		observeReadiness()
		var ready <-chan struct{}
		var done <-chan error
		if current != nil {
			done = current.done
			if current.state() != runtimeServing {
				ready = current.ready
			}
		}
		select {
		case <-ctx.Done():
			return stopCurrent()
		case <-reload:
			if err := loadConfiguration(false); err != nil {
				return err
			}
		case <-ready:
			// select picks randomly among ready arms, so readiness can win
			// over a concurrent shutdown. Commit it at the top of the loop,
			// after the shutdown check, so a runtime that is being stopped is
			// never recorded as the last good configuration.
			continue
		case runtimeErr := <-done:
			observeReadiness()
			state, rollbackCause := current.state(), current.rollbackCause
			current.markFinished(runtimeErr)
			if ctx.Err() != nil {
				return stopCurrent()
			}
			current = nil
			if runtimeErr == nil {
				runtimeErr = errors.New("proxy runtime stopped unexpectedly")
			}
			if state == runtimeStarting && lastGood != nil {
				log.Error("configuration reload failed", "err", runtimeErr)
				log.Warn("restoring previous configuration")
				if err := start(lastGood, runtimeErr, true); err != nil {
					return err
				}
				continue
			}
			if state == runtimeRollingBack {
				runtimeErr = errors.Join(rollbackCause, fmt.Errorf("restoring previous configuration: %w", runtimeErr))
			}
			if shouldReturnProxyError(foreground, runtimeErr) {
				return runtimeErr
			}
			switch state {
			case runtimeRollingBack:
				log.Error("restoring previous configuration failed", "err", runtimeErr)
				log.Error("idling until stopped or reloaded; fix the problem and send SIGHUP")
			case runtimeStarting:
				log.Error("proxy startup error", "err", runtimeErr)
				log.Error("idling until stopped or reloaded; fix the upstream agent and send SIGHUP")
			default:
				log.Error("proxy runtime error", "err", runtimeErr)
				log.Error("idling until stopped or reloaded; fix the problem and send SIGHUP")
			}
		}
	}
}

type runtimeState uint8

const (
	runtimeIdle runtimeState = iota
	runtimeStarting
	runtimeRollingBack
	runtimeServing
)

type runtimeInstance struct {
	cfg           *config.Config
	ready         <-chan struct{}
	serving       bool
	reloaded      bool
	rollbackCause error
	cancel        context.CancelFunc
	done          chan error
	log           *slog.Logger
	finished      bool
	runErr        error
}

// runtimeServer is the part of proxy.Server that a runtime drives.
type runtimeServer interface {
	Run(ctx context.Context, groups []config.Group) error
	SetReadyCallback(callback func())
	LogTelemetry()
}

// serverFactory builds the proxy server for one runtime.
type serverFactory func(ctx context.Context, upstream string, cacheTTL time.Duration, log *slog.Logger) runtimeServer

func newProxyServer(ctx context.Context, upstream string, cacheTTL time.Duration, log *slog.Logger) runtimeServer {
	return proxy.NewServer(ctx, upstream, cacheTTL, log)
}

func launchRuntime(
	parent context.Context,
	newServer serverFactory,
	cfgPath string,
	cfg *config.Config,
	cacheTTL time.Duration,
	version Version,
) *runtimeInstance {
	ctx, cancel := context.WithCancel(parent)
	log := logging.Setup(cfg.Debug)
	srv := newServer(ctx, cfg.Upstream, cacheTTL, log)
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

// state treats the absence of a runtime as idle. A runtime launched with a
// rollback cause is rolling back until it becomes ready, so the cause is the
// single record of that phase.
func (r *runtimeInstance) state() runtimeState {
	switch {
	case r == nil:
		return runtimeIdle
	case r.serving:
		return runtimeServing
	case r.rollbackCause != nil:
		return runtimeRollingBack
	default:
		return runtimeStarting
	}
}

// markFinished records a consumed completion result and releases the context.
func (r *runtimeInstance) markFinished(err error) {
	r.runErr = err
	r.finished = true
	r.cancel()
}

func (r *runtimeInstance) stop() error {
	if !r.finished {
		r.cancel()
		r.markFinished(<-r.done)
	}
	return r.runErr
}

func shouldReturnProxyError(foreground bool, err error) bool {
	return foreground || errors.Is(err, proxy.ErrListenerFailure)
}
