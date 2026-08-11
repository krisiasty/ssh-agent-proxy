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
	cfg, err := config.Load(cfgPath)
	if err != nil {
		if foreground {
			return err
		}
		log.Error("configuration error", "err", err)
		log.Error("idling until stopped or reloaded; fix the config and send SIGHUP")
		cfg = nil
	}

	var current *runtimeInstance
	if cfg != nil {
		current, err = launchRuntime(ctx, cfgPath, cfg, cacheTTL, version)
		if err != nil {
			if ctx.Err() != nil {
				return current.stop()
			}
			if shouldReturnProxyError(ctx, foreground, err) {
				return err
			}
			log = current.log
			log.Error("proxy startup error", "err", err)
			log.Error("idling until stopped or reloaded; fix the upstream agent and send SIGHUP")
			current = nil
		} else {
			log = current.log
		}
	}

	for {
		var runtimeDone <-chan error
		if current != nil {
			runtimeDone = current.done
		}
		select {
		case <-ctx.Done():
			if current == nil {
				return nil
			}
			return current.stop()
		case runtimeErr := <-runtimeDone:
			current.finished = true
			current.runErr = runtimeErr
			if runtimeErr == nil {
				runtimeErr = errors.New("proxy runtime stopped unexpectedly")
			}
			if shouldReturnProxyError(ctx, foreground, runtimeErr) {
				return runtimeErr
			}
			log.Error("proxy runtime error", "err", runtimeErr)
			log.Error("idling until stopped or reloaded; fix the problem and send SIGHUP")
			current = nil
		case <-reload:
			candidate, loadErr := config.Load(cfgPath)
			if loadErr != nil {
				log.Error("configuration reload failed; keeping current configuration", "err", loadErr)
				continue
			}

			previous := cfg
			log.Info("configuration reload requested", "config", cfgPath)
			if current != nil {
				if stopErr := current.stop(); stopErr != nil {
					log.Warn("stopping current runtime for reload", "err", stopErr)
				}
				current = nil
			}

			replacement, reloadErr := launchRuntime(ctx, cfgPath, candidate, cacheTTL, version)
			if reloadErr == nil {
				cfg = candidate
				current = replacement
				log = replacement.log
				log.Info("configuration reloaded", "config", cfgPath, "groups", len(candidate.Groups))
				continue
			}
			if ctx.Err() != nil {
				return replacement.stop()
			}
			replacement.log.Error("configuration reload failed", "err", reloadErr)

			if previous == nil {
				if shouldReturnProxyError(ctx, foreground, reloadErr) {
					return reloadErr
				}
				log = replacement.log
				log.Error("idling until stopped or reloaded; fix the problem and send SIGHUP")
				continue
			}

			replacement.log.Warn("restoring previous configuration")
			rollback, rollbackErr := launchRuntime(ctx, cfgPath, previous, cacheTTL, version)
			if rollbackErr == nil {
				current = rollback
				log = rollback.log
				log.Info("previous configuration restored", "config", cfgPath, "groups", len(previous.Groups))
				continue
			}
			if ctx.Err() != nil {
				return rollback.stop()
			}
			if shouldReturnProxyError(ctx, foreground, rollbackErr) {
				return errors.Join(reloadErr, fmt.Errorf("restoring previous configuration: %w", rollbackErr))
			}
			log = rollback.log
			log.Error("restoring previous configuration failed", "err", rollbackErr)
			log.Error("idling until stopped or reloaded; fix the problem and send SIGHUP")
		}
	}
}

type runtimeInstance struct {
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
) (*runtimeInstance, error) {
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

	select {
	case <-ready:
		return instance, nil
	case err := <-instance.done:
		instance.finished = true
		instance.runErr = err
		return instance, err
	case <-parent.Done():
		return instance, parent.Err()
	}
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
