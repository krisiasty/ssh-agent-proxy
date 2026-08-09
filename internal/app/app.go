// Package app wires config, logging and the proxy server into the service
// runtime shared by foreground and managed-service execution.
package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
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
// SIGINT/SIGTERM.
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
	return run(ctx, cfgPath, foreground, cacheTTL, version)
}

func run(ctx context.Context, cfgPath string, foreground bool, cacheTTL time.Duration, version Version) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		if foreground {
			return err
		}

		log := logging.Setup(false)
		log.Error("configuration error", "err", err)
		log.Error("idling until stopped; fix the config and restart the service")
		<-ctx.Done()
		return nil
	}

	log := logging.Setup(cfg.Debug)
	log.Info("ssh-agent-proxy", "version", version.Version, "commit", version.Commit, "built", version.Date)
	log.Info("configuration loaded", "config", cfgPath, "groups", len(cfg.Groups))
	log.Info("starting", "upstream", cfg.Upstream, "cache_seconds", int64(cacheTTL/time.Second))

	srv := proxy.NewServer(cfg.Upstream, cacheTTL, log)
	if err := srv.Run(ctx, cfg.Groups); err != nil {
		if foreground || ctx.Err() != nil {
			return err
		}
		log.Error("proxy startup error", "err", err)
		log.Error("idling until stopped; fix the upstream agent and restart the service")
		<-ctx.Done()
	}
	return nil
}
