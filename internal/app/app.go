// Package app wires config, logging and the proxy server into the service
// runtime shared by foreground and managed-service execution.
package app

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/krisiasty/ssh-agent-proxy/internal/config"
	"github.com/krisiasty/ssh-agent-proxy/internal/logging"
	"github.com/krisiasty/ssh-agent-proxy/internal/proxy"
)

// Run loads the config and serves the group sockets until terminated by
// SIGINT/SIGTERM.
//
// If the config cannot be loaded and foreground is false, Run logs the error
// and idles until terminated instead of exiting, so the service manager does
// not restart it in a tight loop. In foreground mode a config error is returned
// to the caller (which exits non-zero).
func Run(cfgPath string, foreground bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log := logging.Setup(false)
		log.Error("configuration error", "path", cfgPath, "err", err)
		if foreground {
			return err
		}
		log.Error("idling until stopped; fix the config and restart the service")
		<-ctx.Done()
		return nil
	}

	log := logging.Setup(cfg.Debug)
	log.Info("starting", "upstream", cfg.Upstream, "groups", len(cfg.Groups), "config", cfgPath)

	srv := proxy.NewServer(cfg.Upstream, log)
	return srv.Run(ctx, cfg.Groups)
}
