// Command ssh-agent-proxy is a filtering proxy in front of an SSH agent.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/krisiasty/ssh-agent-proxy/internal/app"
	"github.com/krisiasty/ssh-agent-proxy/internal/config"
	"github.com/krisiasty/ssh-agent-proxy/internal/diag"
	"github.com/krisiasty/ssh-agent-proxy/internal/proxy"
	"github.com/krisiasty/ssh-agent-proxy/internal/service"
)

const (
	defaultCacheSeconds = 3
	minCacheSeconds     = 0
	maxCacheSeconds     = 60
)

// Build metadata, injected via -ldflags by GoReleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		fInstall    = flag.Bool("install", false, "install and start the service, then exit")
		fReinstall  = flag.Bool("reinstall", false, "reinstall (uninstall then install) the service, then exit")
		fUninstall  = flag.Bool("uninstall", false, "stop and remove the service, then exit")
		fStart      = flag.Bool("start", false, "start the service, then exit")
		fStop       = flag.Bool("stop", false, "stop the service, then exit")
		fRestart    = flag.Bool("restart", false, "restart the service, then exit")
		fReload     = flag.Bool("reload", false, "reload the running service configuration, then exit")
		fStatus     = flag.Bool("status", false, "print service status, then exit")
		fDiag       = flag.Bool("diag", false, "check configuration, service, upstream, and group health, then exit")
		fList       = flag.Bool("list", false, "list upstream keys as ready-to-paste config entries")
		fForeground = flag.Bool("foreground", false, "run in the foreground, logging to stdout")
		fConfig     = flag.String("config", "", "path to config file (default: <user config dir>/ssh-agent-proxy/config.yaml)")
		fCache      = flag.Int("cache", defaultCacheSeconds, "cache upstream identities for 0-60 seconds (0 disables caching)")
		fVersion    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()
	if err := validateCacheSeconds(*fCache); err != nil {
		return err
	}

	if *fVersion {
		fmt.Printf("ssh-agent-proxy %s (commit %s, built %s)\n", version, commit, date)
		return nil
	}

	cfgPath := *fConfig
	if cfgPath == "" {
		p, err := config.DefaultPath()
		if err != nil {
			return err
		}
		cfgPath = p
	}

	// Ensure at most one lifecycle action is requested.
	actions := map[string]bool{
		"-install": *fInstall, "-reinstall": *fReinstall, "-uninstall": *fUninstall,
		"-start": *fStart, "-stop": *fStop, "-restart": *fRestart, "-reload": *fReload,
		"-status": *fStatus, "-diag": *fDiag, "-list": *fList,
	}
	var chosen string
	for name, set := range actions {
		if !set {
			continue
		}
		if chosen != "" {
			return fmt.Errorf("%s and %s cannot be combined", chosen, name)
		}
		chosen = name
	}

	switch chosen {
	case "-list":
		return listKeys(cfgPath)
	case "-diag":
		return diag.Run(context.Background(), cfgPath, *fCache, os.Stdout)
	case "":
		// No lifecycle action: run the service runtime. In foreground mode,
		// scaffold a default config if none exists yet so the tool can be
		// tried without installing a service first.
		if *fForeground {
			created, err := config.EnsureScaffold(cfgPath)
			if err != nil {
				return err
			}
			if created {
				fmt.Printf("created default config: %s\nedit it, then send SIGHUP to reload\n", cfgPath)
			}
		}
		return app.Run(cfgPath, *fForeground, time.Duration(*fCache)*time.Second, app.Version{Version: version, Commit: commit, Date: date})
	default:
		return manageService(cfgPath, chosen, *fCache)
	}
}

func validateCacheSeconds(seconds int) error {
	if seconds < minCacheSeconds || seconds > maxCacheSeconds {
		return fmt.Errorf("--cache must be between %d and %d seconds", minCacheSeconds, maxCacheSeconds)
	}
	return nil
}

func listKeys(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	return proxy.ListUpstream(cfg.Upstream, os.Stdout)
}

func manageService(cfgPath, action string, cacheSeconds int) error {
	mgr, err := service.New(cfgPath, cacheSeconds)
	if err != nil {
		return err
	}
	switch action {
	case "-install":
		if err := mgr.Install(); err != nil {
			return err
		}
		printInstalled(cfgPath, mgr)
	case "-reinstall":
		if err := mgr.Reinstall(); err != nil {
			return err
		}
		printInstalled(cfgPath, mgr)
	case "-uninstall":
		if err := mgr.Uninstall(); err != nil {
			return err
		}
		fmt.Println("ssh-agent-proxy uninstalled.")
	case "-start":
		if err := mgr.Start(); err != nil {
			return err
		}
		fmt.Println("ssh-agent-proxy started.")
	case "-stop":
		if err := mgr.Stop(); err != nil {
			return err
		}
		fmt.Println("ssh-agent-proxy stopped.")
	case "-restart":
		if err := mgr.Restart(); err != nil {
			return err
		}
		fmt.Println("ssh-agent-proxy restarted.")
	case "-reload":
		if err := mgr.Reload(); err != nil {
			return err
		}
		fmt.Println("ssh-agent-proxy reload requested.")
	case "-status":
		st, err := mgr.Status()
		if err != nil {
			return err
		}
		fmt.Printf("installed: %t\n", st.Installed)
		fmt.Printf("running:   %t\n", st.Running)
		if st.PID != "" {
			fmt.Printf("pid:       %s\n", st.PID)
		}
		if st.Program != "" {
			fmt.Printf("binary:    %s\n", st.Program)
		}
		fmt.Printf("config:    %s\n", cfgPath)
		fmt.Printf("logs:      %s\n", mgr.LogHint())
	}
	return nil
}

// printInstalled reports the config and log locations after a successful
// install or reinstall.
func printInstalled(cfgPath string, mgr service.Manager) {
	fmt.Println("ssh-agent-proxy installed and started.")
	fmt.Printf("  config: %s\n", cfgPath)
	fmt.Printf("  logs:   %s\n", mgr.LogHint())
	fmt.Println("\nEdit the config, then run: ssh-agent-proxy -reload")
}
