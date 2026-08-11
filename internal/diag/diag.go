// Package diag performs read-only health checks for ssh-agent-proxy.
package diag

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/krisiasty/ssh-agent-proxy/internal/config"
	"github.com/krisiasty/ssh-agent-proxy/internal/keys"
	"github.com/krisiasty/ssh-agent-proxy/internal/proxy"
	"github.com/krisiasty/ssh-agent-proxy/internal/service"
	"golang.org/x/crypto/ssh/agent"
)

const probeTimeout = 5 * time.Second

// ErrFailures reports that at least one diagnostic check failed.
var ErrFailures = errors.New("diagnostics found failures")

type level string

const (
	pass level = "PASS"
	warn level = "WARN"
	fail level = "FAIL"
)

type result struct {
	level   level
	message string
}

type report struct {
	results []result
}

func (r *report) add(level level, format string, args ...any) {
	r.results = append(r.results, result{level: level, message: fmt.Sprintf(format, args...)})
}

func (r *report) writeTo(w io.Writer) error {
	counts := map[level]int{}
	for _, result := range r.results {
		counts[result.level]++
		if _, err := fmt.Fprintf(w, "[%s] %s\n", result.level, result.message); err != nil {
			return err
		}
	}
	summaryLevel := pass
	if counts[fail] > 0 {
		summaryLevel = fail
	} else if counts[warn] > 0 {
		summaryLevel = warn
	}
	_, err := fmt.Fprintf(
		w,
		"[%s] summary: %d passed, %d %s, %d failed\n",
		summaryLevel,
		counts[pass],
		counts[warn],
		plural(counts[warn], "warning"),
		counts[fail],
	)
	return err
}

type dependencies struct {
	loadConfig        func(string) (*config.Config, error)
	serviceStatus     func(string, int) (service.Status, error)
	listAgentKeys     func(context.Context, string) ([]*agent.Key, error)
	currentExecutable func() (string, error)
}

func defaultDependencies() dependencies {
	return dependencies{
		loadConfig: config.Load,
		serviceStatus: func(cfgPath string, cacheSeconds int) (service.Status, error) {
			manager, err := service.New(cfgPath, cacheSeconds)
			if err != nil {
				return service.Status{}, err
			}
			return manager.Status()
		},
		listAgentKeys: proxy.ListAgentKeys,
		currentExecutable: func() (string, error) {
			executable, err := os.Executable()
			if err != nil {
				return "", err
			}
			if resolved, err := filepath.EvalSymlinks(executable); err == nil {
				executable = resolved
			}
			return executable, nil
		},
	}
}

// Run checks the selected configuration, service, upstream agent, selectors,
// and enabled group sockets. It never modifies service or socket state.
func Run(ctx context.Context, cfgPath string, cacheSeconds int, w io.Writer) error {
	return run(ctx, cfgPath, cacheSeconds, w, defaultDependencies())
}

func run(ctx context.Context, cfgPath string, cacheSeconds int, w io.Writer, deps dependencies) error {
	report := &report{}

	cfg, cfgErr := deps.loadConfig(cfgPath)
	if cfgErr != nil {
		report.add(fail, "config: %v", cfgErr)
	} else {
		enabled := 0
		for i := range cfg.Groups {
			if cfg.Groups[i].IsEnabled() {
				enabled++
			}
		}
		report.add(pass, "config: loaded %q (%d groups, %d enabled)", cfgPath, len(cfg.Groups), enabled)
	}

	status, statusErr := deps.serviceStatus(cfgPath, cacheSeconds)
	if statusErr != nil {
		report.add(fail, "service: unable to inspect managed service: %v", statusErr)
	} else {
		checkService(report, cfgPath, status, deps.currentExecutable)
	}

	if cfg != nil {
		checkGroups(ctx, report, cfg, statusErr == nil && !status.Installed, deps.listAgentKeys)
	}

	if err := report.writeTo(w); err != nil {
		return fmt.Errorf("writing diagnostic report: %w", err)
	}
	for _, result := range report.results {
		if result.level == fail {
			return ErrFailures
		}
	}
	return nil
}

func checkService(r *report, selectedConfig string, status service.Status, currentExecutable func() (string, error)) {
	if !status.Installed {
		r.add(warn, "service: no managed service installation found")
		return
	}
	if status.Running {
		if status.PID == "" {
			r.add(pass, "service: managed service is running")
		} else {
			r.add(pass, "service: managed service is running (pid %s)", status.PID)
		}
	} else {
		r.add(fail, "service: managed service is installed but stopped")
	}

	switch {
	case status.Config == "":
		r.add(warn, "service config: installed definition has no explicit config path")
	case samePath(status.Config, selectedConfig):
		r.add(pass, "service config: installed service uses selected config %q", selectedConfig)
	default:
		r.add(fail, "service config: installed service uses %q instead of selected config %q", status.Config, selectedConfig)
	}

	if status.Program == "" {
		r.add(warn, "service binary: installed definition does not identify an executable")
		return
	}
	current, err := currentExecutable()
	if err != nil {
		r.add(warn, "service binary: unable to locate current executable: %v", err)
		return
	}
	if samePath(status.Program, current) {
		r.add(pass, "service binary: installed service uses the current executable")
	} else {
		r.add(warn, "service binary: installed service uses %q instead of current executable %q", status.Program, current)
	}
}

func checkGroups(
	ctx context.Context,
	r *report,
	cfg *config.Config,
	unmanaged bool,
	listAgentKeys func(context.Context, string) ([]*agent.Key, error),
) {
	upstream, upstreamErr := probe(ctx, cfg.Upstream, listAgentKeys)
	if upstreamErr != nil {
		r.add(fail, "upstream: %v", upstreamErr)
	} else {
		r.add(pass, "upstream: agent responded with %d %s", len(upstream), plural(len(upstream), "key"))
	}

	enabled := 0
	healthySockets := 0
	for i := range cfg.Groups {
		group := &cfg.Groups[i]
		if !group.IsEnabled() {
			r.add(pass, "group %q: disabled (%d %s; socket not probed)", group.Name, len(group.Matchers()), plural(len(group.Matchers()), "selector"))
			continue
		}
		enabled++

		var expected []*agent.Key
		if upstreamErr == nil {
			var matchCounts []int
			expected, matchCounts = keys.Resolve(upstream, group.Matchers())
			unmatched := 0
			for _, count := range matchCounts {
				if count == 0 {
					unmatched++
				}
			}
			r.add(
				pass,
				"group %q selectors: %d %s resolved to %d %s",
				group.Name,
				len(group.Matchers()),
				plural(len(group.Matchers()), "selector"),
				len(expected),
				plural(len(expected), "key"),
			)
			if unmatched > 0 {
				r.add(warn, "group %q selectors: %d of %d %s matched no upstream key", group.Name, unmatched, len(group.Matchers()), plural(len(group.Matchers()), "selector"))
			}
		}

		actual, socketErr := probe(ctx, group.Socket, listAgentKeys)
		if socketErr != nil {
			r.add(fail, "group %q socket: %v", group.Name, socketErr)
			continue
		}
		if upstreamErr != nil {
			r.add(warn, "group %q socket: agent responded with %d %s; expected set unavailable", group.Name, len(actual), plural(len(actual), "key"))
			continue
		}
		if !sameKeys(actual, expected) {
			r.add(fail, "group %q socket: returned %d %s; expected %d in configured order", group.Name, len(actual), plural(len(actual), "key"), len(expected))
			continue
		}
		healthySockets++
		r.add(pass, "group %q socket: returned the expected %d %s in configured order", group.Name, len(expected), plural(len(expected), "key"))
	}

	if !unmanaged {
		return
	}
	switch {
	case enabled == 0:
		r.add(warn, "service mode: unmanaged configuration has no enabled group sockets to probe")
	case healthySockets == enabled:
		r.add(pass, "service mode: foreground/unmanaged proxy is serving all enabled groups")
	default:
		r.add(fail, "service mode: no healthy managed service; %d of %d enabled group sockets passed", healthySockets, enabled)
	}
}

func probe(ctx context.Context, socket string, listAgentKeys func(context.Context, string) ([]*agent.Key, error)) ([]*agent.Key, error) {
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	return listAgentKeys(probeCtx, socket)
}

func sameKeys(left, right []*agent.Key) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].Format != right[i].Format || !bytes.Equal(left[i].Blob, right[i].Blob) {
			return false
		}
	}
	return true
}

func samePath(left, right string) bool {
	return normalizedPath(left) == normalizedPath(right)
}

func normalizedPath(path string) string {
	absolute, err := filepath.Abs(path)
	if err == nil {
		path = absolute
	}
	path = filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	return path
}

func plural(count int, singular string) string {
	if count == 1 {
		return singular
	}
	return singular + "s"
}
