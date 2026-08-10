//go:build darwin

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/krisiasty/ssh-agent-proxy/internal/config"
)

type launchdManager struct {
	cfgPath      string
	cacheSeconds int
	plistPath    string
	logPath      string
}

// New returns the launchd (LaunchAgent) service manager.
func New(cfgPath string, cacheSeconds int) (Manager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return &launchdManager{
		cfgPath:      cfgPath,
		cacheSeconds: cacheSeconds,
		plistPath:    filepath.Join(home, "Library", "LaunchAgents", Label+".plist"),
		logPath:      filepath.Join(home, "Library", "Logs", "ssh-agent-proxy.log"),
	}, nil
}

func (m *launchdManager) installed() bool {
	_, err := os.Stat(m.plistPath)
	return err == nil
}

func (m *launchdManager) Install() error {
	if m.installed() {
		return ErrAlreadyInstalled
	}
	if _, err := config.EnsureScaffold(m.cfgPath); err != nil {
		return err
	}
	exe, err := executablePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.plistPath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.logPath), 0o700); err != nil {
		return err
	}
	plist, err := renderLaunchdPlist(
		Label,
		[]string{exe, "-config", m.cfgPath, "--cache", strconv.Itoa(m.cacheSeconds)},
		m.logPath,
	)
	if err != nil {
		return err
	}
	if err := os.WriteFile(m.plistPath, plist, 0o600); err != nil {
		return fmt.Errorf("writing plist: %w", err)
	}
	return m.launchctl("load", "-w", m.plistPath)
}

func (m *launchdManager) Uninstall() error {
	var uninstallErr error
	if m.installed() {
		if err := m.launchctl("unload", "-w", m.plistPath); err != nil {
			uninstallErr = errors.Join(uninstallErr, err)
		}
	}
	if err := os.Remove(m.plistPath); err != nil && !os.IsNotExist(err) {
		uninstallErr = errors.Join(uninstallErr, fmt.Errorf("removing plist: %w", err))
	}
	return uninstallErr
}

func (m *launchdManager) Reinstall() error { return reinstall(m) }

func (m *launchdManager) LogHint() string { return m.logPath }

func (m *launchdManager) Start() error { return m.launchctl("start", Label) }
func (m *launchdManager) Stop() error  { return m.launchctl("stop", Label) }

func (m *launchdManager) Restart() error {
	st, err := m.Status()
	if err != nil {
		return err
	}
	if st.Running {
		if err := m.Stop(); err != nil {
			return err
		}
	}
	return m.Start()
}

var reLaunchdPID = regexp.MustCompile(`"PID"\s*=\s*(\d+);`)

func (m *launchdManager) Status() (Status, error) {
	st := Status{}
	if _, err := os.Stat(m.plistPath); err == nil {
		st.Installed = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "launchctl", "list", Label).CombinedOutput()
	if err == nil {
		s := string(out)
		if mt := reLaunchdPID.FindStringSubmatch(s); mt != nil {
			st.Running = true
			st.PID = mt[1]
		}
		program, parseErr := parseLaunchdProgram(s)
		if parseErr != nil {
			return st, parseErr
		}
		st.Program = program
	}
	return st, nil
}

func (m *launchdManager) launchctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "launchctl", args...) //nolint:gosec // fixed command; args are program-controlled, not shell-interpreted.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("launchctl %s: %w", strings.Join(args, " "), err)
	}
	return nil
}
