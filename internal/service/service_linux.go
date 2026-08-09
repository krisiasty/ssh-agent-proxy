//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/krisiasty/ssh-agent-proxy/internal/config"
)

const unitName = "ssh-agent-proxy.service"

type systemdManager struct {
	cfgPath      string
	cacheSeconds int
	unitPath     string
}

// New returns the systemd (user) service manager.
func New(cfgPath string, cacheSeconds int) (Manager, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	return &systemdManager{
		cfgPath:      cfgPath,
		cacheSeconds: cacheSeconds,
		unitPath:     filepath.Join(cfgDir, "systemd", "user", unitName),
	}, nil
}

func (m *systemdManager) installed() bool {
	_, err := os.Stat(m.unitPath)
	return err == nil
}

func (m *systemdManager) Install() error {
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
	if err := os.MkdirAll(filepath.Dir(m.unitPath), 0o700); err != nil {
		return err
	}
	unit := fmt.Sprintf(`[Unit]
Description=SSH Agent Proxy (filtering proxy for ssh-agent)
After=default.target

[Service]
Type=simple
ExecStart=%s -config %s --cache %d
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
`, exe, m.cfgPath, m.cacheSeconds)
	if err := os.WriteFile(m.unitPath, []byte(unit), 0o600); err != nil {
		return fmt.Errorf("writing unit file: %w", err)
	}
	if err := m.systemctl("daemon-reload"); err != nil {
		return err
	}
	return m.systemctl("enable", "--now", unitName)
}

func (m *systemdManager) Uninstall() error {
	var uninstallErr error
	if m.installed() {
		if err := m.systemctl("disable", "--now", unitName); err != nil {
			uninstallErr = errors.Join(uninstallErr, err)
		}
	}
	if err := os.Remove(m.unitPath); err != nil && !os.IsNotExist(err) {
		uninstallErr = errors.Join(uninstallErr, fmt.Errorf("removing unit file: %w", err))
	}
	if err := m.systemctl("daemon-reload"); err != nil {
		uninstallErr = errors.Join(uninstallErr, err)
	}
	return uninstallErr
}

func (m *systemdManager) Reinstall() error { return reinstall(m) }

func (m *systemdManager) LogHint() string {
	return "systemd journal (journalctl --user -u " + unitName + ")"
}

func (m *systemdManager) Start() error   { return m.systemctl("start", unitName) }
func (m *systemdManager) Stop() error    { return m.systemctl("stop", unitName) }
func (m *systemdManager) Restart() error { return m.systemctl("restart", unitName) }

func (m *systemdManager) Status() (Status, error) {
	st := Status{}
	if _, err := os.Stat(m.unitPath); err == nil {
		st.Installed = true
	} else if !os.IsNotExist(err) {
		return st, fmt.Errorf("checking unit file: %w", err)
	}
	if !st.Installed {
		return st, nil
	}

	activeOut, activeErr := m.systemctlOut("is-active", unitName)
	active := strings.TrimSpace(activeOut)
	if activeErr != nil && active != "inactive" && active != "failed" {
		return st, activeErr
	}
	st.Running = active == "active"
	if st.Running {
		pidOut, err := m.systemctlOut("show", "-p", "MainPID", "--value", unitName)
		if err != nil {
			return st, err
		}
		if pid := strings.TrimSpace(pidOut); pid != "" && pid != "0" {
			st.PID = pid
		}
	}
	program, err := m.execStartBinary()
	if err != nil {
		return st, err
	}
	st.Program = program
	return st, nil
}

// execStartBinary reads the binary path from the unit file's ExecStart line.
func (m *systemdManager) execStartBinary() (string, error) {
	data, err := os.ReadFile(m.unitPath)
	if err != nil {
		return "", fmt.Errorf("reading unit file: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "ExecStart="); ok {
			if fields := strings.Fields(rest); len(fields) > 0 {
				return fields[0], nil
			}
		}
	}
	return "", nil
}

func (m *systemdManager) systemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	//nolint:gosec // fixed command; args are program-controlled, not shell-interpreted.
	cmd := exec.CommandContext(ctx, "systemctl", append([]string{"--user"}, args...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl --user %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func (m *systemdManager) systemctlOut(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	//nolint:gosec // fixed command; args are program-controlled, not shell-interpreted.
	cmd := exec.CommandContext(ctx, "systemctl", append([]string{"--user"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("systemctl --user %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}
