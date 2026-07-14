//go:build linux

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const unitName = "ssh-agent-proxy.service"

type systemdManager struct {
	cfgPath  string
	unitPath string
}

// New returns the systemd (user) service manager.
func New(cfgPath string) (Manager, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	return &systemdManager{
		cfgPath:  cfgPath,
		unitPath: filepath.Join(cfgDir, "systemd", "user", unitName),
	}, nil
}

func (m *systemdManager) Install() error {
	if err := ensureConfigScaffold(m.cfgPath); err != nil {
		return err
	}
	exe, err := executablePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.unitPath), 0o755); err != nil {
		return err
	}
	unit := fmt.Sprintf(`[Unit]
Description=SSH Agent Proxy (filtering proxy for ssh-agent)
After=default.target

[Service]
Type=simple
ExecStart=%s -config %s
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
`, exe, m.cfgPath)
	if err := os.WriteFile(m.unitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("writing unit file: %w", err)
	}
	if err := m.systemctl("daemon-reload"); err != nil {
		return err
	}
	return m.systemctl("enable", "--now", unitName)
}

func (m *systemdManager) Uninstall() error {
	// Best-effort disable; ignore errors if not currently loaded.
	_ = m.systemctl("disable", "--now", unitName)
	if err := os.Remove(m.unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing unit file: %w", err)
	}
	return m.systemctl("daemon-reload")
}

func (m *systemdManager) Start() error   { return m.systemctl("start", unitName) }
func (m *systemdManager) Stop() error    { return m.systemctl("stop", unitName) }
func (m *systemdManager) Restart() error { return m.systemctl("restart", unitName) }

func (m *systemdManager) Status() (Status, error) {
	installed := true
	if _, err := os.Stat(m.unitPath); os.IsNotExist(err) {
		installed = false
	}
	active := strings.TrimSpace(m.systemctlOut("is-active", unitName))
	detail := strings.TrimSpace(m.systemctlOut("--no-pager", "status", unitName))
	return Status{
		Installed: installed,
		Running:   active == "active",
		Detail:    detail,
	}, nil
}

func (m *systemdManager) systemctl(args ...string) error {
	cmd := exec.Command("systemctl", append([]string{"--user"}, args...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl --user %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func (m *systemdManager) systemctlOut(args ...string) string {
	cmd := exec.Command("systemctl", append([]string{"--user"}, args...)...)
	out, _ := cmd.CombinedOutput()
	return string(out)
}
