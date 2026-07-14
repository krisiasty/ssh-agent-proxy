//go:build darwin

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type launchdManager struct {
	cfgPath   string
	plistPath string
	logPath   string
}

// New returns the launchd (LaunchAgent) service manager.
func New(cfgPath string) (Manager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return &launchdManager{
		cfgPath:   cfgPath,
		plistPath: filepath.Join(home, "Library", "LaunchAgents", Label+".plist"),
		logPath:   filepath.Join(home, "Library", "Logs", "ssh-agent-proxy.log"),
	}, nil
}

func (m *launchdManager) Install() error {
	if err := ensureConfigScaffold(m.cfgPath); err != nil {
		return err
	}
	exe, err := executablePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.plistPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.logPath), 0o755); err != nil {
		return err
	}
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>-config</string>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, Label, exe, m.cfgPath, m.logPath, m.logPath)
	if err := os.WriteFile(m.plistPath, []byte(plist), 0o644); err != nil {
		return fmt.Errorf("writing plist: %w", err)
	}
	return m.launchctl("load", "-w", m.plistPath)
}

func (m *launchdManager) Uninstall() error {
	_ = m.launchctl("unload", "-w", m.plistPath)
	if err := os.Remove(m.plistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing plist: %w", err)
	}
	return nil
}

func (m *launchdManager) Start() error { return m.launchctl("start", Label) }
func (m *launchdManager) Stop() error  { return m.launchctl("stop", Label) }

func (m *launchdManager) Restart() error {
	_ = m.Stop()
	return m.Start()
}

func (m *launchdManager) Status() (Status, error) {
	installed := true
	if _, err := os.Stat(m.plistPath); os.IsNotExist(err) {
		installed = false
	}
	out, err := exec.Command("launchctl", "list", Label).CombinedOutput()
	running := err == nil && strings.Contains(string(out), "\"PID\"")
	detail := strings.TrimSpace(string(out))
	if !installed {
		detail = "not installed"
	}
	return Status{Installed: installed, Running: running, Detail: detail}, nil
}

func (m *launchdManager) launchctl(args ...string) error {
	cmd := exec.Command("launchctl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("launchctl %s: %w", strings.Join(args, " "), err)
	}
	return nil
}
