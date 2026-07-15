//go:build darwin

package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

func (m *launchdManager) installed() bool {
	_, err := os.Stat(m.plistPath)
	return err == nil
}

func (m *launchdManager) Install() error {
	if m.installed() {
		return ErrAlreadyInstalled
	}
	if err := ensureConfigScaffold(m.cfgPath); err != nil {
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
	if err := os.WriteFile(m.plistPath, []byte(plist), 0o600); err != nil {
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

func (m *launchdManager) Reinstall() error { return reinstall(m) }

func (m *launchdManager) LogHint() string { return m.logPath }

func (m *launchdManager) Start() error { return m.launchctl("start", Label) }
func (m *launchdManager) Stop() error  { return m.launchctl("stop", Label) }

func (m *launchdManager) Restart() error {
	_ = m.Stop()
	return m.Start()
}

var (
	reLaunchdPID     = regexp.MustCompile(`"PID"\s*=\s*(\d+);`)
	reLaunchdProgram = regexp.MustCompile(`"Program"\s*=\s*"([^"]*)";`)
	reLaunchdArg0    = regexp.MustCompile(`"ProgramArguments"\s*=\s*\(\s*"([^"]*)"`)
)

func (m *launchdManager) Status() (Status, error) {
	st := Status{}
	if _, err := os.Stat(m.plistPath); err == nil {
		st.Installed = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "launchctl", "list", Label).CombinedOutput() //nolint:gosec // fixed command; Label is a package constant.
	if err == nil {
		s := string(out)
		if mt := reLaunchdPID.FindStringSubmatch(s); mt != nil {
			st.Running = true
			st.PID = mt[1]
		}
		if mt := reLaunchdProgram.FindStringSubmatch(s); mt != nil {
			st.Program = mt[1]
		} else if mt := reLaunchdArg0.FindStringSubmatch(s); mt != nil {
			st.Program = mt[1]
		}
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
