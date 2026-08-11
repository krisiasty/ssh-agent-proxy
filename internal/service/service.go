// Package service installs and controls ssh-agent-proxy as a per-user managed
// service (systemd user unit on Linux, launchd agent on macOS).
package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Label is the reverse-DNS identifier used for the service/agent.
const Label = "io.github.krisiasty.ssh-agent-proxy"

// commandTimeout bounds each launchctl/systemctl invocation.
const commandTimeout = 15 * time.Second

// ErrAlreadyInstalled is returned by Install when the service is already
// installed. Use Reinstall to replace an existing installation.
var ErrAlreadyInstalled = errors.New("ssh-agent-proxy is already installed; use -reinstall to reinstall")

// Status describes the current install/run state of the service.
type Status struct {
	Installed bool
	Running   bool
	PID       string // process id if running, else ""
	Program   string // binary path the service is configured to run, else ""
	Config    string // config path the service is configured to use, else ""
}

// Manager installs and controls the platform service.
type Manager interface {
	Install() error
	Reinstall() error
	Uninstall() error
	Start() error
	Stop() error
	Restart() error
	Status() (Status, error)
	// LogHint describes where the service's logs go, phrased to read after
	// "logs:" (a file path on macOS, a journalctl command on Linux).
	LogHint() string
}

// reinstall replaces an existing installation: uninstall (only if currently
// installed, to avoid spurious "not loaded" errors), then install.
func reinstall(m Manager) error {
	st, err := m.Status()
	if err != nil {
		return err
	}
	if st.Installed {
		if err := m.Uninstall(); err != nil {
			return err
		}
	}
	return m.Install()
}

// executablePath returns the absolute, symlink-resolved path to this binary.
func executablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locating executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return exe, nil
}
