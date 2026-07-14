// Package service installs and controls ssh-agent-proxy as a per-user managed
// service (systemd user unit on Linux, launchd agent on macOS).
package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Label is the reverse-DNS identifier used for the service/agent.
const Label = "io.github.krisiasty.ssh-agent-proxy"

// ErrAlreadyInstalled is returned by Install when the service is already
// installed. Use Reinstall to replace an existing installation.
var ErrAlreadyInstalled = errors.New("ssh-agent-proxy is already installed; use -reinstall to reinstall")

// Status describes the current install/run state of the service.
type Status struct {
	Installed bool
	Running   bool
	PID       string // process id if running, else ""
	Program   string // binary path the service is configured to run, else ""
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

// ensureConfigScaffold creates the config directory and, if no config exists
// yet, writes a commented sample so the user has a starting point.
func ensureConfigScaffold(cfgPath string) error {
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if err := os.WriteFile(cfgPath, []byte(sampleConfig), 0o600); err != nil {
			return fmt.Errorf("writing sample config: %w", err)
		}
	}
	return nil
}

const sampleConfig = `# ssh-agent-proxy configuration.
# Run 'ssh-agent-proxy -list' to print your upstream keys as ready-to-paste entries.

# Path to the upstream SSH agent socket (required). Env vars are expanded.
upstream: ${SSH_AUTH_SOCK}

# Verbose logging.
debug: false

# Filtered views of the upstream agent. Each group is exposed on its own socket;
# point a client at it with: export SSH_AUTH_SOCK=<socket>
# Populate a group's keys with entries from 'ssh-agent-proxy -list'
# (match by comment, sha256 or md5).
groups:
  - name: default
    enabled: false
    socket: ~/.ssh/agent-default.sock
    keys: []
`
