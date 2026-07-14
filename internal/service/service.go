// Package service installs and controls ssh-agent-proxy as a per-user managed
// service (systemd user unit on Linux, launchd agent on macOS).
package service

import (
	"fmt"
	"os"
	"path/filepath"
)

// Label is the reverse-DNS identifier used for the service/agent.
const Label = "io.github.krisiasty.ssh-agent-proxy"

// Status describes the current install/run state of the service.
type Status struct {
	Installed bool
	Running   bool
	Detail    string
}

// Manager installs and controls the platform service.
type Manager interface {
	Install() error
	Uninstall() error
	Start() error
	Stop() error
	Restart() error
	Status() (Status, error)
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
groups: []
#  - socket: ~/.ssh/agent-work.sock
#    keys:
#      - {type: comment, value: laptop@work}
#      - {type: sha256,  value: SHA256:...}
#      - {type: md5,     value: MD5:aa:bb:cc:...}
`
