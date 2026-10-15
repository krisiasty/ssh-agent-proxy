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
	Reload() error
	Status() (Status, error)
	// LogHint describes where the service's logs go, phrased to read after
	// "logs:" (a file path on macOS, a journalctl command on Linux).
	LogHint() string
}

func reloadService(m Manager, signal func(string) error) error {
	st, err := m.Status()
	if err != nil {
		return err
	}
	if !st.Installed {
		return errors.New("ssh-agent-proxy is not installed")
	}
	if !st.Running {
		return errors.New("ssh-agent-proxy is not running")
	}
	if st.PID == "" {
		return errors.New("ssh-agent-proxy service has no process id")
	}
	if err := signal(st.PID); err != nil {
		return fmt.Errorf("signaling ssh-agent-proxy process %s: %w", st.PID, err)
	}
	return nil
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

// executablePath returns the path a service definition should run: the
// absolute, symlink-resolved path to this binary, or a stable link to it when
// the resolved path is specific to one package version.
func executablePath() (string, error) {
	exe, err := CurrentExecutable()
	if err != nil {
		return "", err
	}
	return stableExecutable(exe), nil
}

// CurrentExecutable returns the absolute, symlink-resolved path to this binary.
func CurrentExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locating executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return exe, nil
}

// stableExecutable returns a path to the executable resolved that survives
// package upgrades, or resolved itself. Homebrew keeps each version of a
// formula or cask in its own directory under <prefix>/Cellar or
// <prefix>/Caskroom and links the current version's binary into <prefix>/bin.
// An upgrade repoints that link and removes the old version, so a service
// that saved the versioned path would keep running the old binary or fail to
// start. The link is used only when it is verifiably the same file.
func stableExecutable(resolved string) string {
	for dir := filepath.Dir(resolved); ; {
		parent := filepath.Dir(dir)
		if parent == dir {
			return resolved
		}
		if name := filepath.Base(parent); name == "Cellar" || name == "Caskroom" {
			link := filepath.Join(filepath.Dir(parent), "bin", filepath.Base(resolved))
			if sameFile(link, resolved) {
				return link
			}
			return resolved
		}
		dir = parent
	}
}

func sameFile(left, right string) bool {
	leftInfo, err := os.Stat(left)
	if err != nil {
		return false
	}
	rightInfo, err := os.Stat(right)
	return err == nil && os.SameFile(leftInfo, rightInfo)
}

// SamePath reports whether two paths name the same file once made absolute,
// cleaned, and resolved through symlinks.
func SamePath(left, right string) bool {
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

// CheckProgram reports an installed service whose executable no longer
// exists, for example because a package upgrade removed the version it was
// installed from. Starting such a service cannot succeed.
func CheckProgram(st Status) error {
	if !st.Installed || st.Program == "" {
		return nil
	}
	if _, err := os.Stat(st.Program); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("installed service binary %q no longer exists; run -reinstall to install the current binary", st.Program)
		}
		return fmt.Errorf("checking installed service binary %q: %w", st.Program, err)
	}
	return nil
}
