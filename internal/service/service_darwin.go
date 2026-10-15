//go:build darwin

package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/krisiasty/ssh-agent-proxy/internal/config"
)

// launchctlRunner runs launchctl with args and returns its stdout and stderr.
type launchctlRunner func(ctx context.Context, args ...string) (stdout, stderr []byte, err error)

func runLaunchctl(ctx context.Context, args ...string) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "launchctl", args...) //nolint:gosec // fixed command; args are program-controlled, not shell-interpreted.
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// processAlive reports whether a process with pid exists.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// launchctlServiceNotFound is launchctl's exit status for a service that is
// not loaded in the targeted domain ("Could not find specified service").
const launchctlServiceNotFound = 113

type launchdManager struct {
	cfgPath      string
	cacheSeconds int
	plistPath    string
	logPath      string
	uid          int

	run   launchctlRunner
	alive func(pid int) bool
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
		uid:          os.Getuid(),
		run:          runLaunchctl,
		alive:        processAlive,
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

func (m *launchdManager) Start() error  { return m.launchctl("start", Label) }
func (m *launchdManager) Stop() error   { return m.launchctl("stop", Label) }
func (m *launchdManager) Reload() error { return reloadService(m, signalReload) }

// Restart replaces the running process, or starts the job if it is stopped,
// in one launchd operation. Separate stop and start requests race: "stop" only
// signals the process, a start that arrives while it is still exiting is
// ignored, and the clean exit that follows is not relaunched, leaving the
// service stopped. Success requires launchd to report a new process that is
// still alive; whether it then becomes ready is not checked here.
func (m *launchdManager) Restart() error {
	st, err := m.Status()
	if err != nil {
		return err
	}
	if !st.Installed {
		return errors.New("ssh-agent-proxy is not installed")
	}
	pid, err := m.kickstart()
	if err != nil {
		return err
	}
	if st.PID == strconv.Itoa(pid) {
		return fmt.Errorf("restart did not replace ssh-agent-proxy process %d", pid)
	}
	if !m.alive(pid) {
		return fmt.Errorf("restarted ssh-agent-proxy process %d exited immediately; see %s", pid, m.logPath)
	}
	return nil
}

// kickstart kills any running instance of the job and starts a new one with
// launchctl kickstart -k, returning the new process ID. The legacy load used
// at install time registers the job in the user's GUI domain when installed
// from a login session, and in the user domain otherwise.
func (m *launchdManager) kickstart() (int, error) {
	for _, domain := range []string{"gui", "user"} {
		target := fmt.Sprintf("%s/%d/%s", domain, m.uid, Label)
		args := []string{"kickstart", "-kp", target}
		ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
		stdout, stderr, err := m.run(ctx, args...)
		cancel()
		var exitErr interface{ ExitCode() int }
		if errors.As(err, &exitErr) && exitErr.ExitCode() == launchctlServiceNotFound {
			continue
		}
		if err != nil {
			return 0, launchctlCommandError(args, append(stderr, stdout...), err)
		}
		pid, parseErr := strconv.Atoi(strings.TrimSpace(string(stdout)))
		if parseErr != nil || pid <= 0 {
			return 0, fmt.Errorf("launchctl %s: unexpected output %q", strings.Join(args, " "), strings.TrimSpace(string(stdout)))
		}
		return pid, nil
	}
	return 0, errors.New("ssh-agent-proxy is installed but not loaded in launchd; run -reinstall to load it")
}

var reLaunchdPID = regexp.MustCompile(`"PID"\s*=\s*(\d+);`)

func (m *launchdManager) Status() (Status, error) {
	st := Status{}
	if _, err := os.Stat(m.plistPath); err == nil {
		st.Installed = true
		data, readErr := os.ReadFile(m.plistPath)
		if readErr != nil {
			return st, fmt.Errorf("reading launchd plist: %w", readErr)
		}
		args, parseErr := parseLaunchdPlistArguments(data)
		if parseErr != nil {
			return st, parseErr
		}
		if len(args) > 0 {
			st.Program = args[0]
		}
		st.Config = configArgument(args)
	} else if !os.IsNotExist(err) {
		return st, fmt.Errorf("checking launchd plist: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	stdout, stderr, err := m.run(ctx, "list", Label)
	if err == nil {
		s := string(append(stdout, stderr...))
		if mt := reLaunchdPID.FindStringSubmatch(s); mt != nil {
			st.Running = true
			st.PID = mt[1]
		}
		program, parseErr := parseLaunchdProgram(s)
		if parseErr != nil {
			return st, parseErr
		}
		if program != "" {
			st.Program = program
		}
		args, parseErr := parseLaunchdArguments(s)
		if parseErr != nil {
			return st, parseErr
		}
		if len(args) > 0 {
			st.Program = args[0]
			st.Config = configArgument(args)
		}
	}
	return st, nil
}

func (m *launchdManager) launchctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	stdout, stderr, err := m.run(ctx, args...)
	return launchctlCommandError(args, append(stderr, stdout...), err)
}

func launchctlCommandError(args []string, out []byte, runErr error) error {
	message := strings.TrimSpace(string(out))
	if runErr != nil {
		if message != "" {
			return fmt.Errorf("launchctl %s: %s: %w", strings.Join(args, " "), message, runErr)
		}
		return fmt.Errorf("launchctl %s: %w", strings.Join(args, " "), runErr)
	}
	// Legacy launchctl load/unload commands can print a failure diagnostic but
	// still exit successfully. Treat any diagnostic as an error so callers do
	// not report a failed installation as successful.
	if message != "" {
		return fmt.Errorf("launchctl %s: %s", strings.Join(args, " "), message)
	}
	return nil
}
