//go:build linux || darwin

package proxy

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/krisiasty/ssh-agent-proxy/internal/config"
)

const openSSHTestNamespace = "ssh-agent-proxy-test"

func TestOpenSSHClientInteroperability(t *testing.T) {
	sshAgent := requireOpenSSHBinary(t, "ssh-agent")
	sshAdd := requireOpenSSHBinary(t, "ssh-add")
	sshKeygen := requireOpenSSHBinary(t, "ssh-keygen")

	socketDir := shortSocketDir(t)
	upstreamSocket := filepath.Join(socketDir, "upstream.sock")
	groupSocket := filepath.Join(socketDir, "group.sock")

	keyDir := t.TempDir()
	allowedKey := filepath.Join(keyDir, "allowed")
	excludedKey := filepath.Join(keyDir, "excluded")
	generateOpenSSHKey(t, sshKeygen, allowedKey, "allowed@test")
	generateOpenSSHKey(t, sshKeygen, excludedKey, "excluded@test")

	agentCtx, stopAgent := context.WithCancel(t.Context())
	var agentOutput lockedBuffer
	//nolint:gosec // The executable is resolved from PATH and every argument is test-controlled.
	agentCmd := exec.CommandContext(agentCtx, sshAgent, "-D", "-a", upstreamSocket)
	agentCmd.Stdout = &agentOutput
	agentCmd.Stderr = &agentOutput
	if err := agentCmd.Start(); err != nil {
		t.Fatalf("starting OpenSSH agent: %v", err)
	}
	agentResult := runAsync(agentCmd.Wait)
	t.Cleanup(func() {
		stopAgent()
		_ = waitForAsyncStop(t, agentResult, "OpenSSH agent")
	})
	waitForIntegrationSocket(t, upstreamSocket, agentResult, func() string {
		return string(agentOutput.Bytes())
	})

	if _, stderr, err := runOpenSSH(t, sshAdd, upstreamSocket, nil, "-q", allowedKey, excludedKey); err != nil {
		t.Fatalf("adding keys to OpenSSH agent: %v\n%s", err, stderr)
	}
	for _, privateKey := range []string{allowedKey, excludedKey} {
		if err := os.Remove(privateKey); err != nil {
			t.Fatalf("removing temporary private key after loading it into the agent: %v", err)
		}
	}

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	configBody := fmt.Sprintf(`upstream: %s
groups:
  - name: integration
    socket: %s
    keys:
      - comment: allowed@test
`, strconv.Quote(upstreamSocket), strconv.Quote(groupSocket))
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatalf("writing integration config: %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("loading integration config: %v", err)
	}

	proxyCtx, stopProxy := context.WithCancel(t.Context())
	srv := NewServer(proxyCtx, cfg.Upstream, 0, slog.New(slog.DiscardHandler))
	proxyResult := runAsync(func() error { return srv.Run(proxyCtx, cfg.Groups) })
	t.Cleanup(func() {
		stopProxy()
		if waitForAsyncStop(t, proxyResult, "proxy server") && proxyResult.err != nil {
			t.Errorf("proxy server stopped with error: %v", proxyResult.err)
		}
	})
	waitForIntegrationSocket(t, groupSocket, proxyResult, func() string { return "" })

	listed, stderr, err := runOpenSSH(t, sshAdd, groupSocket, nil, "-L")
	if err != nil {
		t.Fatalf("listing keys through proxy: %v\n%s", err, stderr)
	}
	//nolint:gosec // G304: the path is created beneath this test's temporary directory.
	allowedPublic, err := os.ReadFile(allowedKey + ".pub")
	if err != nil {
		t.Fatalf("reading allowed public key: %v", err)
	}
	if got, want := strings.TrimSpace(string(listed)), strings.TrimSpace(string(allowedPublic)); got != want {
		t.Fatalf("keys listed through proxy = %q, want only %q", got, want)
	}

	message := []byte("ssh-agent-proxy OpenSSH integration test\n")
	signature, stderr, err := runOpenSSH(t, sshKeygen, groupSocket, message,
		"-Y", "sign", "-f", allowedKey+".pub", "-n", openSSHTestNamespace)
	if err != nil {
		t.Fatalf("signing with allowed key through proxy: %v\n%s", err, stderr)
	}
	verifyOpenSSHSignature(t, sshKeygen, allowedPublic, message, signature)

	if _, _, err := runOpenSSH(t, sshKeygen, groupSocket, message,
		"-Y", "sign", "-f", excludedKey+".pub", "-n", openSSHTestNamespace); err == nil {
		t.Fatal("signing with excluded key through proxy succeeded, want failure")
	}
}

type asyncResult struct {
	done chan struct{}
	err  error
}

func runAsync(fn func() error) *asyncResult {
	result := &asyncResult{done: make(chan struct{})}
	go func() {
		result.err = fn()
		close(result.done)
	}()
	return result
}

func waitForAsyncStop(t *testing.T, result *asyncResult, name string) bool {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-result.done:
		return true
	case <-timer.C:
		t.Errorf("timed out waiting for %s to stop", name)
		return false
	}
}

func waitForIntegrationSocket(t *testing.T, path string, result *asyncResult, diagnostic func() string) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		} else if err != nil && !os.IsNotExist(err) {
			t.Fatalf("inspecting integration socket: %v", err)
		}
		select {
		case <-result.done:
			t.Fatalf("socket owner stopped before serving %q: %v\n%s", path, result.err, diagnostic())
		case <-deadline.C:
			t.Fatalf("timed out waiting for integration socket %q\n%s", path, diagnostic())
		case <-ticker.C:
		}
	}
}

func requireOpenSSHBinary(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err == nil {
		return path
	}
	if os.Getenv("SSH_AGENT_PROXY_REQUIRE_OPENSSH") == "1" {
		t.Fatalf("required OpenSSH executable %q not found: %v", name, err)
	}
	t.Skipf("OpenSSH executable %q not found", name)
	return ""
}

func generateOpenSSHKey(t *testing.T, sshKeygen, path, comment string) {
	t.Helper()
	//nolint:gosec // The executable is resolved from PATH and every argument is test-controlled.
	cmd := exec.CommandContext(t.Context(), sshKeygen,
		"-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generating OpenSSH key: %v\n%s", err, output)
	}
}

func runOpenSSH(t *testing.T, executable, socket string, input []byte, args ...string) ([]byte, []byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	//nolint:gosec // The executable is resolved from PATH and every argument is test-controlled.
	cmd := exec.CommandContext(ctx, executable, args...)
	if socket != "" {
		cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+socket)
	}
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func verifyOpenSSHSignature(t *testing.T, sshKeygen string, publicKey, message, signature []byte) {
	t.Helper()
	dir := t.TempDir()
	signersPath := filepath.Join(dir, "allowed_signers")
	signaturePath := filepath.Join(dir, "message.sig")
	signers := "integration " + strings.TrimSpace(string(publicKey)) + "\n"
	//nolint:gosec // G703: the path is created beneath this test's temporary directory.
	if err := os.WriteFile(signersPath, []byte(signers), 0o600); err != nil {
		t.Fatalf("writing allowed signers: %v", err)
	}
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		t.Fatalf("writing signature: %v", err)
	}
	_, stderr, err := runOpenSSH(t, sshKeygen, "", message,
		"-Y", "verify", "-f", signersPath, "-I", "integration",
		"-n", openSSHTestNamespace, "-s", signaturePath)
	if err != nil {
		t.Fatalf("verifying allowed-key signature: %v\n%s", err, stderr)
	}
}
