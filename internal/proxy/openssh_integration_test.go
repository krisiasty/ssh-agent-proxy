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
	"github.com/krisiasty/ssh-agent-proxy/internal/testutil"
)

const openSSHTestNamespace = "ssh-agent-proxy-test"

func TestOpenSSHClientInteroperability(t *testing.T) {
	sshAgent := requireOpenSSHBinary(t, "ssh-agent")
	sshAdd := requireOpenSSHBinary(t, "ssh-add")
	sshKeygen := requireOpenSSHBinary(t, "ssh-keygen")

	socketDir := testutil.ShortSocketDir(t)
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
	agentResult := testutil.RunAsync(agentCmd.Wait)
	t.Cleanup(func() {
		stopAgent()
		_ = testutil.WaitForAsyncStop(t, agentResult, "OpenSSH agent")
	})
	waitForSocket(t, upstreamSocket, agentResult, func() string {
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
	proxyResult := testutil.RunAsync(func() error { return srv.Run(proxyCtx, cfg.Groups) })
	t.Cleanup(func() {
		stopProxy()
		if testutil.WaitForAsyncStop(t, proxyResult, "proxy server") && proxyResult.Err() != nil {
			t.Errorf("proxy server stopped with error: %v", proxyResult.Err())
		}
	})
	waitForSocket(t, groupSocket, proxyResult, nil)

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
