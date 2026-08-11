package diag

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/krisiasty/ssh-agent-proxy/internal/config"
	"github.com/krisiasty/ssh-agent-proxy/internal/service"
	"golang.org/x/crypto/ssh/agent"
)

func TestRunReportsHealthyManagedServiceWithoutKeyDetails(t *testing.T) {
	paths := writeTestConfig(t, true)
	key := &agent.Key{Format: "ssh-ed25519", Blob: []byte("key-one"), Comment: "private-key-comment"}
	deps := testDependencies(service.Status{
		Installed: true,
		Running:   true,
		PID:       "42",
		Program:   "/usr/local/bin/ssh-agent-proxy",
		Config:    paths.config,
	}, map[string][]*agent.Key{
		paths.upstream: {key},
		paths.group:    {key},
	})

	var output bytes.Buffer
	err := run(context.Background(), paths.config, 3, &output, deps)
	if err != nil {
		t.Fatalf("run() error = %v\n%s", err, output.String())
	}

	for _, want := range []string{
		`[PASS] config: loaded`,
		`[PASS] service: managed service is running (pid 42)`,
		`[PASS] upstream: agent responded with 1 key`,
		`[WARN] group "work" selectors: 1 of 2 selectors matched no upstream key`,
		`[PASS] group "work" socket: returned the expected 1 key in configured order`,
		`[PASS] group "disabled": disabled (0 selectors; socket not probed)`,
		`[WARN] summary:`,
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output does not contain %q:\n%s", want, output.String())
		}
	}
	for _, secret := range []string{"private-key-comment", "missing-key-comment", "key-one"} {
		if strings.Contains(output.String(), secret) {
			t.Errorf("output exposes key detail %q:\n%s", secret, output.String())
		}
	}
}

func TestRunReportsSocketMismatchAndContinues(t *testing.T) {
	paths := writeTestConfig(t, true)
	expected := &agent.Key{Format: "ssh-ed25519", Blob: []byte("expected"), Comment: "private-key-comment"}
	unexpected := &agent.Key{Format: "ssh-ed25519", Blob: []byte("unexpected"), Comment: "another-secret"}
	deps := testDependencies(service.Status{Installed: true, Running: false, Config: "/another/config.yaml"}, map[string][]*agent.Key{
		paths.upstream: {expected},
		paths.group:    {unexpected},
	})

	var output bytes.Buffer
	err := run(context.Background(), paths.config, 3, &output, deps)
	if !errors.Is(err, ErrFailures) {
		t.Fatalf("run() error = %v, want ErrFailures\n%s", err, output.String())
	}
	for _, want := range []string{
		"managed service is installed but stopped",
		"instead of selected config",
		`group "work" socket: returned 1 key; expected 1 in configured order`,
		`group "disabled": disabled`,
		`[FAIL] summary:`,
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output does not contain %q:\n%s", want, output.String())
		}
	}
}

func TestRunAcceptsHealthyUnmanagedProxy(t *testing.T) {
	paths := writeTestConfig(t, false)
	key := &agent.Key{Format: "ssh-ed25519", Blob: []byte("key-one"), Comment: "private-key-comment"}
	deps := testDependencies(service.Status{}, map[string][]*agent.Key{
		paths.upstream: {key},
		paths.group:    {key},
	})

	var output bytes.Buffer
	if err := run(context.Background(), paths.config, 3, &output, deps); err != nil {
		t.Fatalf("run() error = %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "foreground/unmanaged proxy is serving all enabled groups") {
		t.Errorf("output does not identify unmanaged mode:\n%s", output.String())
	}
}

func TestRunContinuesServiceCheckAfterInvalidConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("unknown: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deps := testDependencies(service.Status{Installed: true, Running: false, Config: configPath}, nil)

	var output bytes.Buffer
	err := run(context.Background(), configPath, 3, &output, deps)
	if !errors.Is(err, ErrFailures) {
		t.Fatalf("run() error = %v, want ErrFailures", err)
	}
	if !strings.Contains(output.String(), "managed service is installed but stopped") {
		t.Errorf("service check did not continue after config failure:\n%s", output.String())
	}
}

type testPaths struct {
	config   string
	upstream string
	group    string
}

func writeTestConfig(t *testing.T, includeMissingSelector bool) testPaths {
	t.Helper()
	dir := t.TempDir()
	paths := testPaths{
		config:   filepath.Join(dir, "config.yaml"),
		upstream: filepath.Join(dir, "upstream.sock"),
		group:    filepath.Join(dir, "group.sock"),
	}
	missing := ""
	if includeMissingSelector {
		missing = "\n      - comment: missing-key-comment"
	}
	data := fmt.Sprintf(`upstream: %s
groups:
  - name: work
    socket: %s
    keys:
      - comment: private-key-comment%s
  - name: disabled
    enabled: false
    socket: %s
    keys: []
`, paths.upstream, paths.group, missing, filepath.Join(dir, "disabled.sock"))
	if err := os.WriteFile(paths.config, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return paths
}

func testDependencies(status service.Status, socketKeys map[string][]*agent.Key) dependencies {
	return dependencies{
		loadConfig: config.Load,
		serviceStatus: func(string, int) (service.Status, error) {
			return status, nil
		},
		listAgentKeys: func(_ context.Context, socket string) ([]*agent.Key, error) {
			keys, ok := socketKeys[socket]
			if !ok {
				return nil, fmt.Errorf("unexpected socket %q", socket)
			}
			return keys, nil
		},
		currentExecutable: func() (string, error) {
			return "/usr/local/bin/ssh-agent-proxy", nil
		},
	}
}
