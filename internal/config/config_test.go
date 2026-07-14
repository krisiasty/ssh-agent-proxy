package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/run/agent.sock")
	p := writeConfig(t, `
upstream: ${SSH_AUTH_SOCK}
debug: true
groups:
  - socket: /tmp/work.sock
    keys:
      - {type: comment, value: laptop@work}
      - {type: sha256, value: SHA256:abc}
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Upstream != "/run/agent.sock" {
		t.Errorf("upstream not expanded: %q", cfg.Upstream)
	}
	if !cfg.Debug {
		t.Error("debug should be true")
	}
	if len(cfg.Groups) != 1 || len(cfg.Groups[0].Matchers()) != 2 {
		t.Fatalf("expected 1 group with 2 matchers, got %+v", cfg.Groups)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]string{
		"missing upstream": "groups: []\n",
		"group no socket":  "upstream: /a\ngroups:\n  - keys: []\n",
		"bad key type":     "upstream: /a\ngroups:\n  - socket: /s\n    keys:\n      - {type: foo, value: x}\n",
		"empty key value":  "upstream: /a\ngroups:\n  - socket: /s\n    keys:\n      - {type: comment, value: \"\"}\n",
		"unknown field":    "upstream: /a\nnope: 1\n",
		"not yaml":         "upstream: [unterminated\n",
	}
	for name, body := range cases {
		p := writeConfig(t, body)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestExpandTilde(t *testing.T) {
	home, _ := os.UserHomeDir()
	got, err := expandPath("~/x")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(home, "x") {
		t.Errorf("expandPath(~/x) = %q, want %q", got, filepath.Join(home, "x"))
	}
}
