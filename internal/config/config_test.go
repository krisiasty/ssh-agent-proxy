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
  - name: work
    socket: /tmp/work.sock
    keys:
      - type: comment
        value: laptop@work
      - type: sha256
        value: SHA256:abc
  - name: personal
    enabled: false
    socket: /tmp/personal.sock
    keys:
      - type: comment
        value: home
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
	if len(cfg.Groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(cfg.Groups))
	}
	if cfg.Groups[0].Name != "work" || len(cfg.Groups[0].Matchers()) != 2 {
		t.Errorf("group 0 = %q with %d matchers", cfg.Groups[0].Name, len(cfg.Groups[0].Matchers()))
	}
	// enabled defaults to true when omitted, is false when set false.
	if !cfg.Groups[0].IsEnabled() {
		t.Error("group 'work' should be enabled by default")
	}
	if cfg.Groups[1].IsEnabled() {
		t.Error("group 'personal' should be disabled")
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]string{
		"missing upstream": "groups: []\n",
		"missing name":     "upstream: /a\ngroups:\n  - socket: /s\n",
		"duplicate name":   "upstream: /a\ngroups:\n  - {name: g, socket: /s1}\n  - {name: g, socket: /s2}\n",
		"group no socket":  "upstream: /a\ngroups:\n  - name: g\n",
		"bad key type":     "upstream: /a\ngroups:\n  - name: g\n    socket: /s\n    keys:\n      - {type: foo, value: x}\n",
		"empty key value":  "upstream: /a\ngroups:\n  - name: g\n    socket: /s\n    keys:\n      - {type: comment, value: \"\"}\n",
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
