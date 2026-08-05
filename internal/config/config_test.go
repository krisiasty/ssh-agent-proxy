package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/krisiasty/ssh-agent-proxy/internal/keys"
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
	p := writeConfig(t, `
upstream: /run/agent.sock
debug: true
groups:
  - name: work
    socket: /tmp/work.sock
    keys:
      - comment: laptop@work
      - sha256: SHA256:abc
  - name: personal
    enabled: false
    socket: /tmp/personal.sock
    keys:
      - md5: MD5:aa:bb
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Upstream != "/run/agent.sock" {
		t.Errorf("upstream = %q, want %q", cfg.Upstream, "/run/agent.sock")
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
	wantTypes := [][]keys.MatchType{
		{keys.MatchComment, keys.MatchSHA256},
		{keys.MatchMD5},
	}
	for i, group := range cfg.Groups {
		for j, matcher := range group.Matchers() {
			if matcher.Type != wantTypes[i][j] {
				t.Errorf("group %d matcher %d type = %q, want %q", i, j, matcher.Type, wantTypes[i][j])
			}
		}
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]string{
		"missing upstream":     "groups: []\n",
		"missing name":         "upstream: /a\ngroups:\n  - socket: /s\n",
		"duplicate name":       "upstream: /a\ngroups:\n  - {name: g, socket: /s1}\n  - {name: g, socket: /s2}\n",
		"group no socket":      "upstream: /a\ngroups:\n  - name: g\n",
		"relative upstream":    "upstream: ./agent.sock\ngroups: []\n",
		"relative group socket": "upstream: /a\ngroups:\n  - {name: g, socket: ./s.sock}\n",
		"tilde upstream":       "upstream: ~/.ssh/agent.sock\ngroups: []\n",
		"envvar upstream":      "upstream: ${SSH_AUTH_SOCK}\ngroups: []\n",
		"old key form":         "upstream: /a\ngroups:\n  - name: g\n    socket: /s\n    keys:\n      - {type: comment, value: x}\n",
		"unknown key form":     "upstream: /a\ngroups:\n  - name: g\n    socket: /s\n    keys:\n      - {fingerprint: x}\n",
		"missing key form":     "upstream: /a\ngroups:\n  - name: g\n    socket: /s\n    keys:\n      - {}\n",
		"multiple key forms":   "upstream: /a\ngroups:\n  - name: g\n    socket: /s\n    keys:\n      - {comment: x, md5: y}\n",
		"empty key value":      "upstream: /a\ngroups:\n  - name: g\n    socket: /s\n    keys:\n      - {comment: \"\"}\n",
		"unknown field":        "upstream: /a\nnope: 1\n",
		"not yaml":             "upstream: [unterminated\n",
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

func TestEnsureScaffoldCreatesValidDisabledDefaultGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.yaml")

	created, err := EnsureScaffold(path)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("EnsureScaffold() created = false, want true")
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("loading scaffolded config: %v", err)
	}
	if len(cfg.Groups) != 1 {
		t.Fatalf("scaffolded config has %d groups, want 1", len(cfg.Groups))
	}
	group := cfg.Groups[0]
	if group.IsEnabled() {
		t.Error("scaffolded default group should be disabled")
	}
	wantTypes := []keys.MatchType{keys.MatchComment, keys.MatchMD5, keys.MatchSHA256}
	if len(group.Matchers()) != len(wantTypes) {
		t.Fatalf("scaffolded default group has %d keys, want %d", len(group.Matchers()), len(wantTypes))
	}
	for i, matcher := range group.Matchers() {
		if matcher.Type != wantTypes[i] {
			t.Errorf("matcher %d type = %q, want %q", i, matcher.Type, wantTypes[i])
		}
	}
}

func TestRequireAbsolute(t *testing.T) {
	if err := requireAbsolute("/abs/path", "label"); err != nil {
		t.Errorf("requireAbsolute(/abs/path) = %v, want nil", err)
	}
	if err := requireAbsolute("relative/path", "label"); err == nil {
		t.Error("requireAbsolute(relative/path) = nil, want error")
	}
	if err := requireAbsolute("~/home/path", "label"); err == nil {
		t.Error("requireAbsolute(~/home/path) = nil, want error")
	}
}
