// Package config loads, validates and resolves the ssh-agent-proxy YAML config.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/krisiasty/ssh-agent-proxy/internal/keys"
	"gopkg.in/yaml.v3"
)

// AppName is the config subdirectory / service name used throughout the tool.
const AppName = "ssh-agent-proxy"

// KeyEntry is one entry in a group's key list.
type KeyEntry struct {
	Comment *string `yaml:"comment,omitempty"`
	MD5     *string `yaml:"md5,omitempty"`
	SHA256  *string `yaml:"sha256,omitempty"`
}

// Group is a named set of keys exposed on its own socket.
type Group struct {
	Name       string     `yaml:"name"`
	Enabled    *bool      `yaml:"enabled"`
	Socket     string     `yaml:"socket"`
	Keys       []KeyEntry `yaml:"keys"`
	upstream   string     // set after config is resolved
	matchers   []keys.Matcher
	allowSet   keys.AllowSet
}

// Matchers returns the compiled matchers for the group, in config order.
func (g *Group) Matchers() []keys.Matcher { return g.matchers }

// IsEnabled reports whether the group is active. Groups are enabled unless
// 'enabled: false' is set explicitly.
func (g *Group) IsEnabled() bool { return g.Enabled == nil || *g.Enabled }

// Config is the parsed and resolved configuration.
type Config struct {
	Upstream string  `yaml:"upstream"`
	Debug    bool    `yaml:"debug"`
	Groups   []Group `yaml:"groups"`
}

// DefaultPath returns the default config path:
// <os.UserConfigDir>/ssh-agent-proxy/config.yaml.
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("determining user config dir: %w", err)
	}
	return filepath.Join(dir, AppName, "config.yaml"), nil
}

// EnsureScaffold creates the config directory and, if no config exists yet,
// writes a commented sample so the user has a starting point. It reports
// whether a new file was created.
func EnsureScaffold(path string) (created bool, err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, fmt.Errorf("creating config dir: %w", err)
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.WriteFile(path, []byte(sampleConfig), 0o600); err != nil {
			return false, fmt.Errorf("writing sample config: %w", err)
		}
		return true, nil
	}
	return false, nil
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
    keys:
      - comment: "laptop@work"
      - md5: "MD5:aa:bb:cc:dd:..."
      - sha256: "SHA256:abc123..."
`

// Load reads, parses, validates and resolves the config at path.
func Load(path string) (*Config, error) {
	//nolint:gosec // G304: the config path is chosen by the operator (default location or -config), not untrusted input.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}

	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // reject unknown fields to catch typos
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", path, err)
	}

	if err := cfg.resolve(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// resolve validates required fields, expands paths and compiles matchers.
func (c *Config) resolve() error {
	if strings.TrimSpace(c.Upstream) == "" {
		return fmt.Errorf("config: 'upstream' is required")
	}
	up, err := expandPath(c.Upstream)
	if err != nil {
		return fmt.Errorf("config: upstream: %w", err)
	}
	c.Upstream = up

	seenNames := make(map[string]bool)
	for i := range c.Groups {
		g := &c.Groups[i]
		if strings.TrimSpace(g.Name) == "" {
			return fmt.Errorf("config: group #%d: 'name' is required", i+1)
		}
		if seenNames[g.Name] {
			return fmt.Errorf("config: duplicate group name %q", g.Name)
		}
		seenNames[g.Name] = true

		if strings.TrimSpace(g.Socket) == "" {
			return fmt.Errorf("config: group %q: 'socket' is required", g.Name)
		}
		sock, err := expandPath(g.Socket)
		if err != nil {
			return fmt.Errorf("config: group %q: socket: %w", g.Name, err)
		}
		g.Socket = sock

		g.matchers = g.matchers[:0]
		for j, ke := range g.Keys {
			m, err := ke.matcher()
			if err != nil {
				return fmt.Errorf("config: group %q, key #%d: %w", g.Name, j+1, err)
			}
			g.matchers = append(g.matchers, m)
		}
	}
	return nil
}

func (ke KeyEntry) matcher() (keys.Matcher, error) {
	var typ, value string
	count := 0
	if ke.Comment != nil {
		typ, value = "comment", *ke.Comment
		count++
	}
	if ke.MD5 != nil {
		typ, value = "md5", *ke.MD5
		count++
	}
	if ke.SHA256 != nil {
		typ, value = "sha256", *ke.SHA256
		count++
	}
	if count != 1 {
		return keys.Matcher{}, fmt.Errorf("key entry must contain exactly one of 'comment', 'md5' or 'sha256'")
	}
	return keys.NewMatcher(typ, value)
}

// expandPath expands environment variables and a leading "~" to the home dir.
func expandPath(p string) (string, error) {
	p = os.ExpandEnv(p)
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expanding ~: %w", err)
		}
		p = filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	return p, nil
}
