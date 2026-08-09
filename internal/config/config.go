// Package config loads, validates and resolves the ssh-agent-proxy YAML config.
package config

import (
	"errors"
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
	Name     string     `yaml:"name"`
	Enabled  *bool      `yaml:"enabled"`
	Socket   string     `yaml:"socket"`
	Keys     []KeyEntry `yaml:"keys"`
	matchers []keys.Matcher
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

# Path to the upstream SSH agent socket (required).
# Must be an absolute path; environment variables and ~ are NOT expanded.
upstream: /run/user/1000/keyrings/bitwarden/agent.sock

# Verbose logging.
debug: false

# Filtered views of the upstream agent. Each group is exposed on its own socket;
# point a client at it with: export SSH_AUTH_SOCK=<socket>
# Populate a group's keys with entries from 'ssh-agent-proxy -list'
# (match by comment, sha256 or md5).
groups:
  - name: default
    enabled: false
    socket: /run/user/1000/ssh-agent-proxys/default.sock
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

// resolve validates required fields, checks paths are absolute, and compiles matchers.
func (c *Config) resolve() error {
	if strings.TrimSpace(c.Upstream) == "" {
		return errors.New("config: 'upstream' is required")
	}
	if err := requireAbsolute(c.Upstream, "upstream"); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	c.Upstream = filepath.Clean(c.Upstream)
	upstreamPath, err := canonicalSocketPath(c.Upstream)
	if err != nil {
		return fmt.Errorf("config: resolving upstream path: %w", err)
	}

	seenNames := make(map[string]bool)
	seenSockets := make(map[string]string)
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
		if err := requireAbsolute(g.Socket, fmt.Sprintf("group %q: socket", g.Name)); err != nil {
			return fmt.Errorf("config: %w", err)
		}
		g.Socket = filepath.Clean(g.Socket)
		if g.IsEnabled() {
			socketPath, err := canonicalSocketPath(g.Socket)
			if err != nil {
				return fmt.Errorf("config: group %q: resolving socket path: %w", g.Name, err)
			}
			if socketPath == upstreamPath {
				return fmt.Errorf("config: group %q: socket conflicts with upstream path %q", g.Name, c.Upstream)
			}
			if other, ok := seenSockets[socketPath]; ok {
				return fmt.Errorf("config: groups %q and %q use the same socket path", other, g.Name)
			}
			seenSockets[socketPath] = g.Name
		}

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

// canonicalSocketPath resolves every existing path prefix so conflicts through
// symlinked directories are detected even when the socket itself does not yet
// exist. Missing suffixes are appended to the resolved prefix unchanged.
func canonicalSocketPath(path string) (string, error) {
	cleaned := filepath.Clean(path)
	current := cleaned
	var missing []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}

		parent := filepath.Dir(current)
		if parent == current {
			return cleaned, nil
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
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
		return keys.Matcher{}, errors.New("key entry must contain exactly one of 'comment', 'md5' or 'sha256'")
	}
	return keys.NewMatcher(typ, value)
}

// requireAbsolute ensures the path starts with "/". Socket paths must be
// absolute; the program does not perform ~ or environment-variable expansion.
func requireAbsolute(p, label string) error {
	if filepath.IsAbs(p) {
		return nil
	}
	return fmt.Errorf("%s: %q is not an absolute path", label, p)
}
