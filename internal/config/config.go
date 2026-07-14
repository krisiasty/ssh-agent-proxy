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
	Type  string `yaml:"type"`
	Value string `yaml:"value"`
}

// Group is a named set of keys exposed on its own socket.
type Group struct {
	Name    string     `yaml:"name"`
	Enabled *bool      `yaml:"enabled"`
	Socket  string     `yaml:"socket"`
	Keys    []KeyEntry `yaml:"keys"`

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

// Load reads, parses, validates and resolves the config at path.
func Load(path string) (*Config, error) {
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
			m, err := keys.NewMatcher(ke.Type, ke.Value)
			if err != nil {
				return fmt.Errorf("config: group %q, key #%d: %w", g.Name, j+1, err)
			}
			g.matchers = append(g.matchers, m)
		}
	}
	return nil
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
