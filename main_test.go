package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/krisiasty/ssh-agent-proxy/internal/service"
)

func TestValidateCacheSeconds(t *testing.T) {
	if defaultCacheSeconds != 3 {
		t.Fatalf("default cache = %d seconds, want 3", defaultCacheSeconds)
	}

	tests := []struct {
		name    string
		seconds int
		wantErr bool
	}{
		{name: "below minimum", seconds: -1, wantErr: true},
		{name: "disabled", seconds: 0},
		{name: "default", seconds: 3},
		{name: "maximum", seconds: 60},
		{name: "above maximum", seconds: 61, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateCacheSeconds(test.seconds)
			if (err != nil) != test.wantErr {
				t.Errorf("validateCacheSeconds(%d) error = %v, wantErr %t", test.seconds, err, test.wantErr)
			}
		})
	}
}

// statusManager is a service.Manager whose Status is fixed.
type statusManager struct {
	service.Manager
	status service.Status
}

func (m statusManager) Status() (service.Status, error) { return m.status, nil }

func TestCheckInstalledBinary(t *testing.T) {
	present := filepath.Join(t.TempDir(), "ssh-agent-proxy")
	if err := os.WriteFile(present, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "Caskroom", "ssh-agent-proxy", "0.9.0", "ssh-agent-proxy")

	if err := checkInstalledBinary(statusManager{status: service.Status{Installed: true, Program: present}}); err != nil {
		t.Errorf("checkInstalledBinary() with a present binary = %v, want nil", err)
	}
	err := checkInstalledBinary(statusManager{status: service.Status{Installed: true, Program: missing}})
	if err == nil || !strings.Contains(err.Error(), "-reinstall") {
		t.Errorf("checkInstalledBinary() with a removed binary = %v, want a -reinstall error", err)
	}
}
