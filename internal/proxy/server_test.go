package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/krisiasty/ssh-agent-proxy/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestFormatKeysUsesSingleFieldEntries(t *testing.T) {
	key := &agent.Key{
		Format:  "ssh-test",
		Blob:    []byte("public key"),
		Comment: `work "laptop"`,
	}
	want := fmt.Sprintf("[1] ssh-test\n  - comment: %s\n  - sha256: %s\n  - md5: %s\n",
		strconv.Quote(key.Comment),
		strconv.Quote(ssh.FingerprintSHA256(key)),
		strconv.Quote("MD5:"+ssh.FingerprintLegacyMD5(key)),
	)

	if got := formatKeys([]*agent.Key{key}); got != want {
		t.Errorf("formatKeys() = %q, want %q", got, want)
	}
}

func TestServerRunWithoutEnabledGroupsDoesNotDialUpstream(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	missingUpstream := filepath.Join(t.TempDir(), "missing-agent.sock")
	srv := NewServer(missingUpstream, slog.New(slog.DiscardHandler))

	t.Run("no groups", func(t *testing.T) {
		t.Parallel()

		if err := srv.Run(ctx, nil); err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
	})

	t.Run("all groups disabled", func(t *testing.T) {
		t.Parallel()

		disabled := false
		groups := []config.Group{{
			Name:    "disabled",
			Enabled: &disabled,
			Socket:  filepath.Join(t.TempDir(), "disabled.sock"),
		}}
		if err := srv.Run(ctx, groups); err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
	})
}

func TestServerRunReturnsInitialDialError(t *testing.T) {
	t.Parallel()

	missingUpstream := filepath.Join(t.TempDir(), "missing-agent.sock")
	srv := NewServer(missingUpstream, slog.New(slog.DiscardHandler))
	groups := []config.Group{{Name: "test", Socket: filepath.Join(t.TempDir(), "group.sock")}}

	err := srv.Run(t.Context(), groups)
	if err == nil {
		t.Fatal("Run() error = nil, want initial dial error")
	}
	if !strings.Contains(err.Error(), "initial upstream connection") {
		t.Fatalf("Run() error = %q, want initial upstream connection context", err)
	}
}

func TestServerRunReturnsInitialListError(t *testing.T) {
	t.Parallel()

	srv := NewServer("unused", slog.New(slog.DiscardHandler))
	srv.newUpstreamClient = func(_ context.Context, _ string, log *slog.Logger) (*reconnectClient, error) {
		dial := func() (agent.ExtendedAgent, net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			if err := serverConn.Close(); err != nil {
				if closeErr := clientConn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
					return nil, nil, errors.Join(err, fmt.Errorf("closing client end: %w", closeErr))
				}
				return nil, nil, fmt.Errorf("closing server end: %w", err)
			}
			return agent.NewClient(clientConn), clientConn, nil
		}
		client, conn, err := dial()
		if err != nil {
			return nil, err
		}
		rc := &reconnectClient{upstream: "unused", log: log, dial: dial}
		rc.current.Store(&upstreamConn{client: client, conn: conn})
		return rc, nil
	}
	groups := []config.Group{{Name: "test", Socket: filepath.Join(t.TempDir(), "group.sock")}}
	err := srv.Run(t.Context(), groups)
	if err == nil {
		t.Fatal("Run() error = nil, want initial list error")
	}
	if !strings.Contains(err.Error(), "listing upstream keys") {
		t.Fatalf("Run() error = %q, want listing upstream keys context", err)
	}
}
