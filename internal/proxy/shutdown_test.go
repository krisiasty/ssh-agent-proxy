//go:build linux || darwin

package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krisiasty/ssh-agent-proxy/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestServerShutdownInterruptsUpstreamRequests(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		startup  bool
		sign     bool
		terminal bool
	}{
		{name: "initial list", startup: true},
		{name: "client list"},
		{name: "client sign", sign: true},
		{name: "listener failure during list", terminal: true},
		{name: "listener failure during sign", sign: true, terminal: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			dir := shortSocketDir(t)
			backend := newShutdownAgent(t)
			pub := addAgentKey(t, backend.ExtendedAgent, "allowed")
			backend.blockListAt = 2
			if scenario.startup {
				backend.blockListAt = 1
			}
			if scenario.sign {
				backend.blockListAt = 0
				backend.blockSign = true
			}
			upstream := filepath.Join(dir, "upstream.sock")
			serveShutdownAgent(t, upstream, backend)
			socket := filepath.Join(dir, "group.sock")
			cfgPath := filepath.Join(t.TempDir(), "config.yaml")
			body := fmt.Sprintf("upstream: %q\ngroups:\n  - name: test\n    socket: %q\n    keys:\n      - comment: allowed\n", upstream, socket)
			if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(cfgPath)
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithCancel(t.Context())
			srv := NewServer(ctx, upstream, 0, slog.New(slog.DiscardHandler))
			ready := make(chan struct{})
			srv.SetReadyCallback(func() { close(ready) })
			var listener *shutdownFailureListener
			srv.listen = func(ctx context.Context, socket string) (net.Listener, error) {
				ln, listenErr := srv.listenUnix(ctx, socket)
				if listenErr != nil {
					return nil, listenErr
				}
				listener = &shutdownFailureListener{Listener: ln}
				return listener, nil
			}
			result := runAsync(func() error { return srv.Run(ctx, cfg.Groups) })
			t.Cleanup(func() {
				cancel()
				backend.unblock()
				waitForAsyncStop(t, result, "proxy server")
			})

			var request *asyncResult
			if !scenario.startup {
				waitForShutdownEvent(t, ready, "proxy readiness")
				var dialer net.Dialer
				conn, dialErr := dialer.DialContext(t.Context(), "unix", socket)
				if dialErr != nil {
					t.Fatal(dialErr)
				}
				t.Cleanup(func() { _ = conn.Close() })
				client := agent.NewClient(conn)
				request = runAsync(func() error {
					if scenario.sign {
						_, signErr := client.Sign(pub, []byte("payload"))
						return signErr
					}
					_, listErr := client.List()
					return listErr
				})
			}
			waitForShutdownEvent(t, backend.blocked, "stalled upstream request")
			if scenario.terminal {
				listener.fail.Store(true)
				closeListener(t, listener)
			} else {
				cancel()
			}
			if !waitForAsyncStop(t, result, "proxy with unresponsive upstream") {
				return
			}
			if scenario.terminal {
				if !errors.Is(result.err, ErrListenerFailure) {
					t.Errorf("Run() error = %v, want listener failure", result.err)
				}
			} else if result.err != nil {
				t.Errorf("Run() error = %v, want clean cancellation", result.err)
			}
			if request != nil && waitForAsyncStop(t, request, "blocked client request") && request.err == nil {
				t.Error("interrupted client request unexpectedly succeeded")
			}
			if _, err := os.Lstat(socket); !os.IsNotExist(err) {
				t.Errorf("group socket remains after shutdown: %v", err)
			}
			lock, err := acquireSocketLock(socket)
			if err != nil {
				t.Fatalf("socket lock not released: %v", err)
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReconnectClientShutdownDiscardsInFlightDial(t *testing.T) {
	for _, explicitClose := range []bool{false, true} {
		name := "parent cancellation"
		if explicitClose {
			name = "explicit close"
		}
		t.Run(name, func(t *testing.T) {
			backend := newShutdownAgent(t)
			upstream := filepath.Join(shortSocketDir(t), "upstream.sock")
			serveShutdownAgent(t, upstream, backend)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			client, err := newReconnectClientWithTelemetry(ctx, upstream, slog.New(slog.DiscardHandler), nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cancel()
				if err := client.Close(t.Context()); err != nil {
					t.Error(err)
				}
			})
			original := client.current.Load()
			replacement := &testUpstreamTransport{}
			entered := make(chan struct{})
			client.dial = func() (agent.ExtendedAgent, net.Conn, error) {
				close(entered)
				<-client.logContext().Done()
				// Model a successful dial racing with cancellation.
				return backend.ExtendedAgent, replacement, nil
			}
			var reconnected bool
			result := runAsync(func() error {
				reconnected = client.reconnect(original)
				return nil
			})
			waitForShutdownEvent(t, entered, "replacement dial")
			closed := runAsync(func() error {
				if !explicitClose {
					cancel()
				}
				return client.Close(t.Context())
			})
			if !waitForAsyncStop(t, closed, "upstream close during reconnect") {
				return
			}
			if !waitForAsyncStop(t, result, "reconnect during shutdown") {
				return
			}
			if reconnected || client.current.Load() != original {
				t.Error("shutdown published a replacement upstream connection")
			}
			if got := replacement.closeCalls.Load(); got != 1 {
				t.Errorf("discarded connection closes = %d, want 1", got)
			}
			if closed.err != nil {
				t.Errorf("Close() error = %v", closed.err)
			}
		})
	}
}

func TestReconnectClientCloseIsFinalAndIdempotent(t *testing.T) {
	transport := &testUpstreamTransport{}
	client := &reconnectClient{log: slog.New(slog.DiscardHandler)}
	client.current.Store(&upstreamConn{client: newTestKeyring(t), conn: transport})
	var dials atomic.Int32
	client.dial = func() (agent.ExtendedAgent, net.Conn, error) {
		dials.Add(1)
		return newTestKeyring(t), &testUpstreamTransport{}, nil
	}
	var calls sync.WaitGroup
	for range 16 {
		calls.Go(func() {
			if err := client.Close(t.Context()); err != nil {
				t.Error(err)
			}
		})
	}
	calls.Wait()
	if client.reconnect(client.current.Load()) {
		t.Error("closed upstream reconnected")
	}
	if got := transport.closeCalls.Load(); got != 1 {
		t.Errorf("transport closes = %d, want 1", got)
	}
	if got := dials.Load(); got != 0 {
		t.Errorf("dials after Close = %d, want 0", got)
	}
}

type shutdownAgent struct {
	agent.ExtendedAgent
	blockListAt int32
	blockSign   bool
	listCalls   atomic.Int32
	blocked     chan struct{}
	release     chan struct{}
	blockOnce   sync.Once
	releaseOnce sync.Once
}

func newShutdownAgent(t *testing.T) *shutdownAgent {
	t.Helper()
	return &shutdownAgent{ExtendedAgent: newTestKeyring(t), blocked: make(chan struct{}), release: make(chan struct{})}
}

func (a *shutdownAgent) List() ([]*agent.Key, error) {
	if calls := a.listCalls.Add(1); a.blockListAt > 0 && calls >= a.blockListAt {
		a.stall()
	}
	return a.ExtendedAgent.List()
}

func (a *shutdownAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if a.blockSign {
		a.stall()
	}
	return a.ExtendedAgent.SignWithFlags(key, data, flags)
}

func (a *shutdownAgent) stall() {
	a.blockOnce.Do(func() { close(a.blocked) })
	<-a.release
}

func (a *shutdownAgent) unblock() {
	a.releaseOnce.Do(func() { close(a.release) })
}

func serveShutdownAgent(t *testing.T, socket string, backend *shutdownAgent) {
	t.Helper()
	listener := listenUnix(t, socket)
	accepted := make(chan net.Conn, 1)
	result := runAsync(func() error {
		conn, err := listener.Accept()
		if err != nil {
			close(accepted)
			return err
		}
		accepted <- conn
		close(accepted)
		defer func() { _ = conn.Close() }()
		return agent.ServeAgent(backend, conn)
	})
	t.Cleanup(func() {
		backend.unblock()
		closeListener(t, listener)
		if conn, ok := <-accepted; ok {
			_ = conn.Close()
		}
		waitForAsyncStop(t, result, "test upstream agent")
	})
}

func waitForShutdownEvent(t *testing.T, event <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

type shutdownFailureListener struct {
	net.Listener
	fail atomic.Bool
}

func (l *shutdownFailureListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil && l.fail.Load() {
		return nil, errors.New("injected listener failure")
	}
	return conn, err
}
