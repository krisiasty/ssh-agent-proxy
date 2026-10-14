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

	"github.com/krisiasty/ssh-agent-proxy/internal/config"
	"golang.org/x/crypto/ssh/agent"
)

func TestServerShutdownInterruptsUpstreamRequests(t *testing.T) {
	for _, scenario := range []struct {
		name         string
		startup      bool
		sign         bool
		terminal     bool
		nilTelemetry bool
	}{
		{name: "initial list", startup: true},
		{name: "initial list without telemetry", startup: true, nilTelemetry: true},
		{name: "client list"},
		{name: "client sign", sign: true},
		{name: "listener failure during list", terminal: true},
		{name: "listener failure during sign", sign: true, terminal: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			dir := shortSocketDir(t)
			backend := newBlockingListAgent(t)
			pub := addAgentKey(t, backend.ExtendedAgent, "allowed")
			backend.blockListAt = 2
			if scenario.startup {
				backend.blockListAt = 1
			}
			if scenario.sign {
				backend.blockListAt = -1
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
			if scenario.nilTelemetry {
				srv.newUpstreamClient = func(ctx context.Context, socket string, log *slog.Logger) (*reconnectClient, error) {
					return newReconnectClientWithTelemetry(ctx, socket, log, nil)
				}
			}
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
				if !waitForEvent(t, ready, "proxy readiness") {
					return
				}
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
			if !waitForEvent(t, backend.started, "stalled upstream request") {
				return
			}
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
			backend := newBlockingListAgent(t)
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
			if !waitForEvent(t, entered, "replacement dial") {
				return
			}
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

func TestServerClosesListenersBeforeUpstream(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	srv := NewServer(t.Context(), "unused", 0, log)
	listener := newScriptedListener(errors.New("terminal listener failure"))
	srv.listen = func(context.Context, string) (net.Listener, error) { return listener, nil }
	transport := &shutdownObservingTransport{onClose: func() {
		if !listener.Closed() {
			t.Error("upstream closed before the group listener")
		}
		srv.clientsMu.Lock()
		closing := srv.clientsClosing
		srv.clientsMu.Unlock()
		if !closing {
			t.Error("upstream closed before new clients were refused")
		}
	}}
	srv.newUpstreamClient = func(ctx context.Context, _ string, log *slog.Logger) (*reconnectClient, error) {
		client := &reconnectClient{ctx: ctx, log: log}
		client.current.Store(&upstreamConn{client: newTestKeyring(t), conn: transport})
		return client, nil
	}
	socket := filepath.Join(shortSocketDir(t), "group.sock")
	if err := srv.Run(t.Context(), []config.Group{{Name: "test", Socket: socket}}); !errors.Is(err, ErrListenerFailure) {
		t.Errorf("Run() error = %v, want listener failure", err)
	}
}

type shutdownObservingTransport struct {
	testUpstreamTransport
	onClose func()
}

func (c *shutdownObservingTransport) Close() error {
	c.onClose()
	return c.testUpstreamTransport.Close()
}

func serveShutdownAgent(t *testing.T, socket string, backend *blockingListAgent) {
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
