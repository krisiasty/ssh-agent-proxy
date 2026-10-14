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
	"github.com/krisiasty/ssh-agent-proxy/internal/testutil"
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
			dir := testutil.ShortSocketDir(t)
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
				srv.newUpstreamClient = func(ctx context.Context, socket string, log *slog.Logger, _ *proxyTelemetry) (*reconnectClient, error) {
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
			result := testutil.RunAsync(func() error { return srv.Run(ctx, cfg.Groups) })
			t.Cleanup(func() {
				cancel()
				backend.unblock()
				testutil.WaitForAsyncStop(t, result, "proxy server")
			})

			var request *testutil.AsyncResult
			if !scenario.startup {
				if !testutil.WaitForEvent(t, ready, "proxy readiness") {
					return
				}
				var dialer net.Dialer
				conn, dialErr := dialer.DialContext(t.Context(), "unix", socket)
				if dialErr != nil {
					t.Fatal(dialErr)
				}
				t.Cleanup(func() { _ = conn.Close() })
				client := agent.NewClient(conn)
				request = testutil.RunAsync(func() error {
					if scenario.sign {
						_, signErr := client.Sign(pub, []byte("payload"))
						return signErr
					}
					_, listErr := client.List()
					return listErr
				})
			}
			if !testutil.WaitForEvent(t, backend.started, "stalled upstream request") {
				return
			}
			if scenario.terminal {
				listener.fail.Store(true)
				closeListener(t, listener)
			} else {
				cancel()
			}
			if !testutil.WaitForAsyncStop(t, result, "proxy with unresponsive upstream") {
				return
			}
			if scenario.terminal {
				if !errors.Is(result.Err(), ErrListenerFailure) {
					t.Errorf("Run() error = %v, want listener failure", result.Err())
				}
			} else if result.Err() != nil {
				t.Errorf("Run() error = %v, want clean cancellation", result.Err())
			}
			if request != nil && testutil.WaitForAsyncStop(t, request, "blocked client request") && request.Err() == nil {
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
			upstream := filepath.Join(testutil.ShortSocketDir(t), "upstream.sock")
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
				<-client.ctx.Done()
				// Model a successful dial racing with cancellation.
				return backend.ExtendedAgent, replacement, nil
			}
			var reconnected bool
			result := testutil.RunAsync(func() error {
				reconnected = client.reconnect(original)
				return nil
			})
			if !testutil.WaitForEvent(t, entered, "replacement dial") {
				return
			}
			closed := testutil.RunAsync(func() error {
				if !explicitClose {
					cancel()
				}
				return client.Close(t.Context())
			})
			if !testutil.WaitForAsyncStop(t, closed, "upstream close during reconnect") {
				return
			}
			if !testutil.WaitForAsyncStop(t, result, "reconnect during shutdown") {
				return
			}
			if reconnected || client.current.Load() != original {
				t.Error("shutdown published a replacement upstream connection")
			}
			if got := replacement.closeCalls.Load(); got != 1 {
				t.Errorf("discarded connection closes = %d, want 1", got)
			}
			if closed.Err() != nil {
				t.Errorf("Close() error = %v", closed.Err())
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
	srv.newUpstreamClient = func(ctx context.Context, _ string, log *slog.Logger, telemetry *proxyTelemetry) (*reconnectClient, error) {
		client := &reconnectClient{ctx: ctx, log: log, telemetry: telemetry}
		client.current.Store(&upstreamConn{client: newTestKeyring(t), conn: transport})
		return client, nil
	}
	socket := filepath.Join(testutil.ShortSocketDir(t), "group.sock")
	if err := srv.Run(t.Context(), []config.Group{{Name: "test", Socket: socket}}); !errors.Is(err, ErrListenerFailure) {
		t.Errorf("Run() error = %v, want listener failure", err)
	}
}

func TestServerListenCancellationIsClean(t *testing.T) {
	for _, successfulBind := range []bool{false, true} {
		name := "probe error"
		if successfulBind {
			name = "bind completed during cancellation"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			log := slog.New(slog.DiscardHandler)
			srv := NewServer(ctx, "unused", 0, log)
			srv.newUpstreamClient = func(ctx context.Context, _ string, log *slog.Logger, telemetry *proxyTelemetry) (*reconnectClient, error) {
				client := &reconnectClient{ctx: ctx, log: log, telemetry: telemetry}
				client.current.Store(&upstreamConn{client: newTestKeyring(t), conn: &testUpstreamTransport{}})
				return client, nil
			}
			binding := make(chan struct{})
			srv.listen = func(ctx context.Context, path string) (net.Listener, error) {
				close(binding)
				<-ctx.Done()
				if successfulBind {
					// Model a bind that succeeds just as its context is canceled.
					return srv.listenUnix(context.WithoutCancel(ctx), path)
				}
				return nil, fmt.Errorf("probing existing socket: %w", ctx.Err())
			}
			var ready atomic.Bool
			srv.SetReadyCallback(func() { ready.Store(true) })
			socket := filepath.Join(testutil.ShortSocketDir(t), "group.sock")
			result := testutil.RunAsync(func() error { return srv.Run(ctx, []config.Group{{Name: "test", Socket: socket}}) })
			t.Cleanup(func() { cancel(); testutil.WaitForAsyncStop(t, result, "proxy server") })
			if !testutil.WaitForEvent(t, binding, "listen phase") {
				return
			}
			cancel()
			if !testutil.WaitForAsyncStop(t, result, "proxy server") {
				return
			}
			if result.Err() != nil {
				t.Errorf("Run() returned error for cancellation: %v", result.Err())
			}
			if ready.Load() {
				t.Error("canceled startup announced readiness")
			}
			if _, err := os.Lstat(socket); !os.IsNotExist(err) {
				t.Errorf("startup left a socket behind: %v", err)
			}
		})
	}
}

func TestUpstreamContextInterruptsWireRequests(t *testing.T) {
	for _, signing := range []bool{false, true} {
		name := "list"
		if signing {
			name = "sign"
		}
		t.Run(name, func(t *testing.T) {
			backend := newBlockingListAgent(t)
			pub := addAgentKey(t, backend.ExtendedAgent, "allowed")
			if signing {
				backend.blockListAt, backend.blockSign = -1, true
			}
			socket := filepath.Join(testutil.ShortSocketDir(t), "upstream.sock")
			serveShutdownAgent(t, socket, backend)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			client, err := newReconnectClientWithTelemetry(ctx, socket, slog.New(slog.DiscardHandler), nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cancel(); _ = client.Close(t.Context()) })
			result := testutil.RunAsync(func() error {
				if signing {
					_, err := client.SignWithFlags(pub, []byte("payload"), 0)
					return err
				}
				_, err := client.List()
				return err
			})
			if !testutil.WaitForEvent(t, backend.started, "blocked wire request") {
				return
			}
			cancel()
			if testutil.WaitForAsyncStop(t, result, "wire request") && result.Err() == nil {
				t.Error("canceled wire request succeeded")
			}
		})
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
	result := testutil.RunAsync(func() error {
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
		testutil.WaitForAsyncStop(t, result, "test upstream agent")
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

func TestServerStartupErrorsDuringCancellation(t *testing.T) {
	failure := errors.New("injected startup failure")
	for _, phase := range []string{"dial", "listen"} {
		for _, cause := range []error{failure, context.Canceled} {
			t.Run(phase+"/"+cause.Error(), func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				srv := NewServer(ctx, "unused", 0, slog.New(slog.DiscardHandler))
				srv.newUpstreamClient = func(ctx context.Context, _ string, log *slog.Logger, telemetry *proxyTelemetry) (*reconnectClient, error) {
					if phase == "dial" {
						cancel()
						return nil, fmt.Errorf("dial: %w", cause)
					}
					client := &reconnectClient{ctx: ctx, log: log, telemetry: telemetry}
					client.current.Store(&upstreamConn{client: newTestKeyring(t), conn: &testUpstreamTransport{}})
					return client, nil
				}
				srv.listen = func(context.Context, string) (net.Listener, error) {
					cancel()
					return nil, fmt.Errorf("listen: %w", cause)
				}
				socket := filepath.Join(testutil.ShortSocketDir(t), "group.sock")
				err := srv.Run(ctx, []config.Group{{Name: "test", Socket: socket}})
				if errors.Is(cause, context.Canceled) {
					if err != nil {
						t.Errorf("Run() error = %v, want clean cancellation", err)
					}
				} else if !errors.Is(err, failure) {
					t.Errorf("Run() error = %v, want original failure", err)
				}
			})
		}
	}
}
