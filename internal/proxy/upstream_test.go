package proxy

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestAgentClientTransportFailureIsDetected(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	trackedConn := &failureTrackingConn{Conn: clientConn}
	upstream := &upstreamConn{client: agent.NewClient(trackedConn), conn: trackedConn}
	if err := serverConn.Close(); err != nil {
		t.Fatal(err)
	}

	_, err := upstream.client.List()
	if err == nil {
		t.Fatal("List() error = nil after transport closure")
	}
	if !upstream.transportFailed(err) {
		t.Fatalf("transport error %q was not detected", err)
	}
}

func TestAgentFailureReplyIsNotATransportFailure(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	trackedConn := &failureTrackingConn{Conn: clientConn}
	upstream := &upstreamConn{client: agent.NewClient(trackedConn), conn: trackedConn}
	semanticAgent := &scriptedAgent{
		ExtendedAgent:    newTestKeyring(t),
		signWithFlagsErr: errors.New("confirmation rejected"),
	}
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- agent.ServeAgent(semanticAgent, serverConn)
	}()

	pub := addAgentKey(t, newTestKeyring(t), "test")
	_, err := upstream.client.SignWithFlags(pub, []byte("payload"), 0)
	if err == nil {
		t.Fatal("SignWithFlags() error = nil after agent failure reply")
	}
	if upstream.transportFailed(err) {
		t.Fatalf("agent failure reply %q was classified as a transport error", err)
	}

	if err := clientConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("agent server did not stop after closing test connection")
	}
}

func TestSemanticAgentFailuresDoNotReconnectOrRetry(t *testing.T) {
	semanticErr := errors.New("agent refused request")
	pub := addAgentKey(t, newTestKeyring(t), "test")

	tests := []struct {
		name string
		call func(*reconnectClient) error
		set  func(*scriptedAgent)
	}{
		{
			name: "list",
			call: func(client *reconnectClient) error {
				_, err := client.List()
				return err
			},
			set: func(upstream *scriptedAgent) { upstream.listErr = semanticErr },
		},
		{
			name: "sign",
			call: func(client *reconnectClient) error {
				_, err := client.Sign(pub, []byte("payload"))
				return err
			},
			set: func(upstream *scriptedAgent) { upstream.signErr = semanticErr },
		},
		{
			name: "sign-with-flags",
			call: func(client *reconnectClient) error {
				_, err := client.SignWithFlags(pub, []byte("payload"), agent.SignatureFlagRsaSha256)
				return err
			},
			set: func(upstream *scriptedAgent) { upstream.signWithFlagsErr = semanticErr },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := &scriptedAgent{ExtendedAgent: newTestKeyring(t)}
			tt.set(upstream)
			conn := &testUpstreamTransport{}
			// Simulate another concurrent request observing an I/O failure.
			// This semantic error must still not be mistaken for that failure.
			conn.failed.Store(true)
			current := &upstreamConn{client: upstream, conn: conn}
			client := &reconnectClient{log: slog.New(slog.DiscardHandler)}
			client.current.Store(current)
			var dialCalls atomic.Int32
			client.dial = func() (agent.ExtendedAgent, net.Conn, error) {
				dialCalls.Add(1)
				return newTestKeyring(t), &testUpstreamTransport{}, nil
			}

			err := tt.call(client)
			if !errors.Is(err, semanticErr) {
				t.Fatalf("call error = %v, want %v", err, semanticErr)
			}
			if got := upstream.calls(); got != 1 {
				t.Errorf("upstream calls = %d, want 1", got)
			}
			if got := dialCalls.Load(); got != 0 {
				t.Errorf("reconnect dials = %d, want 0", got)
			}
			if got := conn.closeCalls.Load(); got != 0 {
				t.Errorf("connection closes = %d, want 0", got)
			}
			if got := client.current.Load(); got != current {
				t.Error("semantic failure replaced the current connection")
			}
		})
	}
}

func TestSigningTransportFailureReconnectsWithoutRetry(t *testing.T) {
	transportErr := errors.New("agent: client error: unexpected EOF")
	pub := addAgentKey(t, newTestKeyring(t), "test")

	tests := []struct {
		name string
		call func(*reconnectClient) error
		set  func(*scriptedAgent)
	}{
		{
			name: "sign",
			call: func(client *reconnectClient) error {
				_, err := client.Sign(pub, []byte("payload"))
				return err
			},
			set: func(upstream *scriptedAgent) { upstream.signErr = transportErr },
		},
		{
			name: "sign-with-flags",
			call: func(client *reconnectClient) error {
				_, err := client.SignWithFlags(pub, []byte("payload"), 0)
				return err
			},
			set: func(upstream *scriptedAgent) { upstream.signWithFlagsErr = transportErr },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failedAgent := &scriptedAgent{ExtendedAgent: newTestKeyring(t)}
			tt.set(failedAgent)
			failedConn := &testUpstreamTransport{}
			failedConn.failed.Store(true)
			client := &reconnectClient{log: slog.New(slog.DiscardHandler)}
			client.current.Store(&upstreamConn{client: failedAgent, conn: failedConn})

			replacementAgent := &scriptedAgent{ExtendedAgent: newTestKeyring(t)}
			replacementConn := &testUpstreamTransport{}
			var dialCalls atomic.Int32
			client.dial = func() (agent.ExtendedAgent, net.Conn, error) {
				dialCalls.Add(1)
				return replacementAgent, replacementConn, nil
			}

			err := tt.call(client)
			if !errors.Is(err, transportErr) {
				t.Fatalf("call error = %v, want original transport error %v", err, transportErr)
			}
			if got := failedAgent.calls(); got != 1 {
				t.Errorf("failed upstream calls = %d, want 1", got)
			}
			if got := replacementAgent.calls(); got != 0 {
				t.Errorf("replacement upstream calls = %d, want 0", got)
			}
			if got := dialCalls.Load(); got != 1 {
				t.Errorf("reconnect dials = %d, want 1", got)
			}
			if got := failedConn.closeCalls.Load(); got != 1 {
				t.Errorf("failed connection closes = %d, want 1", got)
			}
			if got := replacementConn.closeCalls.Load(); got != 0 {
				t.Errorf("replacement connection closes = %d, want 0", got)
			}
		})
	}
}

func TestConcurrentTransportFailuresInstallOneReplacement(t *testing.T) {
	const callers = 128
	failedAgent := &barrierListAgent{
		ExtendedAgent: newTestKeyring(t),
		wantCallers:   callers,
		ready:         make(chan struct{}),
		release:       make(chan struct{}),
	}
	failedConn := &testUpstreamTransport{}
	failedConn.failed.Store(true)
	client := &reconnectClient{log: slog.New(slog.DiscardHandler)}
	client.current.Store(&upstreamConn{client: failedAgent, conn: failedConn})

	replacementAgent := newTestKeyring(t)
	replacementConn := &testUpstreamTransport{}
	var dialCalls atomic.Int32
	client.dial = func() (agent.ExtendedAgent, net.Conn, error) {
		dialCalls.Add(1)
		return replacementAgent, replacementConn, nil
	}

	start := make(chan struct{})
	errs := make(chan error, callers)
	var ready sync.WaitGroup
	ready.Add(callers)
	for range callers {
		go func() {
			ready.Done()
			<-start
			_, err := client.List()
			errs <- err
		}()
	}
	ready.Wait()
	close(start)

	select {
	case <-failedAgent.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent callers did not all reach the failed connection")
	}
	close(failedAgent.release)

	for range callers {
		if err := <-errs; err != nil {
			t.Errorf("List() after reconnect: %v", err)
		}
	}
	if got := dialCalls.Load(); got != 1 {
		t.Errorf("reconnect dials = %d, want 1", got)
	}
	if got := failedConn.closeCalls.Load(); got != 1 {
		t.Errorf("failed connection closes = %d, want 1", got)
	}
	if got := replacementConn.closeCalls.Load(); got != 0 {
		t.Errorf("winning replacement closes = %d, want 0", got)
	}
}

type scriptedAgent struct {
	agent.ExtendedAgent
	listErr          error
	signErr          error
	signWithFlagsErr error
	callCount        atomic.Int32
}

func (a *scriptedAgent) List() ([]*agent.Key, error) {
	a.callCount.Add(1)
	if a.listErr != nil {
		return nil, a.listErr
	}
	return a.ExtendedAgent.List()
}

func (a *scriptedAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	a.callCount.Add(1)
	if a.signErr != nil {
		return nil, a.signErr
	}
	return a.ExtendedAgent.Sign(key, data)
}

func (a *scriptedAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.callCount.Add(1)
	if a.signWithFlagsErr != nil {
		return nil, a.signWithFlagsErr
	}
	return a.ExtendedAgent.SignWithFlags(key, data, flags)
}

func (a *scriptedAgent) calls() int {
	return int(a.callCount.Load())
}

type barrierListAgent struct {
	agent.ExtendedAgent
	wantCallers int32
	arrived     atomic.Int32
	ready       chan struct{}
	release     chan struct{}
}

func (a *barrierListAgent) List() ([]*agent.Key, error) {
	if a.arrived.Add(1) == a.wantCallers {
		close(a.ready)
	}
	<-a.release
	return nil, errors.New("agent: client error: unexpected EOF")
}

type testUpstreamTransport struct {
	failed     atomic.Bool
	closeCalls atomic.Int32
}

func (c *testUpstreamTransport) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *testUpstreamTransport) Write(p []byte) (int, error)      { return len(p), nil }
func (c *testUpstreamTransport) Close() error                     { c.closeCalls.Add(1); return nil }
func (c *testUpstreamTransport) LocalAddr() net.Addr              { return nil }
func (c *testUpstreamTransport) RemoteAddr() net.Addr             { return nil }
func (c *testUpstreamTransport) SetDeadline(time.Time) error      { return nil }
func (c *testUpstreamTransport) SetReadDeadline(time.Time) error  { return nil }
func (c *testUpstreamTransport) SetWriteDeadline(time.Time) error { return nil }
func (c *testUpstreamTransport) transportFailed() bool            { return c.failed.Load() }
