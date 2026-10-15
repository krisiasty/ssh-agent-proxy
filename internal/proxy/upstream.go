// Package proxy implements the filtering SSH agent and the socket server that
// exposes one filtered view of the upstream agent per group.
package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type upstreamConn struct {
	client agent.ExtendedAgent
	conn   net.Conn
	// unanswered is set when the watchdog drops the connection because a
	// request on it went unanswered.
	unanswered atomic.Bool
}

// failureTrackingConn records I/O failures without changing the error returned
// by the SSH agent client. Agent-level failure replies are ordinary successful
// reads, which lets reconnectClient distinguish them from a broken transport.
type failureTrackingConn struct {
	net.Conn
	failed           atomic.Bool
	stopCancellation func() bool
}

func (c *failureTrackingConn) Close() error {
	if c.stopCancellation != nil {
		c.stopCancellation()
	}
	return c.Conn.Close()
}

func (c *failureTrackingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.failed.Store(true)
	}
	return n, err
}

func (c *failureTrackingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil {
		c.failed.Store(true)
	}
	return n, err
}

func (c *failureTrackingConn) transportFailed() bool {
	return c.failed.Load()
}

type transportFailureReporter interface {
	transportFailed() bool
}

// x/crypto/ssh/agent does not expose a typed transport error. It consistently
// wraps failures from the underlying connection with this prefix, while agent
// failure replies use operation-specific errors. Requiring both that prefix
// and a recorded I/O error avoids blaming one concurrent semantic failure for
// a transport error observed by another request on the shared connection.
const agentClientErrorPrefix = "agent: client error:"

func (c *upstreamConn) transportFailed(err error) bool {
	reporter, ok := c.conn.(transportFailureReporter)
	return err != nil && ok && reporter.transportFailed() && strings.HasPrefix(err.Error(), agentClientErrorPrefix)
}

type upstreamCall struct {
	log       *slog.Logger
	telemetry *proxyTelemetry
	started   time.Time
	attrs     []any
	enabled   bool
}

func beginTrackedUpstreamCall(ctx context.Context, log *slog.Logger, telemetry *proxyTelemetry, operation string, attrs ...any) upstreamCall {
	if !log.Enabled(ctx, slog.LevelDebug) {
		return upstreamCall{telemetry: telemetry}
	}
	callAttrs := make([]any, 0, len(attrs)+2)
	callAttrs = append(callAttrs, "operation", operation)
	callAttrs = append(callAttrs, attrs...)
	return upstreamCall{
		log:       log,
		telemetry: telemetry,
		started:   time.Now(),
		attrs:     callAttrs,
		enabled:   true,
	}
}

func (c upstreamCall) finish(err error, attrs ...any) {
	c.telemetry.upstreamCall(err)
	if !c.enabled {
		return
	}
	resultAttrs := make([]any, 0, len(c.attrs)+len(attrs)+4)
	resultAttrs = append(resultAttrs, c.attrs...)
	resultAttrs = append(resultAttrs, attrs...)
	resultAttrs = append(resultAttrs, "duration", time.Since(c.started).String())
	if err != nil {
		resultAttrs = append(resultAttrs, "err", err)
	}
	c.log.Debug("upstream call", resultAttrs...)
}

// reconnectClient wraps a shared upstream agent client and reconnects
// transparently if the connection dies.
//
// The first connection is dialed on first use rather than at construction, so
// an agent that is not running yet never keeps the group sockets unbound. The
// current pointer is nil until that dial succeeds, and again after the
// request watchdog drops a stuck connection; loading it is lock-free. Dialing
// is serialized so only one goroutine dials at a time, and a replacement for a
// failed connection is dialed **before** swapping.
type reconnectClient struct {
	upstream  string
	log       *slog.Logger
	ctx       context.Context
	cancel    context.CancelFunc
	current   atomic.Pointer[upstreamConn]
	telemetry *proxyTelemetry

	// requestTimeout is how long a request may go unanswered before the
	// connection is dropped; zero disables the watchdog.
	requestTimeout time.Duration

	dial func() (agent.ExtendedAgent, net.Conn, error)

	mu       sync.Mutex // guards reconnect and shutdown
	closed   bool
	closeErr error
}

func newReconnectClientWithTelemetry(parentCtx context.Context, upstream string, log *slog.Logger, telemetry *proxyTelemetry) (*reconnectClient, error) {
	clientCtx, cancelClient := context.WithCancel(parentCtx)
	var connectionAttempt atomic.Uint64
	dial := func() (agent.ExtendedAgent, net.Conn, error) {
		attempt := connectionAttempt.Add(1)
		ctx, cancel := context.WithTimeout(clientCtx, dialTimeout)
		defer cancel()
		call := beginTrackedUpstreamCall(ctx, log, telemetry, "connect", "attempt", attempt, "upstream", upstream)

		conn, err := dialer.DialContext(ctx, "unix", upstream)
		if err != nil {
			call.finish(err)
			return nil, nil, fmt.Errorf("connecting to upstream agent: %w", err)
		}
		trackedConn := &failureTrackingConn{Conn: conn}
		// Cancellation interrupts every pending wire operation without closing
		// resources outside the server's ordered teardown. Requests carry no
		// wire deadline; only cancellation and the request watchdog end them.
		trackedConn.stopCancellation = context.AfterFunc(clientCtx, func() {
			_ = conn.SetDeadline(time.Now())
		})
		call.finish(nil)
		return agent.NewClient(trackedConn), trackedConn, nil
	}
	return &reconnectClient{
		upstream:  upstream,
		log:       log,
		ctx:       clientCtx,
		cancel:    cancelClient,
		telemetry: telemetry,
		dial:      dial,
	}, nil
}

// errUpstreamClosed reports a request made after the client was closed or its
// lifetime ended.
var errUpstreamClosed = fmt.Errorf("upstream agent client closed: %w", net.ErrClosed)

// connection returns the current upstream connection, dialing the first one
// if none is open yet. A failed dial is returned to the caller and retried on
// the next request, so the proxy connects as soon as the agent is available.
func (r *reconnectClient) connection() (*upstreamConn, error) {
	if current := r.current.Load(); current != nil {
		return current, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed || r.canceled() {
		return nil, errUpstreamClosed
	}
	if current := r.current.Load(); current != nil {
		return current, nil
	}
	client, conn, err := r.dial()
	if err != nil {
		return nil, err
	}
	if r.canceled() {
		if err := conn.Close(); err != nil {
			r.log.Warn("closing upstream connection dialed during shutdown", "err", err)
		}
		return nil, errUpstreamClosed
	}
	current := &upstreamConn{client: client, conn: conn}
	r.current.Store(current)
	r.log.Info("upstream connected")
	return current, nil
}

func (r *reconnectClient) logContext() context.Context {
	return r.ctx
}

func (r *reconnectClient) canceled() bool {
	return r.ctx.Err() != nil
}

// reconnect replaces failed if it is still the current upstream connection.
//
// The identity check prevents callers that failed concurrently on the same old
// connection from replacing and closing a replacement installed by another
// caller. The return value reports whether a usable replacement is available.
func (r *reconnectClient) reconnect(failed *upstreamConn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed || r.canceled() {
		return false
	}
	// Another caller already installed a replacement. A nil pointer means the
	// watchdog dropped the connection, so a replacement is still needed.
	if current := r.current.Load(); current != failed && current != nil {
		return true
	}

	// Dial the replacement **before** touching the live pointer.
	client, conn, err := r.dial()
	if err != nil {
		if !r.canceled() {
			r.log.Warn("upstream reconnect failed, proxy may not work", "err", err)
		}
		return false // keep old connection intact
	}
	if r.canceled() {
		if err := conn.Close(); err != nil {
			r.log.Warn("closing upstream connection dialed during shutdown", "err", err)
		}
		return false
	}

	old := r.current.Swap(&upstreamConn{client: client, conn: conn})
	if r.telemetry != nil {
		r.telemetry.upstreamReconnects.Add(1)
	}
	r.log.Warn("upstream reconnected")
	if old != nil {
		call := beginTrackedUpstreamCall(r.logContext(), r.log, r.telemetry, "close", "connection", "replaced")
		err = old.conn.Close()
		call.finish(err)
	}
	return true
}

// watch starts the request watchdog for one request on current and returns a
// function that stops it once the request returns. The agent answers the
// requests on a connection in order, so one left unanswered for
// requestTimeout means the connection is stuck: everything queued behind it
// would wait forever, even after the agent recovers. Dropping it fails those
// requests, as they would fail against a hung agent anyway, and the next
// request dials a fresh connection, so the proxy recovers on its own once the
// agent answers again, as clients connecting to the agent directly would.
func (r *reconnectClient) watch(current *upstreamConn) (stop func()) {
	if r.requestTimeout <= 0 {
		return func() {}
	}
	timer := time.AfterFunc(r.requestTimeout, func() { r.drop(current) })
	return func() { timer.Stop() }
}

// drop closes current after a request on it went unanswered and clears it, so
// the next request dials a replacement.
func (r *reconnectClient) drop(current *upstreamConn) {
	if !current.unanswered.CompareAndSwap(false, true) {
		return
	}
	if !r.current.CompareAndSwap(current, nil) {
		// Already replaced or closed by another path.
		return
	}
	if !r.canceled() {
		r.log.Warn("upstream request unanswered; dropping connection", "timeout", r.requestTimeout.String())
	}
	call := beginTrackedUpstreamCall(r.logContext(), r.log, r.telemetry, "close", "connection", "unanswered")
	call.finish(current.conn.Close())
}

// unansweredErr explains a request error caused by the watchdog dropping
// current.
func (r *reconnectClient) unansweredErr(current *upstreamConn, err error) error {
	if err == nil || !current.unanswered.Load() {
		return err
	}
	return fmt.Errorf("upstream agent left a request unanswered for %s: %w", r.requestTimeout, err)
}

// Close interrupts reconnects and closes the current upstream connection once.
// Repeated calls return the original close result.
func (r *reconnectClient) Close(ctx context.Context) error {
	// Cancel before taking mu so an in-progress reconnect dial can finish.
	r.cancel()
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return r.closeErr
	}
	r.closed = true
	current := r.current.Load()
	if current == nil {
		return nil
	}
	call := beginTrackedUpstreamCall(ctx, r.log, r.telemetry, "close", "connection", "current")
	r.closeErr = current.conn.Close()
	call.finish(r.closeErr)
	return r.closeErr
}

func (r *reconnectClient) List() ([]*agent.Key, error) {
	current, err := r.connection()
	if err != nil {
		return nil, err
	}
	ks, err := r.listAttempt(current, 1)
	// A request the watchdog dropped is not retried: an immediate retry would
	// wait out the timeout again against the same stuck agent.
	if err == nil || !current.transportFailed(err) || current.unanswered.Load() {
		return ks, err
	}
	if !r.reconnect(current) {
		return nil, err
	}
	next, nextErr := r.connection()
	if nextErr != nil {
		return nil, err
	}
	return r.listAttempt(next, 2)
}

func (r *reconnectClient) listAttempt(current *upstreamConn, attempt int) ([]*agent.Key, error) {
	call := beginTrackedUpstreamCall(r.logContext(), r.log, r.telemetry, "list", "attempt", attempt)
	stop := r.watch(current)
	ks, err := current.client.List()
	stop()
	err = r.unansweredErr(current, err)
	call.finish(err, "keys", len(ks))
	if err == nil && r.log.Enabled(r.logContext(), slog.LevelDebug) {
		for i, key := range ks {
			r.log.Debug(fmt.Sprintf("identity %d/%d", i+1, len(ks)),
				"fingerprint", ssh.FingerprintSHA256(key),
				"comment", key.Comment,
				"algorithm", key.Format,
				"key_size", keyBits(key.Blob))
		}
	}
	return ks, err
}

func (r *reconnectClient) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	current, err := r.connection()
	if err != nil {
		return nil, err
	}
	sig, err := r.signAttempt(current, key, data)
	if current.transportFailed(err) && !current.unanswered.Load() {
		r.reconnect(current)
	}
	return sig, err
}

func (r *reconnectClient) signAttempt(current *upstreamConn, key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	call := beginTrackedUpstreamCall(r.logContext(), r.log, r.telemetry, "sign",
		"attempt", 1,
		"fingerprint", ssh.FingerprintSHA256(key),
		"payload_bytes", len(data))
	stop := r.watch(current)
	sig, err := current.client.Sign(key, data)
	stop()
	err = r.unansweredErr(current, err)
	call.finish(err)
	return sig, err
}

func (r *reconnectClient) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	current, err := r.connection()
	if err != nil {
		return nil, err
	}
	sig, err := r.signWithFlagsAttempt(current, key, data, flags)
	if current.transportFailed(err) && !current.unanswered.Load() {
		r.reconnect(current)
	}
	return sig, err
}

func (r *reconnectClient) signWithFlagsAttempt(current *upstreamConn, key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	call := beginTrackedUpstreamCall(r.logContext(), r.log, r.telemetry, "sign-with-flags",
		"attempt", 1,
		"fingerprint", ssh.FingerprintSHA256(key),
		"flags", flags,
		"payload_bytes", len(data))
	stop := r.watch(current)
	sig, err := current.client.SignWithFlags(key, data, flags)
	stop()
	err = r.unansweredErr(current, err)
	call.finish(err)
	return sig, err
}

func (r *reconnectClient) Add(key agent.AddedKey) error {
	call := beginTrackedUpstreamCall(r.logContext(), r.log, r.telemetry, "add")
	err := r.withConnection(func(up agent.ExtendedAgent) error { return up.Add(key) })
	call.finish(err)
	return err
}

func (r *reconnectClient) Remove(key ssh.PublicKey) error {
	call := beginTrackedUpstreamCall(r.logContext(), r.log, r.telemetry, "remove", "fingerprint", ssh.FingerprintSHA256(key))
	err := r.withConnection(func(up agent.ExtendedAgent) error { return up.Remove(key) })
	call.finish(err)
	return err
}

func (r *reconnectClient) RemoveAll() error {
	call := beginTrackedUpstreamCall(r.logContext(), r.log, r.telemetry, "remove-all")
	err := r.withConnection(func(up agent.ExtendedAgent) error { return up.RemoveAll() })
	call.finish(err)
	return err
}

func (r *reconnectClient) Lock(passphrase []byte) error {
	call := beginTrackedUpstreamCall(r.logContext(), r.log, r.telemetry, "lock")
	err := r.withConnection(func(up agent.ExtendedAgent) error { return up.Lock(passphrase) })
	call.finish(err)
	return err
}

func (r *reconnectClient) Unlock(passphrase []byte) error {
	call := beginTrackedUpstreamCall(r.logContext(), r.log, r.telemetry, "unlock")
	err := r.withConnection(func(up agent.ExtendedAgent) error { return up.Unlock(passphrase) })
	call.finish(err)
	return err
}

func (r *reconnectClient) Signers() ([]ssh.Signer, error) {
	call := beginTrackedUpstreamCall(r.logContext(), r.log, r.telemetry, "signers")
	var signers []ssh.Signer
	err := r.withConnection(func(up agent.ExtendedAgent) error {
		var err error
		signers, err = up.Signers()
		return err
	})
	call.finish(err, "signers", len(signers))
	return signers, err
}

func (r *reconnectClient) Extension(s string, b []byte) ([]byte, error) {
	call := beginTrackedUpstreamCall(r.logContext(), r.log, r.telemetry, "extension", "extension", s, "payload_bytes", len(b))
	var result []byte
	err := r.withConnection(func(up agent.ExtendedAgent) error {
		var err error
		result, err = up.Extension(s, b)
		return err
	})
	call.finish(err, "result_bytes", len(result))
	return result, err
}

// withConnection runs op on the current upstream connection, dialing it first
// if needed.
func (r *reconnectClient) withConnection(op func(agent.ExtendedAgent) error) error {
	current, err := r.connection()
	if err != nil {
		return err
	}
	stop := r.watch(current)
	err = op(current.client)
	stop()
	return r.unansweredErr(current, err)
}
