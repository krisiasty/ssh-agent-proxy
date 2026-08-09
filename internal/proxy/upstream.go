// Package proxy implements the filtering SSH agent and the socket server that
// exposes one filtered view of the upstream agent per group.
package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type upstreamConn struct {
	client agent.ExtendedAgent
	conn   net.Conn
}

type upstreamCall struct {
	log     *slog.Logger
	started time.Time
	attrs   []any
	enabled bool
}

func beginUpstreamCall(ctx context.Context, log *slog.Logger, operation string, attrs ...any) upstreamCall {
	if !log.Enabled(ctx, slog.LevelDebug) {
		return upstreamCall{}
	}
	callAttrs := make([]any, 0, len(attrs)+2)
	callAttrs = append(callAttrs, "operation", operation)
	callAttrs = append(callAttrs, attrs...)
	return upstreamCall{
		log:     log,
		started: time.Now(),
		attrs:   callAttrs,
		enabled: true,
	}
}

func (c upstreamCall) finish(err error, attrs ...any) {
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
// The current pointer is an atomic.Pointer that is never nil — get() is
// always a lock-free load. Reconnect is serialized so only one goroutine
// dials at a time, and the new connection is dialed **before** swapping to
// eliminate the nil-window panic that existed in the previous Swap(nil) →
// dial → Store sequence.
type reconnectClient struct {
	upstream string
	log      *slog.Logger
	ctx      context.Context
	current  atomic.Pointer[upstreamConn]

	dial func() (agent.ExtendedAgent, net.Conn, error)

	mu sync.Mutex // guards reconnect: only one goroutine reconnects at a time
}

func newReconnectClient(parentCtx context.Context, upstream string, log *slog.Logger) (*reconnectClient, error) {
	var connectionAttempt atomic.Uint64
	dial := func() (agent.ExtendedAgent, net.Conn, error) {
		attempt := connectionAttempt.Add(1)
		ctx, cancel := context.WithTimeout(parentCtx, dialTimeout)
		defer cancel()
		call := beginUpstreamCall(ctx, log, "connect", "attempt", attempt, "upstream", upstream)

		conn, err := dialer.DialContext(ctx, "unix", upstream)
		if err != nil {
			call.finish(err)
			return nil, nil, fmt.Errorf("connecting to upstream agent: %w", err)
		}
		call.finish(nil)
		return agent.NewClient(conn), conn, nil
	}
	rc := &reconnectClient{
		upstream: upstream,
		log:      log,
		ctx:      parentCtx,
		dial:     dial,
	}
	client, conn, err := rc.dial()
	if err != nil {
		return nil, fmt.Errorf("initial upstream connection: %w", err)
	}
	rc.current.Store(&upstreamConn{client: client, conn: conn})
	return rc, nil
}

func (r *reconnectClient) get() agent.ExtendedAgent {
	return r.current.Load().client
}

func (r *reconnectClient) logContext() context.Context {
	if r.ctx != nil {
		return r.ctx
	}
	return context.Background()
}

// reconnect replaces the upstream connection if it is broken.
//
// Only one goroutine performs the actual dial (guarded by mu). The new
// connection is dialed **before** swapping, so r.current is never nil and
// concurrent readers always get a valid pointer. If the dial fails, the old
// connection is kept intact.
func (r *reconnectClient) reconnect() {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Dial the replacement **before** touching the live pointer.
	client, conn, err := r.dial()
	if err != nil {
		r.log.Warn("upstream reconnect failed, proxy may not work", "err", err)
		return // keep old connection alive
	}

	old := r.current.Swap(&upstreamConn{client: client, conn: conn})
	r.log.Warn("upstream reconnected")
	call := beginUpstreamCall(r.logContext(), r.log, "close", "connection", "replaced")
	err = old.conn.Close()
	call.finish(err)
}

// Close closes the current upstream connection.
func (r *reconnectClient) Close(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	current := r.current.Load()
	if current == nil {
		return nil
	}
	call := beginUpstreamCall(ctx, r.log, "close", "connection", "current")
	err := current.conn.Close()
	call.finish(err)
	return err
}

func (r *reconnectClient) List() ([]*agent.Key, error) {
	ks, err := r.listAttempt(1)
	if err != nil {
		r.reconnect()
		return r.listAttempt(2)
	}
	return ks, nil
}

func (r *reconnectClient) listAttempt(attempt int) ([]*agent.Key, error) {
	call := beginUpstreamCall(r.logContext(), r.log, "list", "attempt", attempt)
	ks, err := r.get().List()
	call.finish(err, "keys", len(ks))
	return ks, err
}

func (r *reconnectClient) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	sig, err := r.signAttempt(key, data, 1)
	if err != nil {
		r.reconnect()
		return r.signAttempt(key, data, 2)
	}
	return sig, nil
}

func (r *reconnectClient) signAttempt(key ssh.PublicKey, data []byte, attempt int) (*ssh.Signature, error) {
	call := beginUpstreamCall(r.logContext(), r.log, "sign",
		"attempt", attempt,
		"fingerprint", ssh.FingerprintSHA256(key),
		"payload_bytes", len(data))
	sig, err := r.get().Sign(key, data)
	call.finish(err)
	return sig, err
}

func (r *reconnectClient) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	sig, err := r.signWithFlagsAttempt(key, data, flags, 1)
	if err != nil {
		r.reconnect()
		return r.signWithFlagsAttempt(key, data, flags, 2)
	}
	return sig, nil
}

func (r *reconnectClient) signWithFlagsAttempt(key ssh.PublicKey, data []byte, flags agent.SignatureFlags, attempt int) (*ssh.Signature, error) {
	call := beginUpstreamCall(r.logContext(), r.log, "sign-with-flags",
		"attempt", attempt,
		"fingerprint", ssh.FingerprintSHA256(key),
		"flags", flags,
		"payload_bytes", len(data))
	sig, err := r.get().SignWithFlags(key, data, flags)
	call.finish(err)
	return sig, err
}

func (r *reconnectClient) Add(key agent.AddedKey) error {
	call := beginUpstreamCall(r.logContext(), r.log, "add")
	err := r.get().Add(key)
	call.finish(err)
	return err
}

func (r *reconnectClient) Remove(key ssh.PublicKey) error {
	call := beginUpstreamCall(r.logContext(), r.log, "remove", "fingerprint", ssh.FingerprintSHA256(key))
	err := r.get().Remove(key)
	call.finish(err)
	return err
}

func (r *reconnectClient) RemoveAll() error {
	call := beginUpstreamCall(r.logContext(), r.log, "remove-all")
	err := r.get().RemoveAll()
	call.finish(err)
	return err
}

func (r *reconnectClient) Lock(passphrase []byte) error {
	call := beginUpstreamCall(r.logContext(), r.log, "lock")
	err := r.get().Lock(passphrase)
	call.finish(err)
	return err
}

func (r *reconnectClient) Unlock(passphrase []byte) error {
	call := beginUpstreamCall(r.logContext(), r.log, "unlock")
	err := r.get().Unlock(passphrase)
	call.finish(err)
	return err
}

func (r *reconnectClient) Signers() ([]ssh.Signer, error) {
	call := beginUpstreamCall(r.logContext(), r.log, "signers")
	signers, err := r.get().Signers()
	call.finish(err, "signers", len(signers))
	return signers, err
}

func (r *reconnectClient) Extension(s string, b []byte) ([]byte, error) {
	call := beginUpstreamCall(r.logContext(), r.log, "extension", "extension", s, "payload_bytes", len(b))
	result, err := r.get().Extension(s, b)
	call.finish(err, "result_bytes", len(result))
	return result, err
}
