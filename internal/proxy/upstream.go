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

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type upstreamConn struct {
	client agent.ExtendedAgent
	conn   net.Conn
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
	current  atomic.Pointer[upstreamConn]

	dial func() (agent.ExtendedAgent, net.Conn, error)

	mu sync.Mutex // guards reconnect: only one goroutine reconnects at a time
}

func newReconnectClient(parentCtx context.Context, upstream string, log *slog.Logger) (*reconnectClient, error) {
	dial := func() (agent.ExtendedAgent, net.Conn, error) {
		ctx, cancel := context.WithTimeout(parentCtx, dialTimeout)
		defer cancel()

		conn, err := dialer.DialContext(ctx, "unix", upstream)
		if err != nil {
			return nil, nil, fmt.Errorf("connecting to upstream agent: %w", err)
		}
		return agent.NewClient(conn), conn, nil
	}
	rc := &reconnectClient{
		upstream: upstream,
		log:      log,
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
	if err := old.conn.Close(); err != nil {
		r.log.Debug("closing replaced upstream connection", "err", err)
	}
}

// Close closes the current upstream connection.
func (r *reconnectClient) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	current := r.current.Load()
	if current == nil {
		return nil
	}
	return current.conn.Close()
}

func (r *reconnectClient) List() ([]*agent.Key, error) {
	ks, err := r.get().List()
	if err != nil {
		r.reconnect()
		return r.get().List()
	}
	return ks, nil
}

func (r *reconnectClient) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	sig, err := r.get().Sign(key, data)
	if err != nil {
		r.reconnect()
		return r.get().Sign(key, data)
	}
	return sig, nil
}

func (r *reconnectClient) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	sig, err := r.get().SignWithFlags(key, data, flags)
	if err != nil {
		r.reconnect()
		return r.get().SignWithFlags(key, data, flags)
	}
	return sig, nil
}

func (r *reconnectClient) Add(key agent.AddedKey) error   { return r.get().Add(key) }
func (r *reconnectClient) Remove(key ssh.PublicKey) error { return r.get().Remove(key) }
func (r *reconnectClient) RemoveAll() error               { return r.get().RemoveAll() }
func (r *reconnectClient) Lock(passphrase []byte) error   { return r.get().Lock(passphrase) }
func (r *reconnectClient) Unlock(passphrase []byte) error { return r.get().Unlock(passphrase) }
func (r *reconnectClient) Signers() ([]ssh.Signer, error) { return r.get().Signers() }
func (r *reconnectClient) Extension(s string, b []byte) ([]byte, error) {
	return r.get().Extension(s, b)
}
