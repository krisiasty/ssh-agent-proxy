// Package proxy implements the filtering SSH agent and the socket server that
// exposes one filtered view of the upstream agent per group.
package proxy

import (
	"fmt"
	"log/slog"
	"net"
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
type reconnectClient struct {
	upstream string
	log      *slog.Logger
	current  atomic.Pointer[upstreamConn]

	dial func() (agent.ExtendedAgent, net.Conn, error)
}

func newReconnectClient(upstream string, log *slog.Logger) *reconnectClient {
	dial := func() (agent.ExtendedAgent, net.Conn, error) {
		conn, err := dialer.Dial("unix", upstream)
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
		panic("reconnectClient: initial dial failed: " + err.Error())
	}
	rc.current.Store(&upstreamConn{client: client, conn: conn})
	return rc
}

func (r *reconnectClient) get() agent.ExtendedAgent {
	return r.current.Load().client
}

func (r *reconnectClient) reconnect() {
	old := r.current.Swap(nil)
	if old != nil {
		_ = old.conn.Close()
	}
	client, conn, err := r.dial()
	if err != nil {
		r.log.Warn("upstream reconnect failed, proxy may not work", "err", err)
		return
	}
	r.log.Warn("upstream reconnected")
	r.current.Store(&upstreamConn{client: client, conn: conn})
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

func (r *reconnectClient) Add(key agent.AddedKey) error          { return r.get().Add(key) }
func (r *reconnectClient) Remove(key ssh.PublicKey) error        { return r.get().Remove(key) }
func (r *reconnectClient) RemoveAll() error                      { return r.get().RemoveAll() }
func (r *reconnectClient) Lock(passphrase []byte) error          { return r.get().Lock(passphrase) }
func (r *reconnectClient) Unlock(passphrase []byte) error        { return r.get().Unlock(passphrase) }
func (r *reconnectClient) Signers() ([]ssh.Signer, error)        { return r.get().Signers() }
func (r *reconnectClient) Extension(s string, b []byte) ([]byte, error) { return r.get().Extension(s, b) }
