package testutil

import (
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// NewKeyring returns an empty in-memory agent with the extended interface.
func NewKeyring(t *testing.T) agent.ExtendedAgent {
	t.Helper()
	keyring, ok := agent.NewKeyring().(agent.ExtendedAgent)
	if !ok {
		t.Fatal("agent.NewKeyring does not implement agent.ExtendedAgent")
	}
	return keyring
}

// BlockingAgent wraps an agent and stalls selected requests until Release, so
// tests can hold an upstream request in flight. Nothing blocks until a test
// calls BlockListFrom, BlockLists, or BlockSign.
type BlockingAgent struct {
	agent.ExtendedAgent
	listCalls   atomic.Int64
	blockListAt atomic.Int64 // First List call that stalls; zero disables List blocking.
	blockSign   atomic.Bool
	started     chan struct{}
	release     chan struct{}
	startOnce   sync.Once
	releaseOnce sync.Once
}

// NewBlockingAgent wraps backend and releases any stalled request when the
// test finishes.
func NewBlockingAgent(t *testing.T, backend agent.ExtendedAgent) *BlockingAgent {
	t.Helper()
	a := &BlockingAgent{ExtendedAgent: backend, started: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(a.Release)
	return a
}

// BlockListFrom stalls the call-th List request and every later one.
func (a *BlockingAgent) BlockListFrom(call int64) {
	a.blockListAt.Store(call)
}

// BlockLists stalls every List request from now on.
func (a *BlockingAgent) BlockLists() {
	a.BlockListFrom(a.listCalls.Load() + 1)
}

// BlockSign stalls every signing request from now on.
func (a *BlockingAgent) BlockSign() {
	a.blockSign.Store(true)
}

// Started is closed when the first request stalls.
func (a *BlockingAgent) Started() <-chan struct{} {
	return a.started
}

// Release unblocks stalled and future requests. It is safe to call repeatedly.
func (a *BlockingAgent) Release() {
	a.releaseOnce.Do(func() { close(a.release) })
}

// ListCalls reports how many List requests the agent has received.
func (a *BlockingAgent) ListCalls() int64 {
	return a.listCalls.Load()
}

// List counts the request and stalls it when List blocking applies.
func (a *BlockingAgent) List() ([]*agent.Key, error) {
	calls := a.listCalls.Add(1)
	if at := a.blockListAt.Load(); at > 0 && calls >= at {
		a.stall()
	}
	return a.ExtendedAgent.List()
}

// SignWithFlags stalls the request when signing is blocked.
func (a *BlockingAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if a.blockSign.Load() {
		a.stall()
	}
	return a.ExtendedAgent.SignWithFlags(key, data, flags)
}

func (a *BlockingAgent) stall() {
	a.startOnce.Do(func() { close(a.started) })
	<-a.release
}
