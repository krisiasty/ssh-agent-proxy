package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/krisiasty/ssh-agent-proxy/internal/keys"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestFilterAgentEnforcement(t *testing.T) {
	// Build ed25519 keys directly so we keep the private key for keyring.Add.
	_, privAllowed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, privHidden, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	up, ok := agent.NewKeyring().(agent.ExtendedAgent)
	if !ok {
		t.Fatal("agent.NewKeyring does not implement agent.ExtendedAgent")
	}
	if err := up.Add(agent.AddedKey{PrivateKey: privAllowed, Comment: "allowed"}); err != nil {
		t.Fatal(err)
	}
	if err := up.Add(agent.AddedKey{PrivateKey: privHidden, Comment: "hidden"}); err != nil {
		t.Fatal(err)
	}

	m, err := keys.NewMatcher("comment", "allowed")
	if err != nil {
		t.Fatal(err)
	}

	fa := &filterAgent{
		up:            up,
		authorization: newGroupAuthorization([]keys.Matcher{m}),
		group:         "test",
		log:           slog.New(slog.DiscardHandler),
	}

	// List exposes only the allowed key.
	list, err := fa.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Comment != "allowed" {
		t.Fatalf("List = %d keys, want 1 (allowed)", len(list))
	}

	allowedPub, err := ssh.NewPublicKey(privAllowed.Public())
	if err != nil {
		t.Fatal(err)
	}
	hiddenPub, err := ssh.NewPublicKey(privHidden.Public())
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("sign me")

	// Signing with the allowed key succeeds.
	if _, err := fa.Sign(allowedPub, data); err != nil {
		t.Errorf("Sign(allowed) failed: %v", err)
	}

	// Signing with the hidden key is refused server-side, even though upstream holds it.
	if _, err := fa.Sign(hiddenPub, data); err == nil {
		t.Error("Sign(hidden) succeeded; expected refusal")
	}

	// All mutating operations are refused.
	if err := fa.Add(agent.AddedKey{PrivateKey: privHidden}); err == nil {
		t.Error("Add should be refused")
	}
	if err := fa.Remove(allowedPub); err == nil {
		t.Error("Remove should be refused")
	}
	if err := fa.RemoveAll(); err == nil {
		t.Error("RemoveAll should be refused")
	}
	if err := fa.Lock([]byte("x")); err == nil {
		t.Error("Lock should be refused")
	}
	if _, err := fa.Extension("query", nil); !errors.Is(err, agent.ErrExtensionUnsupported) {
		t.Errorf("Extension err = %v, want ErrExtensionUnsupported", err)
	}

	// Upstream is untouched: still holds both keys.
	all, err := up.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("upstream now has %d keys, want 2 (proxy must not mutate)", len(all))
	}
}

func TestFilterAgentTracksUpstreamKeyChanges(t *testing.T) {
	up, ok := agent.NewKeyring().(agent.ExtendedAgent)
	if !ok {
		t.Fatal("agent.NewKeyring does not implement agent.ExtendedAgent")
	}
	matcher, err := keys.NewMatcher("comment", "allowed")
	if err != nil {
		t.Fatal(err)
	}
	fa := &filterAgent{
		up:            up,
		authorization: newGroupAuthorization([]keys.Matcher{matcher}),
		group:         "dynamic",
		log:           slog.New(slog.DiscardHandler),
	}

	assertListedKeys(t, fa)
	first := addAgentKey(t, up, "allowed")
	assertListedKeys(t, fa, first)
	assertSigns(t, fa, first)

	added := addAgentKey(t, up, "allowed")
	assertListedKeys(t, fa, first, added)
	assertSigns(t, fa, added)

	if err := up.Remove(first); err != nil {
		t.Fatalf("removing first key: %v", err)
	}
	assertListedKeys(t, fa, added)
	assertRefusesKey(t, fa, first)

	if err := up.Remove(added); err != nil {
		t.Fatalf("removing added key: %v", err)
	}
	replacement := addAgentKey(t, up, "allowed")
	hidden := addAgentKey(t, up, "hidden")
	assertListedKeys(t, fa, replacement)
	assertRefusesKey(t, fa, added)
	assertSigns(t, fa, replacement)
	assertRefusesKey(t, fa, hidden)
}

func TestConcurrentSignAuthorizationCoalescesRefresh(t *testing.T) {
	keyring, ok := agent.NewKeyring().(agent.ExtendedAgent)
	if !ok {
		t.Fatal("agent.NewKeyring does not implement agent.ExtendedAgent")
	}
	pub := addAgentKey(t, keyring, "allowed")
	up := &blockingListAgent{
		ExtendedAgent: keyring,
		started:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	matcher, err := keys.NewMatcher("comment", "allowed")
	if err != nil {
		t.Fatal(err)
	}
	fa := &filterAgent{
		up:            up,
		authorization: newGroupAuthorization([]keys.Matcher{matcher}),
		group:         "concurrent",
		log:           slog.New(slog.DiscardHandler),
	}

	const clients = 128
	start := make(chan struct{})
	errs := make(chan error, clients)
	var ready sync.WaitGroup
	ready.Add(clients)
	for range clients {
		go func() {
			ready.Done()
			<-start
			client := &filterAgent{
				up:            up,
				authorization: fa.authorization,
				group:         fa.group,
				log:           fa.log,
			}
			_, err := client.Sign(pub, []byte("high-load request"))
			errs <- err
		}()
	}
	ready.Wait()
	close(start)
	<-up.started
	close(up.release)

	for range clients {
		if err := <-errs; err != nil {
			t.Errorf("concurrent Sign() failed: %v", err)
		}
	}
	if got := up.listCalls.Load(); got != 1 {
		t.Errorf("upstream List() calls = %d, want 1", got)
	}
}

func TestFilterAgentRecoversAfterListFailure(t *testing.T) {
	keyring, ok := agent.NewKeyring().(agent.ExtendedAgent)
	if !ok {
		t.Fatal("agent.NewKeyring does not implement agent.ExtendedAgent")
	}
	pub := addAgentKey(t, keyring, "allowed")
	up := &toggleListAgent{ExtendedAgent: keyring}
	up.fail.Store(true)
	matcher, err := keys.NewMatcher("comment", "allowed")
	if err != nil {
		t.Fatal(err)
	}
	fa := &filterAgent{
		up:            up,
		authorization: newGroupAuthorization([]keys.Matcher{matcher}),
		group:         "recover",
		log:           slog.New(slog.DiscardHandler),
	}

	if _, err := fa.List(); err == nil {
		t.Fatal("List() error = nil while upstream is locked")
	}
	up.fail.Store(false)
	assertListedKeys(t, fa, pub)
	assertSigns(t, fa, pub)

	// A failed later refresh must not clear the last successful immutable
	// snapshot used by concurrent signing requests.
	up.fail.Store(true)
	if _, err := fa.List(); err == nil {
		t.Fatal("List() error = nil after locking upstream again")
	}
	assertSigns(t, fa, pub)
}

type blockingListAgent struct {
	agent.ExtendedAgent
	listCalls atomic.Int64
	started   chan struct{}
	release   chan struct{}
	startOnce sync.Once
}

type toggleListAgent struct {
	agent.ExtendedAgent
	fail atomic.Bool
}

func (a *toggleListAgent) List() ([]*agent.Key, error) {
	if a.fail.Load() {
		return nil, errors.New("test agent is locked")
	}
	return a.ExtendedAgent.List()
}

func (a *blockingListAgent) List() ([]*agent.Key, error) {
	a.listCalls.Add(1)
	a.startOnce.Do(func() { close(a.started) })
	<-a.release
	return a.ExtendedAgent.List()
}

func addAgentKey(t *testing.T, up agent.ExtendedAgent, comment string) ssh.PublicKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := up.Add(agent.AddedKey{PrivateKey: privateKey, Comment: comment}); err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(privateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func assertListedKeys(t *testing.T, fa *filterAgent, want ...ssh.PublicKey) {
	t.Helper()
	listed, err := fa.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != len(want) {
		t.Fatalf("List() returned %d keys, want %d", len(listed), len(want))
	}
	for i := range want {
		if string(listed[i].Marshal()) != string(want[i].Marshal()) {
			t.Errorf("List() key %d = %s, want %s", i, ssh.FingerprintSHA256(listed[i]), ssh.FingerprintSHA256(want[i]))
		}
	}
}

func assertSigns(t *testing.T, fa *filterAgent, key ssh.PublicKey) {
	t.Helper()
	if _, err := fa.Sign(key, []byte("sign me")); err != nil {
		t.Errorf("Sign(%s) failed: %v", ssh.FingerprintSHA256(key), err)
	}
}

func assertRefusesKey(t *testing.T, fa *filterAgent, key ssh.PublicKey) {
	t.Helper()
	if _, err := fa.Sign(key, []byte("sign me")); !errors.Is(err, errKeyNotInGroup) {
		t.Errorf("Sign(%s) error = %v, want errKeyNotInGroup", ssh.FingerprintSHA256(key), err)
	}
}
