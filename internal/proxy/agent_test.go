package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"testing"

	"github.com/krisiasty/ssh-agent-proxy/internal/keys"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestFilterAgentEnforcement(t *testing.T) {
	// Build ed25519 keys directly so we keep the private key for keyring.Add.
	_, privAllowed, _ := ed25519.GenerateKey(rand.Reader)
	_, privHidden, _ := ed25519.GenerateKey(rand.Reader)

	up := agent.NewKeyring().(agent.ExtendedAgent)
	if err := up.Add(agent.AddedKey{PrivateKey: privAllowed, Comment: "allowed"}); err != nil {
		t.Fatal(err)
	}
	if err := up.Add(agent.AddedKey{PrivateKey: privHidden, Comment: "hidden"}); err != nil {
		t.Fatal(err)
	}

	// Build the allow set from the upstream key list (simulates config resolution).
	allowedKeys, err := up.List()
	if err != nil {
		t.Fatal(err)
	}
	m, _ := keys.NewMatcher("comment", "allowed")
	allowSet := keys.BuildAllowSet(allowedKeys, []keys.Matcher{m})

	fa := &filterAgent{
		up:       up,
		matchers: []keys.Matcher{m},
		allowSet: allowSet,
		group:    "test",
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	// List exposes only the allowed key.
	list, err := fa.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Comment != "allowed" {
		t.Fatalf("List = %d keys, want 1 (allowed)", len(list))
	}

	allowedPub, _ := ssh.NewPublicKey(privAllowed.Public())
	hiddenPub, _ := ssh.NewPublicKey(privHidden.Public())
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
	if _, err := fa.Extension("query", nil); err != agent.ErrExtensionUnsupported {
		t.Errorf("Extension err = %v, want ErrExtensionUnsupported", err)
	}

	// Upstream is untouched: still holds both keys.
	if all, _ := up.List(); len(all) != 2 {
		t.Errorf("upstream now has %d keys, want 2 (proxy must not mutate)", len(all))
	}
}