package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// makeKey builds an agent.Key with the given comment from a fresh ed25519 key.
func makeKey(t *testing.T, comment string) *agent.Key {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return &agent.Key{Format: sshPub.Type(), Blob: sshPub.Marshal(), Comment: comment}
}

func TestNewMatcherNormalization(t *testing.T) {
	tests := []struct {
		typ, value, want string
		wantErr          bool
	}{
		{"comment", "laptop@work", "laptop@work", false},
		{"md5", "MD5:AA:BB", "aa:bb", false},
		{"md5", "aa:bb", "aa:bb", false},
		{"sha256", "abc123", "SHA256:abc123", false},
		{"sha256", "SHA256:abc123", "SHA256:abc123", false},
		{"comment", "", "", true},
		{"bogus", "x", "", true},
	}
	for _, tc := range tests {
		m, err := NewMatcher(tc.typ, tc.value)
		if tc.wantErr {
			if err == nil {
				t.Errorf("NewMatcher(%q,%q): expected error", tc.typ, tc.value)
			}
			continue
		}
		if err != nil {
			t.Errorf("NewMatcher(%q,%q): %v", tc.typ, tc.value, err)
			continue
		}
		if m.value != tc.want {
			t.Errorf("NewMatcher(%q,%q) value = %q, want %q", tc.typ, tc.value, m.value, tc.want)
		}
	}
}

func TestMatchByFingerprint(t *testing.T) {
	k := makeKey(t, "keyA")

	md5m := mustMatcher(t, "md5", ssh.FingerprintLegacyMD5(k))
	if !md5m.Matches(k) {
		t.Error("md5 matcher should match its own key")
	}
	sha := ssh.FingerprintSHA256(k)
	shaMWithPrefix := mustMatcher(t, "sha256", sha)
	if !shaMWithPrefix.Matches(k) {
		t.Error("sha256 matcher (with prefix) should match")
	}
	shaMBare := mustMatcher(t, "sha256", sha[len("SHA256:"):])
	if !shaMBare.Matches(k) {
		t.Error("sha256 matcher (bare base64) should match")
	}
	commentM := mustMatcher(t, "comment", "keyA")
	if !commentM.Matches(k) {
		t.Error("comment matcher should match")
	}
	if wrong := mustMatcher(t, "comment", "KEYA"); wrong.Matches(k) {
		t.Error("comment match must be case-sensitive")
	}
}

func TestFilterOrderAndDedup(t *testing.T) {
	a := makeKey(t, "alpha")
	b := makeKey(t, "beta")
	c := makeKey(t, "gamma")
	upstream := []*agent.Key{a, b, c}

	// Order follows matcher order, not upstream order.
	mBeta := mustMatcher(t, "comment", "beta")
	mAlpha := mustMatcher(t, "comment", "alpha")
	got := Filter(upstream, []Matcher{mBeta, mAlpha})
	if len(got) != 2 || got[0].Comment != "beta" || got[1].Comment != "alpha" {
		t.Fatalf("got %v, want [beta alpha]", comments(got))
	}

	// A key matched twice appears once, at its first position.
	mBetaFp := mustMatcher(t, "sha256", ssh.FingerprintSHA256(b))
	got = Filter(upstream, []Matcher{mBeta, mBetaFp})
	if len(got) != 1 {
		t.Fatalf("dedup failed: got %v", comments(got))
	}

	// No matchers => nothing.
	if got := Filter(upstream, nil); len(got) != 0 {
		t.Fatalf("expected empty, got %v", comments(got))
	}
}

func TestResolveReportsPerMatcherCountsBeforeDeduplication(t *testing.T) {
	first := makeKey(t, "shared")
	second := makeKey(t, "shared")
	upstream := []*agent.Key{first, second}
	matchers := []Matcher{
		mustMatcher(t, "comment", "shared"),
		mustMatcher(t, "sha256", ssh.FingerprintSHA256(first)),
		mustMatcher(t, "comment", "missing"),
	}

	resolved, matchCounts := Resolve(upstream, matchers)
	if len(resolved) != 2 || resolved[0] != first || resolved[1] != second {
		t.Errorf("Resolve() keys = %v, want [first second] in upstream order", comments(resolved))
	}
	wantCounts := []int{2, 1, 0}
	if len(matchCounts) != len(wantCounts) {
		t.Fatalf("Resolve() match counts = %v, want %v", matchCounts, wantCounts)
	}
	for i := range wantCounts {
		if matchCounts[i] != wantCounts[i] {
			t.Errorf("Resolve() match count %d = %d, want %d", i, matchCounts[i], wantCounts[i])
		}
	}
}

func mustMatcher(t *testing.T, typ, value string) Matcher {
	t.Helper()
	m, err := NewMatcher(typ, value)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func comments(ks []*agent.Key) []string {
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = k.Comment
	}
	return out
}
