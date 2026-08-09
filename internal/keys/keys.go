// Package keys provides SSH public-key fingerprinting and the matching logic
// used to select upstream agent keys for a group.
package keys

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// MatchType identifies how a configured key entry is matched against an
// upstream key.
type MatchType string

const (
	// MatchComment matches on the key's comment (exact, case-sensitive).
	MatchComment MatchType = "comment"
	// MatchMD5 matches on the MD5 fingerprint of the public key blob.
	MatchMD5 MatchType = "md5"
	// MatchSHA256 matches on the SHA256 hash of the public key blob.
	MatchSHA256 MatchType = "sha256"
)

// Matcher selects upstream keys by a single criterion.
type Matcher struct {
	Type  MatchType
	value string // normalized comparison value
}

// Value returns the normalized comparison value used by the matcher.
func (m Matcher) Value() string { return m.value }

// NewMatcher validates and normalizes a match criterion.
func NewMatcher(typ, value string) (Matcher, error) {
	if value == "" {
		return Matcher{}, errors.New("key match value must not be empty")
	}
	switch MatchType(typ) {
	case MatchComment:
		// Comments are matched exactly and case-sensitively.
		return Matcher{Type: MatchComment, value: value}, nil
	case MatchMD5:
		// Accept an optional "MD5:" prefix; compare lowercase colon-hex.
		v := strings.TrimPrefix(value, "MD5:")
		v = strings.TrimPrefix(v, "md5:")
		return Matcher{Type: MatchMD5, value: strings.ToLower(v)}, nil
	case MatchSHA256:
		// Canonicalize to the "SHA256:<base64>" form ssh.FingerprintSHA256 emits.
		// The base64 payload is case-sensitive and must not be altered.
		v := value
		if !strings.HasPrefix(v, "SHA256:") {
			v = "SHA256:" + strings.TrimPrefix(v, "sha256:")
		}
		return Matcher{Type: MatchSHA256, value: v}, nil
	default:
		return Matcher{}, fmt.Errorf("unknown key match type %q (want comment, md5 or sha256)", typ)
	}
}

// Matches reports whether the given upstream key satisfies this matcher.
func (m Matcher) Matches(k *agent.Key) bool {
	switch m.Type {
	case MatchComment:
		return k.Comment == m.value
	case MatchMD5:
		return ssh.FingerprintLegacyMD5(k) == m.value
	case MatchSHA256:
		return ssh.FingerprintSHA256(k) == m.value
	}
	return false
}

// Filter returns the subset of upstream keys matched by matchers, ordered by
// matcher (config order); within a single matcher, matches keep upstream order.
// A key matched by more than one matcher appears once, at its earliest position.
func Filter(upstream []*agent.Key, matchers []Matcher) []*agent.Key {
	var out []*agent.Key
	seen := make(map[string]bool)
	for _, m := range matchers {
		for _, k := range upstream {
			id := string(k.Marshal())
			if seen[id] {
				continue
			}
			if m.Matches(k) {
				out = append(out, k)
				seen[id] = true
			}
		}
	}
	return out
}

// AllowSet is an immutable set of key blobs that are allowed for a group.
// It can be safely shared by concurrent readers after construction.
type AllowSet struct {
	blobs map[string]bool // marshal() → true
}

// BuildAllowSet returns an AllowSet containing every supplied key that matches
// at least one matcher.
func BuildAllowSet(upstream []*agent.Key, matchers []Matcher) AllowSet {
	return NewAllowSet(Filter(upstream, matchers))
}

// NewAllowSet returns an AllowSet containing the supplied keys.
func NewAllowSet(allowedKeys []*agent.Key) AllowSet {
	allowed := make(map[string]bool)
	for _, key := range allowedKeys {
		allowed[string(key.Marshal())] = true
	}
	return AllowSet{blobs: allowed}
}

// Allowed reports whether the given public key blob is in the allow set.
func (s AllowSet) Allowed(pub ssh.PublicKey) bool {
	return s.blobs[string(pub.Marshal())]
}

// Len returns the number of keys in the allow set.
func (s AllowSet) Len() int {
	return len(s.blobs)
}
