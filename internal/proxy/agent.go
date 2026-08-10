package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// errReadOnly is returned for every mutating request; the proxy is read-only.
var errReadOnly = errors.New("ssh-agent-proxy: read-only agent, request refused")

var errKeyNotInGroup = errors.New("ssh-agent-proxy: key not in group")

// filterAgent is an agent.ExtendedAgent that exposes only the keys of a single
// group and forwards list/sign to the upstream agent. It is created per client
// connection and bound to one upstream connection.
type filterAgent struct {
	up            agent.ExtendedAgent
	authorization *groupAuthorization
	group         string
	log           *slog.Logger
	identityLog   *slog.Logger
	telemetry     *proxyTelemetry
}

// List returns only the keys assigned to this group.
func (f *filterAgent) List() ([]*agent.Key, error) {
	if f.telemetry != nil {
		f.telemetry.listRequests.Add(1)
	}
	ks, err := f.authorization.list(f.up)
	if err != nil {
		if f.telemetry != nil {
			f.telemetry.listErrors.Add(1)
		}
		f.log.Warn("upstream list failed", "group", f.group, "err", err)
		return nil, err
	}
	f.log.Info("list identities", "count", len(ks))
	identityLog := f.identityLog
	if identityLog == nil {
		identityLog = f.log
	}
	if identityLog.Enabled(context.Background(), slog.LevelDebug) {
		for i, key := range ks {
			identityLog.Debug(fmt.Sprintf("group identity %d/%d", i+1, len(ks)),
				"fingerprint", ssh.FingerprintSHA256(key),
				"comment", key.Comment,
				"algorithm", key.Format,
				"key_size", keyBits(key.Blob))
		}
	}
	return ks, nil
}

// SignWithFlags signs with key only if it belongs to this group.
func (f *filterAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if f.telemetry != nil {
		f.telemetry.signRequests.Add(1)
	}
	allowed, err := f.authorization.authorize(f.up, key)
	if err != nil {
		if f.telemetry != nil {
			f.telemetry.signErrors.Add(1)
		}
		f.log.Warn("upstream list failed during sign authorization", "group", f.group, "err", err)
		return nil, err
	}
	if !allowed {
		if f.telemetry != nil {
			f.telemetry.signErrors.Add(1)
		}
		f.log.Warn("sign refused: key not in group",
			"group", f.group, "fingerprint", ssh.FingerprintSHA256(key))
		return nil, errKeyNotInGroup
	}
	f.log.Info("sign", "fingerprint", ssh.FingerprintSHA256(key))
	sig, err := f.up.SignWithFlags(key, data, flags)
	if err != nil && f.telemetry != nil {
		f.telemetry.signErrors.Add(1)
	}
	return sig, err
}

// Sign signs with key only if it belongs to this group.
func (f *filterAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return f.SignWithFlags(key, data, 0)
}

// Mutating operations are all refused: the proxy never modifies upstream state.
func (f *filterAgent) Add(agent.AddedKey) error   { return f.refuse("add") }
func (f *filterAgent) Remove(ssh.PublicKey) error { return f.refuse("remove") }
func (f *filterAgent) RemoveAll() error           { return f.refuse("remove-all") }
func (f *filterAgent) Lock([]byte) error          { return f.refuse("lock") }
func (f *filterAgent) Unlock([]byte) error        { return f.refuse("unlock") }

func (f *filterAgent) refuse(op string) error {
	f.log.Warn("refused mutating request", "group", f.group, "op", op)
	return errReadOnly
}

// Signers is unused by the socket server; refuse it for safety.
func (f *filterAgent) Signers() ([]ssh.Signer, error) { return nil, errReadOnly }

// Extension declines all agent extensions.
func (f *filterAgent) Extension(_ string, _ []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
