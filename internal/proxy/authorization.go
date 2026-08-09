package proxy

import (
	"sync"
	"sync/atomic"

	"github.com/krisiasty/ssh-agent-proxy/internal/keys"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// authorizationSnapshot is immutable after publication. Readers can check it
// without contending with other clients while one goroutine refreshes it.
type authorizationSnapshot struct {
	allowSet keys.AllowSet
}

type authorizationRefresh struct {
	done    chan struct{}
	visible []*agent.Key
	err     error
}

// groupAuthorization owns the current authorization view for one group. All
// client connections for that group share it. Concurrent refreshes are
// coalesced so a burst of clients produces one upstream List request.
type groupAuthorization struct {
	matchers []keys.Matcher
	snapshot atomic.Pointer[authorizationSnapshot]

	mu       sync.Mutex
	inFlight *authorizationRefresh
}

func newGroupAuthorization(matchers []keys.Matcher) *groupAuthorization {
	return &groupAuthorization{matchers: append([]keys.Matcher(nil), matchers...)}
}

func (a *groupAuthorization) allows(key ssh.PublicKey) bool {
	snapshot := a.snapshot.Load()
	return snapshot != nil && snapshot.allowSet.Allowed(key)
}

// list refreshes the group from upstream and returns the exact filtered view
// used to publish the new signing allow-set.
func (a *groupAuthorization) list(up agent.ExtendedAgent) ([]*agent.Key, error) {
	refresh, owner := a.joinRefresh()
	if owner {
		a.runRefresh(up, refresh)
	}
	<-refresh.done
	return refresh.visible, refresh.err
}

// authorize checks the lock-free current snapshot first. A miss refreshes the
// group once, allowing keys added after startup without adding an upstream
// round trip to the normal signing path.
func (a *groupAuthorization) authorize(up agent.ExtendedAgent, key ssh.PublicKey) (bool, error) {
	if a.allows(key) {
		return true, nil
	}

	a.mu.Lock()
	// Recheck while holding the refresh mutex: another client may have
	// published the key between the fast-path load and this lock acquisition.
	if a.allows(key) {
		a.mu.Unlock()
		return true, nil
	}
	refresh, owner := a.joinRefreshLocked()
	a.mu.Unlock()

	if owner {
		a.runRefresh(up, refresh)
	}
	<-refresh.done
	if refresh.err != nil {
		return false, refresh.err
	}
	return a.allows(key), nil
}

func (a *groupAuthorization) joinRefresh() (*authorizationRefresh, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.joinRefreshLocked()
}

func (a *groupAuthorization) joinRefreshLocked() (*authorizationRefresh, bool) {
	if a.inFlight != nil {
		return a.inFlight, false
	}
	refresh := &authorizationRefresh{done: make(chan struct{})}
	a.inFlight = refresh
	return refresh, true
}

func (a *groupAuthorization) runRefresh(up agent.ExtendedAgent, refresh *authorizationRefresh) {
	all, err := up.List()
	var visible []*agent.Key
	if err == nil {
		visible = keys.Filter(all, a.matchers)
		a.snapshot.Store(&authorizationSnapshot{
			allowSet: keys.NewAllowSet(visible),
		})
	}

	a.mu.Lock()
	refresh.visible = visible
	refresh.err = err
	a.inFlight = nil
	close(refresh.done)
	a.mu.Unlock()
}
