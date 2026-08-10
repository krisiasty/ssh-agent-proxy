package proxy

import (
	"log/slog"
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
	trigger string
	visible []*agent.Key
	err     error
}

// groupAuthorization owns the current authorization view for one group. All
// client connections for that group share it. Concurrent refreshes are
// coalesced so a burst of clients produces one upstream List request.
type groupAuthorization struct {
	group    string
	log      *slog.Logger
	matchers []keys.Matcher
	snapshot atomic.Pointer[authorizationSnapshot]

	mu        sync.Mutex
	inFlight  *authorizationRefresh
	unmatched []bool
}

func newGroupAuthorization(group string, matchers []keys.Matcher, log *slog.Logger) *groupAuthorization {
	return &groupAuthorization{
		group:    group,
		log:      log,
		matchers: append([]keys.Matcher(nil), matchers...),
	}
}

func (a *groupAuthorization) allows(key ssh.PublicKey) bool {
	snapshot := a.snapshot.Load()
	return snapshot != nil && snapshot.allowSet.Allowed(key)
}

// list refreshes the group from upstream and returns the exact filtered view
// used to publish the new signing allow-set.
func (a *groupAuthorization) list(up agent.ExtendedAgent) ([]*agent.Key, error) {
	refresh, owner := a.joinRefresh("client-list")
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
	refresh, owner := a.joinRefreshLocked("sign-miss")
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

func (a *groupAuthorization) joinRefresh(trigger string) (*authorizationRefresh, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.joinRefreshLocked(trigger)
}

func (a *groupAuthorization) joinRefreshLocked(trigger string) (*authorizationRefresh, bool) {
	if a.inFlight != nil {
		return a.inFlight, false
	}
	refresh := &authorizationRefresh{done: make(chan struct{}), trigger: trigger}
	a.inFlight = refresh
	return refresh, true
}

func (a *groupAuthorization) runRefresh(up agent.ExtendedAgent, refresh *authorizationRefresh) {
	all, err := up.List()
	var visible []*agent.Key
	if err == nil {
		visible = a.resolve(all, refresh.trigger)
	} else {
		a.log.Debug("config key resolution failed",
			"group", a.group,
			"trigger", refresh.trigger,
			"configured_keys", len(a.matchers),
			"err", err)
	}

	a.mu.Lock()
	refresh.visible = visible
	refresh.err = err
	a.inFlight = nil
	close(refresh.done)
	a.mu.Unlock()
}

func (a *groupAuthorization) resolve(upstream []*agent.Key, trigger string) []*agent.Key {
	visible, matchCounts := keys.Resolve(upstream, a.matchers)
	a.snapshot.Store(&authorizationSnapshot{
		allowSet: keys.NewAllowSet(visible),
	})
	a.logResolution(upstream, visible, matchCounts, trigger)
	return visible
}

func (a *groupAuthorization) logResolution(upstream, visible []*agent.Key, matchCounts []int, trigger string) {
	for _, index := range a.newlyUnmatched(matchCounts) {
		a.log.Warn("configured key selector matched no upstream key",
			"group", a.group,
			"config_index", index+1,
			"selector_type", a.matchers[index].Type)
	}
	a.log.Debug("config keys resolved",
		"group", a.group,
		"trigger", trigger,
		"configured_keys", len(a.matchers),
		"upstream_keys", len(upstream),
		"resolved_keys", len(visible))
}

// newlyUnmatched returns selectors that became unmatched in this resolution.
// State is guarded by the refresh mutex so repeated client lists do not flood
// logs, while a selector that recovers and later disappears is warned again.
func (a *groupAuthorization) newlyUnmatched(matchCounts []int) []int {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.unmatched) != len(matchCounts) {
		a.unmatched = make([]bool, len(matchCounts))
	}
	var newly []int
	for i, count := range matchCounts {
		missing := count == 0
		if missing && !a.unmatched[i] {
			newly = append(newly, i)
		}
		a.unmatched[i] = missing
	}
	return newly
}
