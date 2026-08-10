package proxy

import (
	"log/slog"
	"sync"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

// cachedAgent shares one upstream identity cache across every group and client.
// Only List is cached; all other agent operations are forwarded unchanged.
type cachedAgent struct {
	agent.ExtendedAgent
	ttl       time.Duration
	log       *slog.Logger
	now       func() time.Time
	telemetry *proxyTelemetry

	mu          sync.Mutex
	keys        []*agent.Key
	hasSnapshot bool
	cachedErr   error
	expiresAt   time.Time
	inFlight    chan struct{}
}

var _ agent.ExtendedAgent = (*cachedAgent)(nil)

func newCachedAgent(upstream agent.ExtendedAgent, ttl time.Duration, log *slog.Logger, telemetry *proxyTelemetry) *cachedAgent {
	return &cachedAgent{
		ExtendedAgent: upstream,
		ttl:           ttl,
		log:           log,
		now:           time.Now,
		telemetry:     telemetry,
	}
}

func (a *cachedAgent) List() ([]*agent.Key, error) {
	if a.ttl <= 0 {
		if a.telemetry != nil {
			a.telemetry.cacheMisses.Add(1)
			a.telemetry.cacheRefreshes.Add(1)
		}
		return a.ExtendedAgent.List()
	}

	missed := false
	for {
		a.mu.Lock()
		if a.now().Before(a.expiresAt) {
			keys := cloneAgentKeys(a.keys)
			err := a.cachedErr
			a.mu.Unlock()
			if !missed && a.telemetry != nil {
				a.telemetry.cacheHits.Add(1)
			}
			return keys, err
		}
		if !missed {
			missed = true
			if a.telemetry != nil {
				a.telemetry.cacheMisses.Add(1)
			}
		}
		if a.inFlight != nil {
			done := a.inFlight
			a.mu.Unlock()
			if a.telemetry != nil {
				a.telemetry.cacheWaits.Add(1)
			}
			<-done
			continue
		}
		a.inFlight = make(chan struct{})
		done := a.inFlight
		a.mu.Unlock()
		if a.telemetry != nil {
			a.telemetry.cacheRefreshes.Add(1)
		}

		keys, err := a.ExtendedAgent.List()

		a.mu.Lock()
		stale := false
		switch {
		case err == nil:
			a.keys = cloneAgentKeys(keys)
			a.hasSnapshot = true
			a.cachedErr = nil
		case a.hasSnapshot:
			stale = true
			a.cachedErr = nil
		default:
			a.keys = nil
			a.cachedErr = err
		}
		a.expiresAt = a.now().Add(a.ttl)
		result := cloneAgentKeys(a.keys)
		resultErr := a.cachedErr
		a.inFlight = nil
		close(done)
		a.mu.Unlock()

		if stale {
			a.log.Warn("upstream key refresh failed; using cached keys", "err", err, "keys", len(result))
		}
		return result, resultErr
	}
}

func cloneAgentKeys(keys []*agent.Key) []*agent.Key {
	return append([]*agent.Key(nil), keys...)
}
