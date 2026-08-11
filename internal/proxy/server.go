package proxy

import (
	"context"
	"crypto/dsa" //nolint:staticcheck // DSA is inspected only to report the size of legacy upstream public keys.
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/krisiasty/ssh-agent-proxy/internal/config"
	"github.com/krisiasty/ssh-agent-proxy/internal/peercreds"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	// dialTimeout bounds how long connecting to the upstream agent may take.
	dialTimeout = 10 * time.Second
	// socketProbeTimeout bounds the live-owner check before a stale socket is
	// removed. A timeout is ambiguous and therefore treated as a live owner.
	socketProbeTimeout = time.Second
	// acceptRetryInitial and acceptRetryMax bound retries for temporary listener
	// failures such as process or system file-descriptor exhaustion.
	acceptRetryInitial = 5 * time.Millisecond
	acceptRetryMax     = time.Second
)

var dialer net.Dialer

// ErrListenerFailure identifies a terminal group listener failure. Managed
// service runtimes should exit so their supervisor can restart the process.
var ErrListenerFailure = errors.New("terminal listener failure")

// Server exposes one filtered agent socket per configured group.
type Server struct {
	upstream          string
	cacheTTL          time.Duration
	log               *slog.Logger
	newUpstreamClient func(context.Context, string, *slog.Logger) (*reconnectClient, error)
	listen            func(context.Context, string) (net.Listener, error)
	onReady           func()
	telemetry         *proxyTelemetry
}

// nextConnID returns a random 8-character hex string for log correlation.
func (s *Server) nextConnID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		s.log.Warn("generating connection ID", "err", err)
		return "unavailable"
	}
	return hex.EncodeToString(b)
}

// NewServer returns a Server that forwards to the upstream agent socket.
func NewServer(ctx context.Context, upstream string, cacheTTL time.Duration, log *slog.Logger) *Server {
	s := &Server{upstream: upstream, cacheTTL: cacheTTL, log: log, telemetry: newProxyTelemetry(ctx, log)}
	s.newUpstreamClient = func(ctx context.Context, upstream string, log *slog.Logger) (*reconnectClient, error) {
		return newReconnectClientWithTelemetry(ctx, upstream, log, s.telemetry)
	}
	s.listen = s.listenUnix
	return s
}

// LogTelemetry emits and resets the current application telemetry interval.
func (s *Server) LogTelemetry() {
	s.telemetry.logReport()
}

// SetReadyCallback configures a function called synchronously after all
// enabled group sockets are serving, or after Run determines that no groups
// are enabled. It must be called before Run.
func (s *Server) SetReadyCallback(callback func()) {
	s.onReady = callback
}

// Run binds every group socket and serves connections until ctx is cancelled,
// then removes the sockets. Run returns nil on clean shutdown.
func (s *Server) Run(ctx context.Context, groups []config.Group) (runErr error) {
	enabledGroups := make([]config.Group, 0, len(groups))
	for _, g := range groups {
		if !g.IsEnabled() {
			s.log.Info("group disabled, skipping", "group", g.Name)
			continue
		}
		enabledGroups = append(enabledGroups, g)
	}
	if len(enabledGroups) == 0 {
		s.log.Info("no enabled groups; exposing nothing", "upstream", s.upstream)
		if s.onReady != nil {
			s.onReady()
		}
		<-ctx.Done()
		return nil
	}

	socketPaths := make([]string, 0, len(enabledGroups))
	for _, g := range enabledGroups {
		socketPaths = append(socketPaths, g.Socket)
	}
	locks, err := acquireSocketLocks(socketPaths)
	if err != nil {
		return fmt.Errorf("acquiring group socket locks: %w", err)
	}
	defer func() {
		if err := closeSocketLocks(locks); err != nil {
			s.log.Warn("releasing group socket locks", "err", err)
			runErr = errors.Join(runErr, fmt.Errorf("releasing group socket locks: %w", err))
		}
	}()

	// Open a single shared connection to the upstream agent. All proxy clients
	// funnel through it — this avoids overwhelming agents (e.g. Bitwarden) that
	// cannot handle many concurrent connections. agent.NewClient pipelines
	// requests with a 32-slot FIFO queue, so writes are serialized on the wire.
	// The reconnecting wrapper will dial a fresh connection if the current one
	// dies, so a single failure does not kill all clients.
	rc, err := s.newUpstreamClient(ctx, s.upstream, s.log)
	if err != nil {
		return err
	}
	if rc.telemetry == nil {
		rc.telemetry = s.telemetry
	}
	defer func() {
		if err := rc.Close(ctx); err != nil && !errors.Is(err, net.ErrClosed) {
			s.log.Warn("closing upstream connection", "err", err)
			runErr = errors.Join(runErr, fmt.Errorf("closing upstream connection: %w", err))
		}
	}()
	upstream := newCachedAgent(rc, s.cacheTTL, s.log, s.telemetry)

	// Create one shared authorization state per group. A successful initial list
	// seeds every group from the same upstream snapshot; later requests refresh
	// the snapshots so a locked or empty agent can recover without a restart.
	type enrichedGroup struct {
		g             config.Group
		authorization *groupAuthorization
		resolvedKeys  int
		resolved      bool
	}
	egs := make([]enrichedGroup, 0, len(enabledGroups))
	for _, g := range enabledGroups {
		egs = append(egs, enrichedGroup{
			g:             g,
			authorization: newGroupAuthorization(g.Name, g.Matchers(), s.log),
		})
	}
	allKeys, err := upstream.List()
	if err != nil {
		s.log.Warn("initial config key resolution failed; deferring until client request", "err", err)
	} else {
		for i := range egs {
			egs[i].resolvedKeys = len(egs[i].authorization.resolve(allKeys, "startup"))
			egs[i].resolved = true
		}
	}

	var listeners []net.Listener
	acceptFailures := make(chan error, len(egs))
	for _, eg := range egs {
		g := eg.g
		ln, err := s.listen(ctx, g.Socket)
		if err != nil {
			listenErr := fmt.Errorf("group %q socket %q: %w", g.Name, g.Socket, err)
			return errors.Join(listenErr, s.closeListeners(listeners))
		}
		listeners = append(listeners, ln)
		logAttrs := []any{"group", g.Name, "socket", g.Socket}
		if eg.resolved {
			logAttrs = append(logAttrs, "keys", eg.resolvedKeys)
		}
		s.log.Info("serving group", logAttrs...)
		go func() {
			if err := s.acceptLoop(ctx, ln, g, eg.authorization, upstream); err != nil {
				acceptFailures <- err
			}
		}()
	}
	if s.onReady != nil {
		s.onReady()
	}

	select {
	case <-ctx.Done():
		s.log.Info("shutting down")
		return s.closeListeners(listeners)
	case err := <-acceptFailures:
		return errors.Join(err, s.closeListeners(listeners))
	}
}

func (s *Server) closeListeners(listeners []net.Listener) error {
	var closeErr error
	for _, ln := range listeners {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.log.Warn("closing group listener", "address", ln.Addr(), "err", err)
			closeErr = errors.Join(closeErr, fmt.Errorf("closing listener %q: %w", ln.Addr(), err))
		}
	}
	return closeErr
}

// listen creates the group's parent dir, verifies an existing socket is stale,
// binds the path, and restricts it to the owner (0600).
func (s *Server) listenUnix(ctx context.Context, path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating socket directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("socket path exists and is not a Unix socket")
		}
		if err := removeStaleSocket(ctx, path, info); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspecting socket path: %w", err)
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("binding Unix socket: %w", err)
	}
	unixListener, ok := ln.(*net.UnixListener)
	if !ok {
		if closeErr := ln.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			return nil, errors.Join(
				fmt.Errorf("listener for %q is %T, want *net.UnixListener", path, ln),
				fmt.Errorf("closing unexpected listener: %w", closeErr),
			)
		}
		return nil, fmt.Errorf("listener for %q is %T, want *net.UnixListener", path, ln)
	}
	unixListener.SetUnlinkOnClose(false)
	identity, err := os.Lstat(path)
	if err != nil {
		if closeErr := unixListener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			return nil, errors.Join(
				fmt.Errorf("inspecting newly bound socket: %w", err),
				fmt.Errorf("closing listener after inspection failure: %w", closeErr),
			)
		}
		return nil, fmt.Errorf("inspecting newly bound socket: %w", err)
	}
	owned := &ownedUnixListener{UnixListener: unixListener, path: path, identity: identity}
	if err := os.Chmod(path, 0o600); err != nil {
		if closeErr := owned.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			return nil, errors.Join(err, fmt.Errorf("closing listener after chmod failure: %w", closeErr))
		}
		return nil, fmt.Errorf("restricting socket permissions: %w", err)
	}
	return owned, nil
}

func removeStaleSocket(ctx context.Context, path string, original os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("probing existing socket: %w", err)
	}
	probeCtx, cancel := context.WithTimeout(ctx, socketProbeTimeout)
	defer cancel()

	conn, err := dialer.DialContext(probeCtx, "unix", path)
	if err == nil {
		inUseErr := fmt.Errorf("%w: %q accepted a connection", ErrSocketInUse, path)
		if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			return errors.Join(inUseErr, fmt.Errorf("closing socket probe connection: %w", closeErr))
		}
		return inUseErr
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("probing existing socket: %w", ctxErr)
	}
	if probeErr := probeCtx.Err(); probeErr != nil {
		return errors.Join(
			fmt.Errorf("%w: probe was inconclusive", ErrSocketInUse),
			fmt.Errorf("socket probe: %w", probeErr),
		)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, os.ErrNotExist) {
		return errors.Join(
			fmt.Errorf("%w: probe failed without proving staleness", ErrSocketInUse),
			fmt.Errorf("socket probe: %w", err),
		)
	}

	current, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("rechecking stale socket: %w", err)
	}
	if !os.SameFile(original, current) {
		return fmt.Errorf("%w: socket changed while it was being probed", ErrSocketInUse)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing stale socket: %w", err)
	}
	return nil
}

type temporaryAcceptError interface {
	Temporary() bool
}

func (s *Server) acceptLoop(ctx context.Context, ln net.Listener, g config.Group, authorization *groupAuthorization, upClient agent.ExtendedAgent) error {
	var retryDelay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				//nolint:nilerr // Listener closure is the successful shutdown signal.
				return nil
			}

			var temporary temporaryAcceptError
			if errors.As(err, &temporary) && temporary.Temporary() {
				if retryDelay == 0 {
					retryDelay = acceptRetryInitial
				} else {
					retryDelay = min(retryDelay*2, acceptRetryMax)
				}
				s.log.Warn("temporary listener accept failure; retrying",
					"group", g.Name,
					"socket", g.Socket,
					"retry_in", retryDelay.String(),
					"err", err)
				if !waitForAcceptRetry(ctx, retryDelay) {
					return nil
				}
				continue
			}

			s.log.Error("listener accept failure",
				"group", g.Name,
				"socket", g.Socket,
				"err", err)
			return fmt.Errorf("%w: group %q socket %q: %w", ErrListenerFailure, g.Name, g.Socket, err)
		}
		retryDelay = 0
		go s.serveConn(ctx, conn, g, authorization, upClient)
	}
}

func waitForAcceptRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	select {
	case <-ctx.Done():
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		return false
	case <-timer.C:
		return true
	}
}

// serveConn handles one client with a filtered view over the shared upstream
// connection. No per-client dial is needed.
func (s *Server) serveConn(ctx context.Context, client net.Conn, g config.Group, authorization *groupAuthorization, upClient agent.ExtendedAgent) {
	s.telemetry.clientConnected()
	defer s.telemetry.clientDisconnected()

	id := s.nextConnID()
	identityLog := s.log.With("conn", id, "group", g.Name)
	log := identityLog
	defer func() {
		if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Debug("closing client connection", "err", err)
		}
	}()

	// Try to read peer credentials from the Unix socket.
	// On Linux this gives PID+UID+process name; on macOS, PID+UID+process name.
	peer, err := peercreds.Get(ctx, client)
	if err != nil {
		log.Info("failed to read peer credentials", "err", err)
	}
	if peer.UID != 0 {
		log = log.With("uid", peer.UID)
	}
	if peer.PID != 0 {
		log = log.With("pid", peer.PID)
	}
	if peer.Process != "" {
		log = log.With("process", peer.Process)
	}
	log.Info("client connected")

	fa := &filterAgent{
		up:            upClient,
		authorization: authorization,
		group:         g.Name,
		log:           log,
		identityLog:   identityLog,
		telemetry:     s.telemetry,
	}
	if err := agent.ServeAgent(fa, client); err != nil && !errors.Is(err, io.EOF) {
		if s.telemetry != nil {
			s.telemetry.clientErrors.Add(1)
		}
		log.Debug("client connection ended", "err", err)
	}
	log.Info("client disconnected")
}

// ListUpstream connects to the upstream agent and writes each key as
// ready-to-paste config entries.
func ListUpstream(upstream string, w io.Writer) (retErr error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	ks, err := ListAgentKeys(ctx, upstream)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, formatKeys(ks))
	return err
}

// ListAgentKeys connects to an SSH agent socket and returns its identities.
// The context bounds both connecting and the agent request.
func ListAgentKeys(ctx context.Context, socket string) (ks []*agent.Key, retErr error) {
	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("connecting to agent %q: %w", socket, err)
	}
	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			retErr = errors.Join(retErr, fmt.Errorf("closing agent connection: %w", err))
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("setting agent connection deadline: %w", err)
		}
	}

	ks, err = agent.NewClient(conn).List()
	if err != nil {
		return nil, fmt.Errorf("listing agent keys: %w", err)
	}
	return ks, nil
}

// formatKeys renders the upstream keys as commented config entries.
func formatKeys(ks []*agent.Key) string {
	if len(ks) == 0 {
		return "upstream agent has no keys\n"
	}
	var lines []string
	for i, k := range ks {
		if bits := keyBits(k.Blob); bits > 0 {
			lines = append(lines, fmt.Sprintf("[%d] %s %d\n", i+1, k.Format, bits))
		} else {
			lines = append(lines, fmt.Sprintf("[%d] %s\n", i+1, k.Format))
		}
		if k.Comment != "" {
			lines = append(lines, fmt.Sprintf("  - comment: %s\n", strconv.Quote(k.Comment)))
		}
		lines = append(lines, fmt.Sprintf("  - sha256: %s\n", strconv.Quote(ssh.FingerprintSHA256(k))))
		lines = append(lines, fmt.Sprintf("  - md5: %s\n", strconv.Quote("MD5:"+ssh.FingerprintLegacyMD5(k))))
	}
	return strings.Join(lines, "")
}

// keyBits returns the key size in bits for the given public-key blob, or 0 if
// it cannot be determined.
func keyBits(blob []byte) int {
	pk, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return 0
	}
	if certificate, ok := pk.(*ssh.Certificate); ok {
		pk = certificate.Key
	}
	cpk, ok := pk.(ssh.CryptoPublicKey)
	if !ok {
		return 0
	}
	switch key := cpk.CryptoPublicKey().(type) {
	case *dsa.PublicKey:
		return key.P.BitLen()
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return len(key) * 8
	default:
		return 0
	}
}
