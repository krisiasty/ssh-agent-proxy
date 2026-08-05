package proxy

import (
	"context"
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
	"time"

	"github.com/krisiasty/ssh-agent-proxy/internal/config"
	"github.com/krisiasty/ssh-agent-proxy/internal/keys"
	"github.com/krisiasty/ssh-agent-proxy/internal/peercreds"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// dialTimeout bounds how long connecting to the upstream agent may take.
const dialTimeout = 10 * time.Second

var dialer net.Dialer

// Server exposes one filtered agent socket per configured group.
type Server struct {
	upstream string
	log      *slog.Logger
}

// nextConnID returns a random 8-character hex string for log correlation.
func (s *Server) nextConnID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// NewServer returns a Server that forwards to the upstream agent socket.
func NewServer(upstream string, log *slog.Logger) *Server {
	return &Server{upstream: upstream, log: log}
}

// Run binds every group socket and serves connections until ctx is cancelled,
// then removes the sockets. Run returns nil on clean shutdown.
func (s *Server) Run(ctx context.Context, groups []config.Group) error {
	if len(groups) == 0 {
		s.log.Info("no groups configured; exposing nothing", "upstream", s.upstream)
	}

	// Open a single shared connection to the upstream agent. All proxy clients
	// funnel through it — this avoids overwhelming agents (e.g. Bitwarden) that
	// cannot handle many concurrent connections. agent.NewClient pipelines
	// requests with a 32-slot FIFO queue, so writes are serialized on the wire.
	// The reconnecting wrapper will dial a fresh connection if the current one
	// dies, so a single failure does not kill all clients.
	rc := newReconnectClient(s.upstream, s.log)

	// Precompute allow sets from the initial upstream key list.
	upstreamKeys, err := rc.List()
	if err != nil {
		return fmt.Errorf("listing upstream keys: %w", err)
	}
	s.log.Debug("upstream keys listed at startup", "keys", len(upstreamKeys))

	// Enrich each group with its precomputed allow set.
	type enrichedGroup struct {
		g        config.Group
		allowSet keys.AllowSet
	}
	egs := make([]enrichedGroup, 0, len(groups))
	for _, g := range groups {
		allowSet := keys.BuildAllowSet(upstreamKeys, g.Matchers())
		egs = append(egs, enrichedGroup{g: g, allowSet: allowSet})
	}

	var listeners []net.Listener
	for _, eg := range egs {
		g := eg.g
		if !g.IsEnabled() {
			s.log.Info("group disabled, skipping", "group", g.Name)
			continue
		}
		ln, err := s.listen(ctx, g.Socket)
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			return fmt.Errorf("group %q socket %q: %w", g.Name, g.Socket, err)
		}
		listeners = append(listeners, ln)
		s.log.Info("serving group", "group", g.Name, "socket", g.Socket, "keys", len(g.Keys))
		go s.acceptLoop(ctx, ln, g, eg.allowSet, rc)
	}

	<-ctx.Done()
	s.log.Info("shutting down")
	for _, ln := range listeners {
		_ = ln.Close() // UnixListener unlinks the socket file on close
	}
	return nil
}

// listen creates the group's parent dir, replaces any stale socket, binds it
// and restricts it to the owner (0600).
func (s *Server) listen(ctx context.Context, path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// Remove a stale socket left by a previous run or crash.
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(path)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

func (s *Server) acceptLoop(ctx context.Context, ln net.Listener, g config.Group, allowSet keys.AllowSet, upClient agent.ExtendedAgent) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed during shutdown
		}
		go s.serveConn(ctx, conn, g, allowSet, upClient)
	}
}

// serveConn handles one client with a filtered view over the shared upstream
// connection. No per-client dial is needed.
func (s *Server) serveConn(_ context.Context, client net.Conn, g config.Group, allowSet keys.AllowSet, upClient agent.ExtendedAgent) {
	defer func() { _ = client.Close() }()

	id := s.nextConnID()
	log := s.log.With("conn", id, "group", g.Name)

	// Try to read peer credentials from the Unix socket.
	// On Linux this gives PID+UID+process name; on macOS, UID only.
	if peer, err := peercreds.Get(client); err == nil {
		log = log.With("uid", peer.UID)
		if peer.PID != 0 {
			log = log.With("pid", peer.PID)
		}
		if peer.Process != "" {
			log = log.With("process", peer.Process)
		}
	}

	log.Info("client connected")

	fa := &filterAgent{
		up:       upClient,
		matchers: g.Matchers(),
		allowSet: allowSet,
		group:    g.Name,
		log:      log,
	}
	if err := agent.ServeAgent(fa, client); err != nil && !errors.Is(err, io.EOF) {
		log.Debug("client connection ended", "err", err)
	}
	log.Info("client disconnected")
}

// ListUpstream connects to the upstream agent and writes each key as
// ready-to-paste config entries.
func ListUpstream(upstream string, w io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "unix", upstream)
	if err != nil {
		return fmt.Errorf("connecting to upstream agent %q: %w", upstream, err)
	}
	defer func() { _ = conn.Close() }()

	ks, err := agent.NewClient(conn).List()
	if err != nil {
		return fmt.Errorf("listing upstream keys: %w", err)
	}
	_, err = io.WriteString(w, formatKeys(ks))
	return err
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
	cpk, ok := pk.(ssh.CryptoPublicKey)
	if !ok {
		return 0
	}
	switch key := cpk.CryptoPublicKey().(type) {
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
