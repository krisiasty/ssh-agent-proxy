package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
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

	// Precompute allow sets by connecting to the upstream agent once.
	// This eliminates the per-sign round-trip and the TOCTOU race.
	upConn, err := dialer.DialContext(context.Background(), "unix", s.upstream)
	if err != nil {
		return fmt.Errorf("connecting to upstream agent: %w", err)
	}
	upClient := agent.NewClient(upConn)
	upstreamKeys, err := upClient.List()
	if err != nil {
		_ = upConn.Close()
		return fmt.Errorf("listing upstream keys: %w", err)
	}
	_ = upConn.Close()

	// Enrich each group with its allow set.
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
		go s.acceptLoop(ctx, ln, g, eg.allowSet)
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

func (s *Server) acceptLoop(ctx context.Context, ln net.Listener, g config.Group, allowSet keys.AllowSet) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed during shutdown
		}
		go s.serveConn(ctx, conn, g, allowSet)
	}
}

// serveConn dials the upstream agent and serves one client with a filtered view.
func (s *Server) serveConn(ctx context.Context, client net.Conn, g config.Group, allowSet keys.AllowSet) {
	defer func() { _ = client.Close() }()

	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	up, err := dialer.DialContext(dctx, "unix", s.upstream)
	if err != nil {
		s.log.Warn("upstream agent unreachable", "group", g.Name, "upstream", s.upstream, "err", err)
		return
	}
	defer func() { _ = up.Close() }()

	fa := &filterAgent{
		up:       agent.NewClient(up),
		matchers: g.Matchers(),
		allowSet: allowSet,
		group:    g.Name,
		log:      s.log,
	}
	if err := agent.ServeAgent(fa, client); err != nil && err != io.EOF {
		s.log.Debug("client connection ended", "group", g.Name, "err", err)
	}
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