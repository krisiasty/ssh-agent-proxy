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

	"github.com/krisiasty/ssh-agent-proxy/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

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

	var listeners []net.Listener
	for i := range groups {
		g := groups[i]
		if !g.IsEnabled() {
			s.log.Info("group disabled, skipping", "group", g.Name)
			continue
		}
		ln, err := s.listen(g.Socket)
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return fmt.Errorf("group %q socket %q: %w", g.Name, g.Socket, err)
		}
		listeners = append(listeners, ln)
		s.log.Info("serving group", "group", g.Name, "socket", g.Socket, "keys", len(g.Keys))
		go s.acceptLoop(ln, g)
	}

	<-ctx.Done()
	s.log.Info("shutting down")
	for _, ln := range listeners {
		ln.Close() // UnixListener unlinks the socket file on close
	}
	return nil
}

// listen creates the group's parent dir, replaces any stale socket, binds it
// and restricts it to the owner (0600).
func (s *Server) listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// Remove a stale socket left by a previous run or crash.
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func (s *Server) acceptLoop(ln net.Listener, g config.Group) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed during shutdown
		}
		go s.serveConn(conn, g)
	}
}

// serveConn dials the upstream agent and serves one client with a filtered view.
func (s *Server) serveConn(client net.Conn, g config.Group) {
	defer client.Close()

	up, err := net.Dial("unix", s.upstream)
	if err != nil {
		s.log.Warn("upstream agent unreachable", "group", g.Name, "upstream", s.upstream, "err", err)
		return
	}
	defer up.Close()

	fa := &filterAgent{
		up:       agent.NewClient(up),
		matchers: g.Matchers(),
		group:    g.Name,
		log:      s.log,
	}
	if err := agent.ServeAgent(fa, client); err != nil && err != io.EOF {
		s.log.Debug("client connection ended", "socket", g.Socket, "err", err)
	}
}

// ListUpstream connects to the upstream agent and writes each key as
// ready-to-paste config entries.
func ListUpstream(upstream string, w io.Writer) error {
	conn, err := net.Dial("unix", upstream)
	if err != nil {
		return fmt.Errorf("connecting to upstream agent %q: %w", upstream, err)
	}
	defer conn.Close()

	ks, err := agent.NewClient(conn).List()
	if err != nil {
		return fmt.Errorf("listing upstream keys: %w", err)
	}
	if len(ks) == 0 {
		fmt.Fprintln(w, "upstream agent has no keys")
		return nil
	}

	for i, k := range ks {
		if bits := keyBits(k.Blob); bits > 0 {
			fmt.Fprintf(w, "[%d] %s %d\n", i+1, k.Format, bits)
		} else {
			fmt.Fprintf(w, "[%d] %s\n", i+1, k.Format)
		}
		if k.Comment != "" {
			fmt.Fprintf(w, "  - type: comment\n    value: %s\n", k.Comment)
		}
		fmt.Fprintf(w, "  - type: sha256\n    value: %s\n", ssh.FingerprintSHA256(k))
		fmt.Fprintf(w, "  - type: md5\n    value: MD5:%s\n", ssh.FingerprintLegacyMD5(k))
	}
	return nil
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
