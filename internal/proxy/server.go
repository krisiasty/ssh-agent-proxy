package proxy

import (
	"context"
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
		ln, err := s.listen(g.Socket)
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return fmt.Errorf("group socket %q: %w", g.Socket, err)
		}
		listeners = append(listeners, ln)
		s.log.Info("serving group", "socket", g.Socket, "keys", len(g.Keys))
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
		s.log.Warn("upstream agent unreachable", "socket", g.Socket, "upstream", s.upstream, "err", err)
		return
	}
	defer up.Close()

	fa := &filterAgent{
		up:       agent.NewClient(up),
		matchers: g.Matchers(),
		group:    g.Socket,
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
		fmt.Fprintln(w, "# upstream agent has no keys")
		return nil
	}

	for i, k := range ks {
		label := k.Comment
		if label == "" {
			label = "(no comment)"
		}
		fmt.Fprintf(w, "# [%d] %s — %s\n", i+1, k.Format, label)
		if k.Comment != "" {
			fmt.Fprintf(w, "    # - {type: comment, value: %s}\n", k.Comment)
		}
		fmt.Fprintf(w, "    # - {type: sha256, value: %s}\n", ssh.FingerprintSHA256(k))
		fmt.Fprintf(w, "    # - {type: md5,    value: MD5:%s}\n", ssh.FingerprintLegacyMD5(k))
	}
	return nil
}
