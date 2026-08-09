# Architecture

## Overview

ssh-agent-proxy sits between SSH clients and an upstream SSH agent (e.g.
`ssh-agent`, Bitwarden, KeePassXC). It listens on one or more Unix domain
sockets, each exposing a **filtered view** of the upstream agent's keys —
only those keys assigned to the group's socket are visible and usable.

```
+-----------+     +---------------------+     +-----------------+
| SSH Client| <-> | proxy group socket  | <-> | upstream agent  |
| (group A) |     | (agent-group-a.sock)|     | (Bitwarden, etc)|
+-----------+     +---------------------+     +-----------------+
+-----------+     +---------------------+          ^  ^
| SSH Client| <-> | proxy group socket  | ---------+  |
| (group B) |     | (agent-group-b.sock)| ------------+ |
+-----------+     +---------------------+ ----------------+
                                                     single
                                                     shared
                                                     connection
```

## Package Layout

| Package     | Role                                           |
|-------------|------------------------------------------------|
| `main`      | CLI parsing, flag dispatch, service lifecycle   |
| `app`       | Wires config, logging, and proxy server together |
| `config`    | YAML config loading, validation, absolute-path enforcement |
| `keys`      | Key matching (comment/MD5/SHA256) and allow sets |
| `proxy`     | Socket server, filtering agent, upstream connection |
| `logging`   | slog setup, legacy `log` package redirection   |
| `service`   | Platform service manager (launchd / systemd)   |

## Startup Flow

```
main()
  └─ flag.Parse()
     ├─ -version       → print version, exit
     ├─ -install/-start/-stop/-restart/-uninstall/-status
     │                    → delegate to service.Manager, exit
     ├─ -list           → load config → dial upstream → print keys, exit
     └─ (no action flag)
        └─ app.Run()
           ├─ runtime.GOMAXPROCS(2)  (unless GOMAXPROCS is set)
           ├─ signal.NotifyContext(SIGINT, SIGTERM)
           ├─ config.Load(path)
           │  ├─ parse YAML
           │  ├─ validate upstream/socket paths are absolute
           │  ├─ reject normalized or symlink-equivalent socket conflicts
           │  └─ compile matchers from key entries
           ├─ logging.Setup(debug)
           │  └─ redirect legacy log package → slog logger
           ├─ log version (structured: version, commit, built)
           └─ proxy.Server.Run(ctx, groups)
```

If configuration or proxy startup fails in **foreground** mode, the process exits
non-zero. In **service** mode, it logs the error and idles until stopped — avoiding
a tight restart loop from the service manager. If no groups are enabled, the server
also idles without opening an unnecessary upstream connection.

## Proxy Server

### Socket Ownership

Before connecting to the upstream agent, `Server.Run` acquires nonblocking file locks
for all enabled group sockets in sorted path order. Holding every lock for the server's
lifetime prevents two proxy instances from racing to own the same endpoint. Lock files
remain on disk so later processes always lock the same inode.

When a socket path already exists, startup connects to it before considering removal.
A successful connection, timeout, or ambiguous error is treated as a live owner and
leaves the path untouched. Only a refused connection proves the socket stale. The
socket inode is checked again before removal to detect replacement during the probe.

Each bound listener records its socket inode and disables the standard library's
unconditional unlink-on-close behavior. Shutdown removes the path only if it still
identifies that inode, preserving any listener that replaced it in the meantime.

### Shared Upstream Connection

At startup, `Server.Run` opens a **single** Unix domain socket connection
to the upstream agent. All proxy clients share this one connection.

Why: upstream agents (particularly password managers like Bitwarden) often
cannot handle many concurrent connections. Under burst load (dozens of SSH
clients connecting simultaneously), per-client dials overwhelm the upstream,
causing corrupted responses, empty key lists, and sign failures.

`agent.NewClient` wraps the socket in a **pipeline** — a 32-slot FIFO queue
with a background reader goroutine. Requests are written to the wire as soon
as the pipe is available; responses are dispatched back to the originating
call via per-request reply channels. Writes are serialized by `writeMu` so
requests never collide.

### Reconnecting Wrapper

The shared connection is wrapped in `reconnectClient` (`upstream.go`), which
implements `agent.ExtendedAgent` and holds an `atomic.Pointer` to the live
upstream connection.

If any `List`, `Sign`, or `SignWithFlags` call fails, the wrapper:
1. Closes the dead connection
2. Dials a fresh connection
3. Swaps the atomic pointer
4. Retries the failed call exactly once

All `filterAgent` instances see the new connection transparently via the
atomic pointer — no restart needed.

If the fresh dial also fails, a warning is logged and subsequent calls will
retry the reconnect on their next failure.

### Per-Client Filtering

For each accepted client connection, `serveConn` creates a fresh `filterAgent`
that implements `agent.ExtendedAgent`. One is then handed to `agent.ServeAgent`
to handle the client-side SSH agent wire protocol.

`filterAgent` is created **per client** and holds:
- A reference to the shared `reconnectClient` (all clients share the same one)
- Compiled matchers (derived from config)
- A **precomputed allowSet** (built once at startup from the initial upstream
  key list — a `map[keyBlob]bool`)

### Key Filtering at Sign Time

`Sign()` and `SignWithFlags()` check the **precomputed allowSet** (zero
round-trip) before forwarding to upstream. This avoids adding pressure to
an already-stressed upstream under burst load.

If the key is in the allowSet, the request is forwarded to the shared
upstream connection. If not, `SSH_AGENT_FAILURE` is returned immediately.

The allowSet is built at startup from a clean snapshot of upstream keys,
before any client burst. It is stable for the lifetime of the process.

### List Filtering

`List()` queries the upstream fresh each time (via the shared pipeline) and
filters the result through the group's matchers, returning keys in config
order. This ensures the client sees the current upstream key state.

### Mutating Operations

All mutating operations (`Add`, `Remove`, `RemoveAll`, `Lock`, `Unlock`,
`Signers`, `Extension`) are **refused** with `SSH_AGENT_FAILURE`. The proxy
is read-only — it never modifies upstream state.

## Connection Diagram

```
Client A ─┐
Client B ─┼── → acceptLoop(group A) ─→ serveConn ─┐
Client C ─┘                                        │
                                                    │
Client D ─┐                                         │
Client E ─┼── → acceptLoop(group B) ─→ serveConn ──┼── → reconnectClient ──→ upstream
Client F ─┘                                        │      (atomic.Pointer)           socket
                                                    │
         Each serveConn creates a filterAgent       │
         with its group's allowSet + matchers ──────┘
         All filterAgents share the same reconnectClient
```

## Shutdown

On SIGINT or SIGTERM:
1. `app.Run` cancels the context
2. `Server.Run` wakes from `<-ctx.Done()`
3. All group listeners are closed; each socket path is unlinked only if it still
   belongs to that listener
4. All `acceptLoop` goroutines exit their `ln.Accept`
5. In-flight `ServeAgent` calls on client connections detect the closed
   client socket (closed by the client or by deferred `client.Close()`)
6. Per-socket locks are released and the process exits

## Logging

- Structured logging via `log/slog`, writing one JSON object per line to stdout.
- In foreground mode, stdout goes to the terminal.
- As a managed service, stdout is captured by the platform (systemd journal
  on Linux, launchd log file on macOS).
- `debug: true` in config enables `LevelDebug`; default is `LevelInfo`.
- Version is logged at startup with structured fields: `version`, `commit`,
  `built`.
- The legacy `log` package output (used by `agent.ServeAgent` for errors) is
  redirected through slog at WARN level via `log.SetOutput`.

## Service Management (Platform)

| Platform | Mechanism     | Label                                          |
|----------|---------------|------------------------------------------------|
| macOS    | LaunchAgent   | `io.github.krisiasty.ssh-agent-proxy.plist`     |
| Linux    | systemd user  | `ssh-agent-proxy.service`                      |

The `service` package provides a `Manager` interface with platform-specific
implementations (selected at compile time via build tags). CLI flags
(`-install`, `-start`, `-stop`, etc.) dispatch to the manager.

macOS writes a plist to `~/Library/LaunchAgents/` and uses `launchctl` for
lifecycle control. Linux (future) writes a systemd user unit and uses
`systemctl`.
