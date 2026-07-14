# ssh-agent-proxy

## Overview

`ssh-agent-proxy` is a filtering proxy in front of an existing SSH agent (OpenSSH's
`ssh-agent`, or one provided by a password manager such as Bitwarden or KeePassXC).
It exposes one or more filtered views ("groups") of the upstream agent's keys, each
on its own listening socket, so that a given client (selected via `SSH_AUTH_SOCK`)
only sees and can only use the keys assigned to that group.

- Written in **Go 1.26.5**.
- May use the standard library plus **`golang.org/x/crypto/ssh/agent`** for the SSH
  agent wire protocol and **`gopkg.in/yaml.v3`** for config parsing. No other external
  dependencies.
- Initially targets **Linux** and **macOS** (Intel and Apple Silicon). A **Windows**
  version may follow later if feasible.

## Security model

This is the tool's core guarantee and must hold for every group socket:

- A client connected to a group's socket can **list only** the keys assigned to that
  group, and can request a **signature only** with a key assigned to that group.
- A sign request naming any key not in the group is refused with `SSH_AGENT_FAILURE`.
  Filtering is enforced on both listing and signing — it is never merely cosmetic.
- Keys not assigned to any group are not exposed on any socket.

## Key filtering

- Keys are selected by **comment**, **MD5 fingerprint**, or **SHA256 (base64) hash**
  of the public key.
- Fingerprints/hashes are computed over the key's public-key blob: MD5 as the
  hex-with-colons digest, SHA256 as the base64 digest.
- Keys are grouped; each group is exposed on its own socket. A key may belong to any
  number of groups, or to none (in which case it is filtered out entirely).
- With **no group defined, no keys are exposed.**
- Within a group, keys are presented in the **order defined in the config file**.
- If a config key entry matches **multiple** upstream keys, all matches are included
  (in upstream order, at that entry's position).
- If a config key entry matches **no** upstream key, it is skipped and a **warning**
  is logged.

## Configuration

- Format: **YAML**.
- Location: `os.UserConfigDir()` + `/ssh-agent-proxy/config.yaml`. The
  `ssh-agent-proxy` subdirectory is created automatically during installation.
  Typical paths:
  - Linux: `~/.config/ssh-agent-proxy/config.yaml`
  - macOS: `~/Library/Application Support/ssh-agent-proxy/config.yaml`
  - Windows: `%APPDATA%\ssh-agent-proxy\config.yaml`
- The location may be overridden with `-config <path>` (primarily for testing).

### Schema

- **`upstream`** (required): path to the upstream SSH agent socket. Environment
  variables are expanded (e.g. `${SSH_AUTH_SOCK}`).
- **`debug`** (optional, default `false`): enable verbose logging.
- **`groups`** (optional): a list of groups. Each group has:
  - **`socket`** (required): path to the socket this group is exposed on.
  - **`keys`** (optional): an ordered list of key entries. Each entry is an object:
    - **`type`** (required): one of `comment`, `md5`, `sha256`.
    - **`value`** (required): the comment string, MD5 fingerprint, or SHA256 hash to
      match. Comment matches are exact and case-sensitive. `md5`/`sha256` values are
      accepted with or without the `MD5:` / `SHA256:` prefix.

The **only required option is `upstream`**. No groups are required, but any group
that is defined must include `socket`, and its `keys` list (if present) must contain
valid entries.

### Sample configuration

```yaml
upstream: ${SSH_AUTH_SOCK}
debug: false

groups:
  - socket: ~/.ssh/agent-work.sock
    keys:
      - type: comment
        value: laptop@work
      - type: sha256
        value: SHA256:abc123...
  - socket: ~/.ssh/agent-personal.sock
    keys:
      - type: md5
        value: MD5:aa:bb:cc:dd:...
```

Clients select a group by pointing `SSH_AUTH_SOCK` at that group's socket, e.g.
`export SSH_AUTH_SOCK=~/.ssh/agent-work.sock`.

## Runtime behavior

- The proxy serves only **list identities** and **sign request** operations, both
  restricted to the group's keys as described in the security model.
- All **mutating requests** (add identity, remove identity, remove all, lock, unlock,
  add smartcard, extensions) are **rejected read-only** with `SSH_AGENT_FAILURE`.
- On start, each group socket is created; a pre-existing (stale) socket file at that
  path is removed and replaced. Sockets are created with `0600` permissions and are
  removed on clean shutdown.
- If the upstream agent is unreachable when a request arrives, the proxy returns a
  failure to the client and logs the condition; it keeps running.
- A single-instance guard (lock/PID file) prevents two daemons from binding the same
  sockets.
- Configuration is read once at startup. Changes require `-restart` to take effect.

## Logging

- Uses the standard `slog` library.
- Foreground mode logs to standard output.
- As a daemon: **systemd journal** on Linux, native **`os_log`** on macOS, and (in the
  future) the **Windows Event Log**.
- `debug: true` in the config enables verbose logging.

## Daemon / service management

The tool manages its own installation and lifecycle via command-line flags:

- `-install` — install as a per-user service and create the config directory.
- `-uninstall` — remove the service.
- `-start`, `-stop`, `-restart` — control the running service.
- `-status` — report whether the service is running, its PID, each group and its
  socket, and upstream reachability.
- `-list` — connect to the upstream agent and list all of its keys, printing for each
  key its comment, MD5 fingerprint, and SHA256 hash as ready-to-paste config `keys`
  entries so the user can copy selected keys straight into a group. Does not require or
  start the service.
- `-foreground` — run in the foreground, logging to standard output.
- `-config <path>` — use an alternate config file path.
- `-version` — print version and exit.

### `-list` output format

For each upstream key, all three match forms are printed as commented, correctly
indented YAML so the user can uncomment whichever they prefer and paste it under a
group's `keys:`. Example:

```yaml
# [1] ssh-ed25519 256 — laptop@work
    # - {type: comment, value: laptop@work}
    # - {type: sha256,  value: SHA256:abc123...}
    # - {type: md5,     value: MD5:aa:bb:cc:dd:...}
# [2] ssh-rsa 4096 — (no comment)
    # - {type: sha256,  value: SHA256:def456...}
    # - {type: md5,     value: MD5:11:22:33:44:...}
```

Per-OS integration:

- **Linux**: systemd **user services**; logs via the systemd journal.
- **macOS**: installable via Homebrew or manually; started via **Launch Agents**;
  logs via `os_log`.
- **Windows** (future): run via **Task Scheduler**; logs to the **Event Log**.

The service is **automatically restarted if it crashes or is killed**, unless it was
stopped properly.

## Failure handling

If the configuration file cannot be opened, cannot be parsed, or is missing required
options, the tool **logs an error and does nothing** — it does **not** exit (to avoid
being restarted in a loop by the service manager). The exception is **foreground
mode**, where it exits with an error.

## Build and release

- Artifacts are built and released with **GoReleaser**: cross-compiled binaries and
  archives for Linux and macOS (`amd64` and `arm64`), checksums, and the Homebrew
  formula published to a **tap**.
- GoReleaser is a build-time tool only; it does not affect the runtime dependency set.
- **macOS codesigning/notarization is out of scope** (no Apple Developer certificate).
  Manually downloaded macOS binaries may trigger a one-time Gatekeeper warning the user
  must clear; Homebrew installs generally avoid this.

## Deliverables

A `README.md` containing:

- Tool description.
- Installation and uninstallation procedures for each supported OS.
- Description of all command-line options.
- Description of the configuration file format.
- A sample configuration file.
