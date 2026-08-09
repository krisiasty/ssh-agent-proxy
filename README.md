# ssh-agent-proxy

`ssh-agent-proxy` is a filtering proxy that sits in front of an existing SSH agent —
especially the agent built into a password manager such as **Bitwarden, KeePassXC,
1Password, or Secretive**.

**The problem.** Password-manager SSH agents expose *every* key they hold to every
client, all at once and in no particular order. You can't scope which keys a given
host, repo, or container sees, and you can't control their order. Beyond being untidy,
it breaks logins: ssh offers agent keys one at a time, so once you have more than a
handful the server rejects you with *"Too many authentication failures"* (it hits
`MaxAuthTries`) before ever reaching the key you actually needed.

**What this does.** `ssh-agent-proxy` sits in front of that agent and exposes one or
more **filtered views** ("groups") of its keys, each on its own socket. A client that
points `SSH_AUTH_SOCK` at a group's socket sees — and can sign with — *only* the keys
you assigned to that group, **in the order you listed them**. Every other key is
invisible and unusable through that socket. The private keys never leave the upstream
agent, and any confirmation/biometric prompt it enforces still applies.

## How it works

- The proxy connects to your real ("upstream") agent.
- For each configured group it listens on a Unix socket.
- **List identities** returns only the group's keys, in the order you configured.
- **Sign requests** are honored only for keys in the group; any other key is refused.
- The proxy is **read-only**: requests that would modify the agent (add/remove a key,
  lock/unlock, extensions) are always refused. Your upstream agent is never modified.

Select a group from a client by pointing `SSH_AUTH_SOCK` at its socket:

```sh
export SSH_AUTH_SOCK=~/.ssh/agent-work.sock
ssh-add -l          # shows only the work group's keys
ssh git@github.com  # can only authenticate with those keys
```

## Installation

Binaries are built for Linux and macOS (amd64 and arm64).

> **macOS note:** downloaded binaries are not code-signed/notarized. Installing via
> Homebrew avoids Gatekeeper warnings (Homebrew strips the quarantine attribute). If you
> download a binary manually, clear it once with `xattr -d com.apple.quarantine ./ssh-agent-proxy`.

### macOS (Homebrew)

```sh
brew install krisiasty/tap/ssh-agent-proxy
```

### Manual (Linux and macOS)

Download the archive for your OS/arch from the
[releases page](https://github.com/krisiasty/ssh-agent-proxy/releases), extract it, and
put the binary on your `PATH`:

```sh
tar -xzf ssh-agent-proxy_*_"$(uname -s)"_"$(uname -m)".tar.gz
sudo install ssh-agent-proxy /usr/local/bin/
```

### Install as a service

`ssh-agent-proxy` manages its own service installation. This creates the config
directory (with a sample config if none exists) and registers a per-user service that
starts at login and restarts if it crashes:

```sh
ssh-agent-proxy -install
```

- **Linux:** a **systemd user service** (`~/.config/systemd/user/ssh-agent-proxy.service`);
  logs go to the **systemd journal** (`journalctl --user -u ssh-agent-proxy`).
- **macOS:** a **LaunchAgent** (`~/Library/LaunchAgents/io.github.krisiasty.ssh-agent-proxy.plist`);
  logs go to `~/Library/Logs/ssh-agent-proxy.log`.

Runtime logs use JSON Lines: every line is a complete JSON object with `time`, `level`,
`msg`, and any event-specific structured fields.

Then edit the config (see below) and restart:

```sh
ssh-agent-proxy -restart
```

## Uninstallation

```sh
ssh-agent-proxy -uninstall     # stop and remove the service
```

This removes the service definition. Your config file is left in place; delete it
manually if you want it gone. For Homebrew, also run `brew uninstall ssh-agent-proxy`.

## Command-line options

| Flag           | Description                                                            |
| -------------- | ---------------------------------------------------------------------- |
| `-install`     | Install and start the service, then exit. Fails if already installed.  |
| `-reinstall`   | Reinstall (uninstall then install), then exit. Use to update the installed binary path. |
| `-uninstall`   | Stop and remove the service, then exit.                                |
| `-start`       | Start the service, then exit.                                          |
| `-stop`        | Stop the service, then exit.                                           |
| `-restart`     | Restart the service, then exit.                                        |
| `-status`      | Print service status (installed / running), then exit.                 |
| `-list`        | List upstream keys as ready-to-paste config entries, then exit.        |
| `-foreground`  | Run in the foreground, logging to stdout (for testing / debugging).    |
| `-config PATH` | Use an alternate config file path.                                     |
| `-version`     | Print version and exit.                                                |

The lifecycle flags are mutually exclusive. With no flag, the tool runs the proxy in
the foreground of the current process — this is how the service manager runs it.

### Discovering your keys

```sh
ssh-agent-proxy -list
```

prints every key in the upstream agent with all three ways to match it, as YAML entries
you can paste under a group's `keys:`. Each key is preceded by a header line with its
index, algorithm, and size in bits:

```yaml
[1] ssh-ed25519 256
  - comment: "laptop@work"
  - sha256: "SHA256:9N6igGbuSz87xjbn/QUg/C5yfT1nLBMw+MkKnZoOrLI"
  - md5: "MD5:d7:4a:ab:42:5a:c8:a6:fc:c3:a2:c2:9d:86:bc:4b:a9"
```

## Configuration

The config file is YAML, stored at `os.UserConfigDir()/ssh-agent-proxy/config.yaml`:

- Linux: `~/.config/ssh-agent-proxy/config.yaml`
- macOS: `~/Library/Application Support/ssh-agent-proxy/config.yaml`
- Windows: `%APPDATA%\ssh-agent-proxy\config.yaml` *(planned)*

### Fields

| Key                 | Required | Description                                                             |
| ------------------- | -------- | ----------------------------------------------------------------------- |
| `upstream`          | yes      | Path to the upstream SSH agent socket. Env vars (`${VAR}`) and `~` are expanded. |
| `debug`             | no       | `true` for verbose logging (default `false`).                           |
| `groups`            | no       | List of groups. With none defined, no keys are exposed.                 |
| `groups[].name`     | yes\*    | Unique name for the group (used in logs). \*Required if the group exists.|
| `groups[].enabled`  | no       | `true` (default) to expose the group, `false` to skip it.               |
| `groups[].socket`   | yes\*    | Socket path this group is exposed on (\*required if the group exists).  |
| `groups[].keys`     | no       | Ordered list of key entries assigned to the group.                      |
| `groups[].keys[].comment` | no\* | Exact, case-sensitive key comment. \*Exactly one match field is required per entry. |
| `groups[].keys[].md5` | no\* | MD5 fingerprint, with an optional `MD5:` prefix.                        |
| `groups[].keys[].sha256` | no\* | SHA256 hash, with an optional `SHA256:` prefix.                         |

Notes:

- Each group needs a **unique `name`**; it appears in log messages.
- Enabled groups must use distinct socket paths, including paths that become
  equivalent after cleaning or resolving existing symlinked directories. An enabled
  group socket also cannot resolve to the upstream agent socket.
- A group with **`enabled: false`** is not exposed (its socket is not created). Omitting
  `enabled` means the group is enabled.
- **`comment`** matches the key comment exactly (case-sensitive).
- **`md5`** matches the MD5 fingerprint; the `MD5:` prefix is optional.
- **`sha256`** matches the SHA256 hash; the `SHA256:` prefix is optional.
- Each key entry must contain exactly one of `comment`, `md5`, or `sha256`.
- With `debug: true`, logs show one completion record for every upstream call and
  one compact count summary for each configuration-key refresh. Private keys,
  signing payloads, and passphrases are never logged.
- Keys appear in a group in the order their entries are listed.
- A config entry that matches several upstream keys includes them all; one that matches
  no upstream key is skipped.
- On macOS run as a LaunchAgent, `${SSH_AUTH_SOCK}` may not be present in the service's
  environment; if the upstream agent isn't found, set an explicit `upstream:` path.

### Sample configuration

```yaml
# Path to the upstream SSH agent socket (required).
upstream: ${SSH_AUTH_SOCK}

# Verbose logging.
debug: false

# Filtered views of the upstream agent. Point a client at a group with:
#   export SSH_AUTH_SOCK=<socket>
groups:
  - name: work
    enabled: true
    socket: ~/.ssh/agent-work.sock
    keys:
      - comment: "laptop@work"
      - sha256: "SHA256:9N6igGbuSz87xjbn/QUg/C5yfT1nLBMw+MkKnZoOrLI"

  - name: personal
    enabled: false
    socket: ~/.ssh/agent-personal.sock
    keys:
      - md5: "MD5:d7:4a:ab:42:5a:c8:a6:fc:c3:a2:c2:9d:86:bc:4b:a9"
```

Configuration is read once at startup; run `ssh-agent-proxy -restart` to apply changes.

If the config cannot be read or validated, or the upstream agent is unavailable during
startup, the service logs the error and idles rather than exiting into a restart loop.
Fix the config or upstream agent and restart the service. In `-foreground` mode it
returns the error and exits instead. With no enabled groups, it idles without connecting
to the upstream agent because it has no sockets to serve.

Group keys are resolved lazily rather than during startup. If an upstream agent accepts
connections while locked or initially has no keys, the proxy can start serving and will
pick up matching keys after the agent is unlocked or populated.

At startup, each enabled group socket is protected by a nonblocking file lock. If
another proxy instance owns a lock or an existing socket accepts connections, startup
fails without removing that socket. A socket is replaced only when a connection probe
proves that the endpoint is stale. The adjacent `.lock` files are intentionally retained
between runs so every instance locks the same file inode.

## Platform support

| Platform | Service          | Logging          | Status  |
| -------- | ---------------- | ---------------- | ------- |
| Linux    | systemd (user)   | systemd journal  | ✅      |
| macOS    | LaunchAgent      | log file         | ✅      |
| Windows  | Task Scheduler   | Event Log        | planned |

## Building from source

```sh
go build -o ssh-agent-proxy .
```

Requires Go 1.26+. Dependencies: `golang.org/x/crypto` (SSH agent protocol) and
`gopkg.in/yaml.v3` (config).

## License

MIT — see [LICENSE](LICENSE).
