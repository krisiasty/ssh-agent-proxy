# ssh-agent-proxy

[![CI](https://github.com/krisiasty/ssh-agent-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/krisiasty/ssh-agent-proxy/actions/workflows/ci.yml)
[![Release](https://github.com/krisiasty/ssh-agent-proxy/actions/workflows/release.yml/badge.svg)](https://github.com/krisiasty/ssh-agent-proxy/actions/workflows/release.yml)
[![License](https://img.shields.io/github/license/krisiasty/ssh-agent-proxy)](LICENSE)

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
- Upstream identities are shared across all groups and cached for three seconds by
  default, limiting bursts to one upstream list refresh per cache interval.
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

Runtime logs use JSON Lines; see [Logging](#logging) for the default and debug output.

Then edit the config (see below) and reload:

```sh
ssh-agent-proxy -reload
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
| `-reload`      | Ask the running managed service to reload its config, then exit.       |
| `-status`      | Print service status (installed / running), then exit.                 |
| `-diag`        | Check configuration, service, upstream, and group health, then exit.   |
| `-list`        | List upstream keys as ready-to-paste config entries, then exit.        |
| `-foreground`  | Run in the foreground, logging to stdout (for testing / debugging).    |
| `-config PATH` | Use an alternate config file path.                                     |
| `--cache SECONDS` | Cache upstream identities for 0–60 seconds (default `3`; `0` disables caching). |
| `-version`     | Print version and exit.                                                |

The lifecycle flags are mutually exclusive. With no flag, the tool runs the proxy in
the foreground of the current process — this is how the service manager runs it.
When installing or reinstalling a managed service, the selected `--cache` value is
saved in its service definition.

### Reloading configuration

```sh
ssh-agent-proxy -reload
```

sends `SIGHUP` to the running managed service. The process reads and validates its
configured file before disturbing the active proxy. If validation fails, it logs the
error and keeps serving the current configuration. After successful validation it
replaces the upstream connection and group listeners; existing client connections are
closed so clients reconnect against the new authorization state.

If replacement startup fails—for example, because a new socket cannot be bound—the
proxy restores the previous working configuration. A managed service that is idling
after an initial config or upstream error can also recover when reloaded. A foreground
process accepts `SIGHUP` directly; `-reload` specifically targets the installed managed
service. The command-line `--cache` value is not reloaded because it is stored in the
service definition.

### Diagnosing service health

```sh
ssh-agent-proxy -diag
```

performs read-only checks of the selected configuration and reports each result as
`[PASS]`, `[WARN]`, or `[FAIL]`. It verifies that:

- the configuration loads and validates;
- an installed service is running with the selected config and current executable;
- the upstream agent accepts an identity request;
- every selector's match count can be resolved; and
- each enabled group socket returns the exact expected keys in configured order.

Disabled groups are reported but not probed. An unmatched selector is a warning. An
invalid config, unreachable upstream, stopped installed service, different installed
config, unavailable enabled socket, or unexpected group result is a failure. If no
managed service is installed, responding group sockets are recognized as a foreground
or otherwise unmanaged proxy.

Diagnostic output contains counts but never prints selector values, key comments,
fingerprints, or public-key blobs. The command continues independent checks after a
failure and exits non-zero if any check fails.

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

## Logging

Runtime logs use JSON Lines (JSONL): every line is a complete JSON object with `time`,
`level`, `msg`, and event-specific structured fields. This makes the output suitable
for both command-line processing and ingestion by log-management systems.

### Default logging

With the default `debug: false` configuration, the proxy logs:

- version, configuration path, upstream socket, cache and telemetry intervals, and
  group startup with the number of distinct matched keys;
- one warning for each configured selector that matches no upstream key, identifying
  its group, config index, and selector type without logging the selector value;
- client connections and disconnections, including UID, PID, and process name when the
  operating system provides them;
- successful client identity-list requests, including the group and number of returned
  identities;
- successful client sign requests, including the group and public-key fingerprint;
- shutdown, refused operations, reconnects, and any warnings or errors.

For example:

```jsonl
{"time":"2026-08-09T22:55:55.850+02:00","level":"INFO","msg":"serving group","group":"work","socket":"/Users/example/.ssh/agent-work.sock","keys":2}
{"time":"2026-08-09T22:55:55.851+02:00","level":"WARN","msg":"configured key selector matched no upstream key","group":"work","config_index":3,"selector_type":"comment"}
{"time":"2026-08-09T22:55:55.870+02:00","level":"INFO","msg":"client connected","conn":"67d54585","group":"work","uid":501,"pid":60181,"process":"ssh"}
{"time":"2026-08-09T22:55:55.873+02:00","level":"INFO","msg":"list identities","conn":"67d54585","group":"work","uid":501,"pid":60181,"process":"ssh","count":2}
{"time":"2026-08-09T22:55:55.893+02:00","level":"INFO","msg":"sign","conn":"67d54585","group":"work","uid":501,"pid":60181,"process":"ssh","fingerprint":"SHA256:5D4g5Lj3m9tn9r/lOD4vP42WHHyII1A6Y9+Myi1OqVM"}
{"time":"2026-08-09T22:55:55.921+02:00","level":"INFO","msg":"client disconnected","conn":"67d54585","group":"work","uid":501,"pid":60181,"process":"ssh"}
```

### Runtime telemetry

With debug logging enabled, the proxy samples its Go runtime every second and reports
once group startup completes, then periodically every ten minutes. `telemetry current`
contains a fresh sample, `telemetry max` contains the highest sampled values during the
interval, and `telemetry interval` contains activity since the previous report. All
three records and all their defined fields are emitted every time, including unchanged
and zero values, providing a stable schema for log processing. After reporting, the
interval maximum and counter baselines reset.

The current and maximum records contain:

| Field | Description |
| --- | --- |
| `uptime_seconds` | Process telemetry uptime in seconds |
| `goroutines` | Live goroutines |
| `os_threads` | OS threads created by the Go runtime |
| `heap_alloc_bytes` | Bytes allocated to heap objects |
| `heap_inuse_bytes` | Bytes in in-use heap spans |
| `heap_live_bytes` | Reachable heap bytes marked by the most recent garbage collection; zero until the first GC completes |
| `heap_goal_bytes` | Target heap size for the end of the current garbage-collection cycle |
| `stack_inuse_bytes` | Bytes in stack spans |
| `runtime_reserved_bytes` | Bytes reserved by the Go runtime |
| `heap_objects` | Live heap objects |

The interval record contains:

| Field | Description |
| --- | --- |
| `heap_allocated_bytes` | Heap bytes allocated during the interval |
| `heap_allocated_objects` | Heap objects allocated during the interval |
| `gc_cycles` | Completed garbage-collection cycles during the interval |

```jsonl
{"time":"2026-08-09T23:10:34.642Z","level":"DEBUG","msg":"telemetry current","uptime_seconds":117000.000737511,"goroutines":16,"os_threads":7,"heap_alloc_bytes":1713304,"heap_inuse_bytes":3194880,"heap_live_bytes":1605632,"heap_goal_bytes":4194304,"stack_inuse_bytes":491520,"runtime_reserved_bytes":13728008,"heap_objects":10041}
{"time":"2026-08-09T23:10:34.642Z","level":"DEBUG","msg":"telemetry max","uptime_seconds":117000.000737511,"goroutines":17,"os_threads":7,"heap_alloc_bytes":2493920,"heap_inuse_bytes":3858432,"heap_live_bytes":1605632,"heap_goal_bytes":4194304,"stack_inuse_bytes":524288,"runtime_reserved_bytes":13728008,"heap_objects":19349}
{"time":"2026-08-09T23:10:34.642Z","level":"DEBUG","msg":"telemetry interval","heap_allocated_bytes":171064,"heap_allocated_objects":594,"gc_cycles":1}
```

### Proxy telemetry

Debug mode also emits three application-level interval records alongside runtime
telemetry:

| Record | Fields |
| --- | --- |
| `telemetry clients` | Active and maximum concurrent clients, new connections and connection errors, plus list/sign requests and errors |
| `telemetry upstream` | Upstream calls, errors, and successful reconnects |
| `telemetry cache` | Identity-cache hits, misses, actual refreshes, and requests that waited for an in-flight refresh |

The active-client values are gauges. All other values count activity since the previous
report and reset after being logged. A cache miss counts each request that first finds an
expired cache; concurrent misses share one refresh and increment `waits` while blocked.

```jsonl
{"time":"2026-08-09T23:10:34.643Z","level":"DEBUG","msg":"telemetry clients","active_clients":0,"max_active_clients":30,"connections":60,"connection_errors":0,"list_requests":30,"list_errors":0,"sign_requests":30,"sign_errors":0}
{"time":"2026-08-09T23:10:34.643Z","level":"DEBUG","msg":"telemetry upstream","calls":31,"errors":0,"reconnects":0}
{"time":"2026-08-09T23:10:34.643Z","level":"DEBUG","msg":"telemetry cache","hits":29,"misses":1,"refreshes":1,"waits":0}
```

### Debug logging

Set `debug: true` in the configuration and reload the proxy to include debug records.
Debug mode adds:

- runtime and proxy telemetry immediately after group startup and every ten minutes;
- every upstream operation, with its attempt number, duration, result count, error, or
  other operation-specific metadata;
- every identity returned by an upstream list, numbered as `identity n/m`, with its
  fingerprint, comment, algorithm, and key size;
- configuration-key resolution summaries;
- every identity returned to a client, numbered as `group identity n/m`, with the same
  public-key metadata and only the relevant connection and group context;
- low-level client and upstream connection diagnostics.

For example, these records are added to the normal output:

```jsonl
{"time":"2026-08-09T22:37:37.445+02:00","level":"DEBUG","msg":"upstream call","operation":"list","attempt":1,"keys":10,"duration":"9.836284ms"}
{"time":"2026-08-09T22:37:37.445+02:00","level":"DEBUG","msg":"identity 1/10","fingerprint":"SHA256:0KAYsd1LwHitQ6zCUWoRw2FPSLWjsfLMRU6Fn/CyFBw","comment":"laptop@work","algorithm":"ssh-ed25519","key_size":256}
{"time":"2026-08-09T22:37:37.445+02:00","level":"DEBUG","msg":"config keys resolved","group":"work","trigger":"client-list","configured_keys":2,"upstream_keys":10,"resolved_keys":2}
{"time":"2026-08-09T22:37:42.821+02:00","level":"DEBUG","msg":"group identity 1/2","conn":"bb411e20","group":"work","fingerprint":"SHA256:5D4g5Lj3m9tn9r/lOD4vP42WHHyII1A6Y9+Myi1OqVM","comment":"laptop@work","algorithm":"ssh-ed25519","key_size":256}
```

Only public-key metadata is logged. Private keys, signing payloads, and passphrases are
never included.

### Human-friendly output with `hl`

The excellent [`hl`](https://github.com/pamburus/hl) log processor understands JSONL
and renders these structured records in a compact, colored, human-friendly format. For
example:

```text
2026-08-09 22:55:55.873 [INF] list identities :: conn=67d54585 group=work uid=501 pid=60181 process=ssh count=2
2026-08-09 22:55:55.893 [INF] sign :: conn=67d54585 group=work uid=501 pid=60181 process=ssh fingerprint=SHA256:5D4g5Lj3m9tn9r/lOD4vP42WHHyII1A6Y9+Myi1OqVM
2026-08-09 22:37:37.445 [DBG] identity 1/10 :: fingerprint=SHA256:0KAYsd1LwHitQ6zCUWoRw2FPSLWjsfLMRU6Fn/CyFBw comment=laptop@work algorithm=ssh-ed25519 key-size=256
2026-08-09 22:37:42.821 [DBG] group identity 1/2 :: conn=bb411e20 group=work fingerprint=SHA256:5D4g5Lj3m9tn9r/lOD4vP42WHHyII1A6Y9+Myi1OqVM comment=laptop@work algorithm=ssh-ed25519 key-size=256
```

View the macOS log file, follow it live, or process live systemd journal output with:

```sh
hl ~/Library/Logs/ssh-agent-proxy.log
tail -f ~/Library/Logs/ssh-agent-proxy.log | hl -P
journalctl --user -u ssh-agent-proxy -f -o cat | hl -P
```

## Configuration

The config file is YAML, stored at `os.UserConfigDir()/ssh-agent-proxy/config.yaml`:

- Linux: `~/.config/ssh-agent-proxy/config.yaml`
- macOS: `~/Library/Application Support/ssh-agent-proxy/config.yaml`
- Windows: `%APPDATA%\ssh-agent-proxy\config.yaml` *(planned)*

### Fields

| Key                 | Required | Description                                                             |
| ------------------- | -------- | ----------------------------------------------------------------------- |
| `upstream`          | yes      | Absolute path to the upstream SSH agent socket. Environment variables and `~` are not expanded. |
| `debug`             | no       | `true` for verbose logging (default `false`).                           |
| `groups`            | no       | List of groups. With none defined, no keys are exposed.                 |
| `groups[].name`     | yes\*    | Unique name for the group (used in logs). \*Required if the group exists.|
| `groups[].enabled`  | no       | `true` (default) to expose the group, `false` to skip it.               |
| `groups[].socket`   | yes\*    | Absolute socket path this group is exposed on; no environment-variable or `~` expansion (\*required if the group exists). |
| `groups[].keys`     | no       | Ordered list of key entries assigned to the group.                      |
| `groups[].keys[].comment` | no\* | Exact, case-sensitive key comment. \*Exactly one match field is required per entry. |
| `groups[].keys[].md5` | no\* | MD5 fingerprint, with an optional `MD5:` prefix.                        |
| `groups[].keys[].sha256` | no\* | SHA256 hash, with an optional `SHA256:` prefix.                         |

Notes:

- Each group needs a **unique `name`**; it appears in log messages.
- `upstream` and group socket paths must be written as absolute paths. Values such
  as `${SSH_AUTH_SOCK}` and `~/.ssh/agent.sock` are not expanded.
- Enabled groups must use distinct socket paths, including paths that become
  equivalent after cleaning or resolving existing symlinked directories. An enabled
  group socket also cannot resolve to the upstream agent socket.
- A group with **`enabled: false`** is not exposed (its socket is not created). Omitting
  `enabled` means the group is enabled.
- **`comment`** matches the key comment exactly (case-sensitive).
- **`md5`** matches the MD5 fingerprint; the `MD5:` prefix is optional.
- **`sha256`** matches the SHA256 hash; the `SHA256:` prefix is optional.
- Each key entry must contain exactly one of `comment`, `md5`, or `sha256`.
- See [Logging](#logging) for the records enabled by `debug: true` and the public-key
  metadata they contain.
- Keys appear in a group in the order their entries are listed.
- A config entry that matches several upstream keys includes them all; one that matches
  no upstream key is skipped.
- On macOS, configure the LaunchAgent with the upstream agent's explicit absolute
  socket path; do not use `${SSH_AUTH_SOCK}` in the configuration.

### Sample configuration

```yaml
# Path to the upstream SSH agent socket (required).
upstream: /absolute/path/to/upstream-agent.sock

# Verbose logging.
debug: false

# Filtered views of the upstream agent. Point a client at a group with:
#   export SSH_AUTH_SOCK=<socket>
groups:
  - name: work
    enabled: true
    socket: /absolute/path/to/agent-work.sock
    keys:
      - comment: "laptop@work"
      - sha256: "SHA256:9N6igGbuSz87xjbn/QUg/C5yfT1nLBMw+MkKnZoOrLI"

  - name: personal
    enabled: false
    socket: /absolute/path/to/agent-personal.sock
    keys:
      - md5: "MD5:d7:4a:ab:42:5a:c8:a6:fc:c3:a2:c2:9d:86:bc:4b:a9"
```

Configuration is read at startup and on `SIGHUP`; run `ssh-agent-proxy -reload` to apply
changes to a managed service.

If the config cannot be read or validated, or the initial upstream connection cannot be
opened, the service logs the error and idles rather than exiting into a restart loop. Fix
the config or upstream agent and reload the service. In `-foreground` mode it returns
the error and exits instead. With no enabled groups, it idles without connecting to the
upstream agent because it has no sockets to serve.

One shared upstream identity list resolves every enabled group during startup. If the
connected upstream agent is locked or listing otherwise fails, the proxy still starts
serving and defers resolution until a client request. It picks up matching keys after the
agent is unlocked or populated. Successful upstream key lists are cached process-wide
for the configured `--cache` interval. Concurrent refreshes across every group share one
request; if a refresh fails, the last successful list is served until the next interval.

At startup, each enabled group socket is protected by a nonblocking file lock. If
another proxy instance owns a lock or an existing socket accepts connections, startup
fails without removing that socket. A socket is replaced only when a connection probe
proves that the endpoint is stale. The adjacent `.lock` files are intentionally retained
between runs so every instance locks the same file inode.

Temporary listener accept failures are logged and retried with exponential backoff
capped at one second. A terminal listener failure closes every group listener and exits
non-zero so launchd or systemd can restart the complete proxy instead of leaving one
group silently unavailable.

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
`go.yaml.in/yaml/v3` (config).

## Development and releases

Pull requests and pushes to `main` run formatting, vet, race-enabled tests, a
vulnerability scan, workflow validation, a transitive dependency license gate, and
cgo-free cross-builds for Linux and macOS on amd64 and arm64. The same checks run
weekly to detect newly disclosed dependency vulnerabilities.

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the development
workflow and pull request expectations. Please report security vulnerabilities through
the private process in [SECURITY.md](SECURITY.md), never through a public issue.

Releases are cut by pushing a `v*` tag. The release workflow repeats the quality gates,
then uses GoReleaser to publish platform archives and checksums to GitHub. It also
updates the `ssh-agent-proxy` cask in
[`krisiasty/homebrew-tap`](https://github.com/krisiasty/homebrew-tap). The repository
must define `HOMEBREW_TAP_GITHUB_TOKEN` as a fine-grained token with Contents write
access to that tap.

To validate release packaging locally without publishing:

```sh
goreleaser release --snapshot --clean --skip=publish
```

## License

Apache 2.0 — see [LICENSE](LICENSE). Licenses and notices for statically linked
dependencies are collected in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

Participation in this project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
