# pasla

> Single-file, zero-dependency, security-hardened ephemeral file-sharing CLI.

`pasla` serves a single file (or a directory it auto-archives) over HTTP/HTTPS
with a time-limited, token-protected URL — then exits. No cloud, no login,
no install, no daemons hanging around. One Python file, standard library
only, runs anywhere CPython 3.9+ runs.

> [!IMPORTANT]
> `pasla`'s first goal is **easy** file delivery, not **confidential**
> file delivery.  The token, TLS, rate-limit, and ban defences protect
> the delivery channel — not the file's contents.  If the payload is
> sensitive, **wrap it in a password-protected archive first** (7-Zip
> or WinRAR with AES are the everyday picks) and share the password
> through a separate channel.  The URL stays an opaque handle; the
> secret stays under your control.

## Table of contents

- [The name](#the-name)
- [Features](#features)
- [Compared to common alternatives](#compared-to-common-alternatives)
- [Install](#install)
- [Quick start](#quick-start)
- [CLI reference](#cli-reference)
- [HTTPS mode](#https-mode)
- [Security model](#security-model)
- [Configuration](#configuration)
- [Examples](#examples)
- [Architecture](#architecture)
- [Performance and limits](#performance-and-limits)
- [Cross-platform notes](#cross-platform-notes)
- [Development](#development)
- [Limitations and known constraints](#limitations-and-known-constraints)
- [License](#license)

## The name

**pasla** /pɑs.lɑ/ — Turkish imperative of *paslamak* ("to pass").  In
football you'd shout *"topu pasla!"* — "pass the ball!". That's the whole
mental model: you have something on your machine, you want it on someone
else's machine, you pass it.  Short, memorable, matches the spirit of an
ad-hoc one-shot transfer.

---

## Features

- **One-way, server → client** — pasla is built for the
  "something landed on this machine, get it onto someone else's
  machine" pattern (build artefact, log bundle, generated report,
  game-server world snapshot).  It serves a file; recipients
  download with a browser or curl.  No upload mode, no peer
  pairing.
- **Zero dependencies** — Python standard library only.  No `pip install`,
  no virtualenv, no lockfile.  `openssl` CLI is required only for `--https`.
- **Single file** (~5 KLOC) — easy to audit, drop into a server, or
  embed in your own tooling.
- **Token-protected URLs** — 128-bit `secrets.token_urlsafe`, constant-time
  comparison, IP-based ban after repeated wrong tokens.
- **Time- and count-limited** — link expires automatically; cap the number
  of downloads with `max_downloads` or `--single`.
- **Resumable downloads** — full HTTP `Range` / `206 Partial Content`
  support, including suffix and open-ended ranges.
- **HTTPS** — `--https` generates an ephemeral self-signed ECDSA cert,
  TLS 1.2+ with secure ciphers, fingerprint printed in the banner.
- **SHA-256 integrity** — auto-computed for files ≤ 1 GB, exposed via
  RFC 9530 `Digest` header.
- **Directory sharing** — auto-archives directories as uncompressed tar on the fly.
- **Dual-stack networking** — IPv4 + IPv6 from a single socket where
  the OS supports it; clean fallback otherwise.
- **DDoS posture** — pre-thread global cap, per-IP cap, slowloris timeout,
  RST-on-reject (no `TIME_WAIT` amplification), bounded ban/track tables.
- **Reverse-proxy aware** — `--trust-proxy` honours `X-Forwarded-For`
  (rightmost) by default; `--trust-header` selects a specific edge
  header (e.g. `CF-Connecting-IP` for Cloudflare), with defence-in-depth
  allowlist on both header-derived and socket peer IPs.
- **CIDR allowlist** — `--allow-ip 10.0.0.0/8 --allow-ip 192.168.1.0/24`,
  IPv4 and IPv6, repeatable.
- **Live TUI** — countdown, download count, transferred bytes, OSC 8
  clickable URLs, automatic VT100 enable on Windows 10+.
- **Background / daemon mode** — `pasla -d`, `pasla list`, `pasla stop <id>`,
  `pasla stop --all`.
- **Automation-friendly** — `--json` for machine-readable output,
  `--dry-run` for CI validation.
- **Cross-platform** — Linux, macOS, Windows (incl. Win10+ ANSI, ctypes
  process liveness, `SO_EXCLUSIVEADDRUSE` on the control plane).

---

## Compared to common alternatives

| Tool | Deps | TLS | Auth | Multi-TB | Notes |
|---|---|---|---|---|---|
| `python -m http.server` | none | no | no | yes | no auth, no token, no TLS |
| `nc` | none | no | no | yes | raw bytes, no protocol |
| `magic-wormhole` | `pip` | yes | code | small | NAT-punched, peer-to-peer, end-to-end encrypted |
| `croc` | binary | yes | code | yes | Go binary (~10 MB), end-to-end encrypted |
| `miniserve` | binary | yes | HTTP Basic | yes | Rust binary, directory-listing model, no expiry / cap |
| `transfer.sh` | Go binary | yes | URL secret | config-dep | self-hostable; sender uploads first, recipient downloads |
| `plik` | Go binary | yes | URL token | config-dep | full service: web UI, accounts, expiry policies |
| **pasla** | **none** | yes | token + ban | yes | one-shot CLI from your own machine, URL token, time + count cap |

The closest cousin in *spirit* is **`miniserve`** — also a single
binary you launch ad-hoc on your own machine to share something —
but its auth is HTTP Basic on a directory listing rather than a
token in the URL, and it has no built-in expiry or download cap.

If you would rather run a recurring **service** than a one-shot CLI,
`transfer.sh` (sender uploads to it first, recipient pulls) and
`plik` (full web UI, accounts, retention policies) are the typical
Go-based picks.

If end-to-end secrecy matters more than recipient ergonomics,
`magic-wormhole` and `croc` provide PAKE-derived encryption — but
both require the recipient to install the matching tool and pair
via a code rather than open a URL.

`pasla` lives in the gap between these: a one-command CLI on your
own machine, token-protected URL the recipient opens in a browser,
time-and-count limited, no third party, no recipient install.  When
the goal is "the server already produced this artefact, get it to
one specific person now", that gap is the niche.

---

## Install

Pasla installs **per-user**, no `sudo` required.  The script lives in
your home directory so updates, removal, and free-threaded tweaks never
need elevated permissions.

```bash
# 1. Create the user-local bin directory and download pasla into it
mkdir -p "$HOME/.local/bin"
curl -fsSL https://raw.githubusercontent.com/Fix3dll/pasla/main/pasla \
    -o "$HOME/.local/bin/pasla"
chmod +x "$HOME/.local/bin/pasla"

# 2. Ensure ~/.local/bin is on your PATH (one-time, if not already there)
#    Append this to your shell startup file
#    (~/.profile or ~/.bashrc on bash, ~/.zshrc or ~/.zprofile on zsh):
export PATH="$HOME/.local/bin:$PATH"
```

Open a new terminal (or `source` your shell startup file), then `pasla`
works from any directory:

```bash
pasla report.pdf
```

> [!TIP]
> **Free-threaded mode (No-GIL):** If you have Python 3.13t+ installed and want to maximize performance, edit the first line of `~/.local/bin/pasla` to point to it (e.g., `#!/usr/bin/env python3.14t`).

Or just clone and copy (no `sudo` either):

```bash
git clone https://github.com/Fix3dll/pasla.git
install -m 0755 pasla/pasla "$HOME/.local/bin/pasla"
```

**Requirements:**

- Python 3.9 or newer (3.14+ recommended for free-threaded mode).
- `openssl` on `PATH` if you use `--https`.

That's it.  No `pip install`, no compiled extensions, no system services
to register, no root.

### Windows

```powershell
# 1. Create a permanent directory and download pasla into it
New-Item -ItemType Directory -Force "$env:LOCALAPPDATA\pasla" | Out-Null
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Fix3dll/pasla/main/pasla" `
    -OutFile "$env:LOCALAPPDATA\pasla\pasla"

# 2. Create a wrapper so that 'pasla' invokes Python automatically
# (Note: If you have installed the free-threaded binaries for Python 3.13t+,
# you can replace '@python' below with '@py -3.14t' or '@python3.14t')
Set-Content "$env:LOCALAPPDATA\pasla\pasla.cmd" '@python "%~dp0pasla" %*'

# 3. Add to user PATH (persistent across sessions, one-time)
$dir = "$env:LOCALAPPDATA\pasla"
$path = [Environment]::GetEnvironmentVariable("Path", "User")
if ($path -notlike "*$dir*") {
    [Environment]::SetEnvironmentVariable("Path", "$path;$dir", "User")
}
```

Restart the terminal, then `pasla` works from any directory:

```powershell
pasla report.pdf
```

> [!NOTE]
> Pressing Ctrl+C shows a `Terminate batch job (Y/N)?` prompt after
> the server stops.  This is a cmd.exe limitation with `.cmd` wrappers;
> type `Y` to dismiss.

---

## Quick start

```bash
# Share a file for 60 minutes (default)
pasla report.pdf

# Single-use link, 30-minute expiry, over HTTPS
pasla report.pdf 30 1 --https --single

# Background, 2-hour expiry, max 5 downloads
pasla -d big.iso 120 5

# List active background instances
pasla list

# Stop a specific instance (or all of them)
pasla stop a1b2c3
pasla stop --all
```

The startup banner shows:

```
──────────────────────────────────────────
  ID          : a1b2c3
  File        : report.pdf
  Port        : 47391 (auto)
  Expires     : 60 minute(s)
  Cap         : max 1
  Ban after   : 5 failed attempts
  Rate limit  : 20 req / 60s per IP
  Range       : supported (resumable)
  IPv6        : yes
  Trust proxy : disabled
  HTTPS       : enabled (self-signed, ephemeral)
  SHA-256     : 9b74c9897…
  Cert FP     : AB:CD:EF:…
──────────────────────────────────────────
  IPv4 : https://203.0.113.5:47391/<token>/report.pdf
  IPv6 : https://[2001:db8::1]:47391/<token>/report.pdf
──────────────────────────────────────────

  ⏱ 59m 58s │ 0/1 downloads │ 0.0 B │ Ctrl+C to stop
```

Send the URL out-of-band (Slack, SMS, paper, whatever).  When the cap
is reached or the timer expires, the server shuts itself down.

---

## CLI reference

```
pasla <file> [duration_minutes] [max_downloads] [options]
pasla list
pasla stop <id> | pasla stop --all
```

### Positional arguments

| Argument | Default | Description |
|---|---|---|
| `file` | — | File to share (or directory; you'll be prompted to archive). |
| `duration_minutes` | `60` | Link expiry in minutes. |
| `max_downloads` | `0` (unlimited) | Stop after this many successful downloads. |

### Options

| Flag | Description |
|---|---|
| `-d, --detach` | Run in background, print URL, exit. |
| `-v, --version` | Print the pasla version and exit. |
| `-p, --port PORT` | Bind to a specific port (default: random 40000–50000). |
| `-4, --ipv4` / `-6, --ipv6` | Restrict to one address family. |
| `--single` | Equivalent to `max_downloads=1`. |
| `--allow-ip CIDR` | Restrict downloads to listed networks.  Repeatable. |
| `--trust-proxy` | Read client IP from `X-Forwarded-For`.  **See security notes.** |
| `--trust-header NAME` | With `--trust-proxy`, read client IP from this specific header instead of XFF (e.g. `CF-Connecting-IP`).  See `--trust-proxy` checklist. |
| `--https` / `--no-https` | Enable TLS (ephemeral cert) / force plaintext, overriding any config. |
| `--tls-cert PATH` / `--tls-key PATH` | Use an existing PEM cert/key pair instead of generating one.  Implies `--https`. |
| `--checksum` / `--no-checksum` | Force-on / force-off SHA-256 (default: on for files ≤ 1 GB). |
| `--json` | Print machine-readable JSON, suppress TUI. |
| `--dry-run` | Validate args, resolve IPs, print URL, exit without serving. |

### Subcommands

| Command | Purpose |
|---|---|
| `pasla list` | List running background instances (live status via control plane). |
| `pasla stop <id>` | Stop one instance.  Prefix-match on `<id>` is supported. |
| `pasla stop --all` | Stop every running instance. |

> **Stopping a background daemon:** always use `pasla stop`.  On POSIX a
> plain `kill <pid>` (SIGTERM) also triggers a graceful shutdown.  On
> Windows there is no graceful-stop equivalent for a detached process:
> `taskkill` terminates it abruptly and leaves stale registry/temp/TLS
> artefacts behind (the next `pasla list` reaps them).  `pasla stop` is
> the only clean way to stop a Windows daemon.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success / clean shutdown. |
| `1` | Configuration or validation error (bad path, occupied port, bad CIDR, etc.). |
| `2` | Detach failed (background process did not become ready in time). |
| `130` | Interrupted with Ctrl+C while waiting for a detached daemon to start. |

---

## HTTPS mode

> [!WARNING]
> **Without `--https`, traffic is plaintext HTTP and the URL token
> travels unencrypted.** Anyone on the network path (Wi-Fi, ISP,
> transparent proxy) can read the token and download the file — and
> for `--single` links, an interceptor can claim the one-and-only
> download before the intended recipient. `pasla` is designed to be
> directly internet-facing, so **enable `--https` whenever the
> recipient is not on your local trusted network.** Plaintext HTTP is
> only appropriate for loopback or a fully trusted LAN.

`pasla` ships with two TLS modes:

1. **Ephemeral self-signed** (default for `--https`).  Quick, zero-setup,
   browser shows a warning that the operator must verify out-of-band.
2. **Bring your own certificate**.  Use a CA-issued cert (Let's Encrypt,
   internal corporate CA, etc.) so recipients see no warning.

### Ephemeral self-signed

```bash
pasla report.pdf --https
```

`--https` runs `openssl req -x509 -newkey ec -pkeyopt
ec_paramgen_curve:prime256v1 …` to generate a fresh ECDSA P-256
certificate, then wraps the listener in `ssl.SSLContext(PROTOCOL_TLS_SERVER)`
with TLS 1.2 minimum and `ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20`
ciphers.

The certificate fingerprint is printed in the startup banner — verify
it out-of-band so the recipient can ignore the browser's "self-signed"
warning safely.

Cert and key live in `REGISTRY_DIR/pasla_<id>_tls/`, mode `0o600`,
removed on clean shutdown.  A hard kill leaves them on disk; the next
`pasla list` invocation reaps them.

### Bring your own certificate

If you already have a CA-issued cert for a domain you control, point
`pasla` at it directly:

```bash
pasla report.pdf 60 1 \
    --tls-cert /etc/letsencrypt/live/share.example.com/fullchain.pem \
    --tls-key  /etc/letsencrypt/live/share.example.com/privkey.pem
```

Both flags must be supplied together (a single one is a configuration
error).  Passing them implies `--https`; no ephemeral generation
happens, no `pasla_<id>_tls/` directory is created, and pasla never
modifies, copies, or deletes the cert/key files.

The banner reflects the active mode:

```
  TLS         : enabled (user-provided)
  Cert FP     : SHA256:AB:CD:EF:…
  Cert source : /etc/letsencrypt/live/share.example.com/fullchain.pem
  Cert expiry : 2026-08-15 (107 days remaining)
```

If the certificate has fewer than 7 days remaining, pasla prints a
warning; if it has already expired, pasla refuses to start.

#### Encrypted private keys

Pass the password through the environment, never the command line:

```bash
PASLA_TLS_KEY_PASSWORD='hunter2' pasla report.pdf \
    --tls-cert /path/cert.pem --tls-key /path/encrypted.key
```

This keeps the secret out of `ps`, shell history, and container
inspect output.

#### Configuring it once

Drop the paths into your config file and pasla will pick them up
automatically — no flags needed:

```ini
[tls]
cert = /etc/letsencrypt/live/share.example.com/fullchain.pem
key  = /etc/letsencrypt/live/share.example.com/privkey.pem
```

After this, `pasla report.pdf` alone produces an HTTPS server using
those credentials.  Use `--no-https` to opt out for a single run
without editing the config.

#### Permissions: reading Let's Encrypt files as a non-root user

By default LE installs `privkey.pem` as `root:root` mode `600`, so
pasla running as your normal user cannot read it.  The cleanest fix
is a POSIX ACL:

```bash
sudo setfacl -m u:$(whoami):r \
    /etc/letsencrypt/live/share.example.com/privkey.pem
```

LE renews the symlink-pointed file every 90 days, so the ACL grant
needs to be re-applied through a deploy hook.  Drop a one-liner into
`/etc/letsencrypt/renewal-hooks/deploy/pasla-acl.sh`:

```bash
#!/bin/sh
setfacl -m u:share:r "$RENEWED_LINEAGE/privkey.pem"
```

(Replace `share` with the user pasla runs as.)  Alternatively, copy
the renewed key to a pasla-owned path inside the renewal hook —
duplication, but no ACL plumbing.

#### Renewal during long-running daemons

Pasla loads the cert into the `SSLContext` at startup; subsequent
on-disk renewals are not picked up automatically.  For sessions that
might outlive a renewal window, restart the daemon after each
renewal:

```bash
pasla stop --all && pasla -d <args>
```

For typical session lengths (minutes to hours), this is a non-issue.

---

## Security model

### Threat model

`pasla` is designed for the case where:

- The operator runs the binary on a machine they control.
- A token-bearing URL is shared out-of-band with one or more
  recipients over a (potentially hostile) network.
- The server is exposed directly to the internet, with **no** trusted
  reverse proxy in front of it (unless `--trust-proxy` is enabled).
- Other local users on the same host are *not* trusted with the
  process state, *but* are assumed not to share the operator's UID.

### Update notifications

On startup `pasla` checks once per 24 hours whether a newer release
exists — a single HTTPS `GET` of a tiny `VERSION` file from
`raw.githubusercontent.com/Fix3dll/pasla`.  If an update is available it
logs a one-line notice; **nothing is downloaded or installed and there
is no auto-update**.  This is the only outbound request `pasla` makes
that is not needed to serve your file.  Disable it by setting
`check = false` under `[update]` in your config file (see
[`.pasla.example`](.pasla.example)).

### What is protected

- **Token entropy** — 128-bit `secrets.token_urlsafe(16)` + constant-time
  comparison (`hmac.compare_digest`).  Brute force is infeasible; 5 wrong
  attempts from one IP triggers a session-permanent ban.
- **Path traversal** — strict UTF-8 percent-decode → null-byte reject →
  backslash-to-slash → `posixpath.normpath` → constant-time compare.
  Each step is a regression test.
- **TOCTOU / symlink swap** — the served file's identity tuple
  (`st_dev`, `st_ino` on POSIX, NTFS file index on Windows) is captured
  at startup and re-checked on every request.  `O_NOFOLLOW` is used on
  POSIX.  A swapped path returns `500`.
- **Slowloris** — every connection has a hard wall-clock header
  deadline (`HEADER_READ_TIMEOUT`, default 10 s).  A single background
  reaper closes any connection that misses its deadline with
  `shutdown(SHUT_RDWR)` — one shared thread for all connections rather
  than a timer thread per connection.  During the body transfer phase,
  each 256 KB chunk must be fully sent within `TRANSFER_STALL_TIMEOUT`
  (default 60 s); slow-reading clients that trickle-acknowledge to
  hold threads indefinitely are disconnected.
- **Connection floods** — `MAX_GLOBAL_CONNECTIONS` (default 100) is
  checked *before* the worker thread is spawned.  Refused connections
  receive a TCP RST (`SO_LINGER {1, 0}`) so they skip `TIME_WAIT`.
  Per-IP cap (`MAX_CONNECTIONS_PER_IP`, default 20) is enforced inside
  the worker thread before any header bytes are read; a connection
  exceeding the cap is dropped with a TCP RST without consuming
  request-handling resources beyond the initial thread allocation.
- **Brute force** — sliding-window rate-limit
  (`RATE_LIMIT_MAX_REQUESTS` / `RATE_LIMIT_WINDOW`, default 20 req /
  60 s per IP), bounded `MAX_TRACKED_IPS` table with LRU eviction,
  bounded `MAX_BANNED_IPS` ban list with LRU eviction.  A request
  carrying the correct URL token is a genuine download: it is exempt
  from the request-rate limit so resumable and multi-segment
  downloads are never throttled.  A token mismatch only counts toward
  the ban threshold when the path has the same shape as the real URL
  (an actual token guess) — browser noise such as `/favicon.ico`
  returns `404` but never bans a legitimate visitor.  Unsupported HTTP
  methods (`POST`, `PUT`, `DELETE`, …) return `405`, but are first run
  through the rate-limit and per-IP connection gates — a `429` is
  returned instead of `405` once the window is full, so they cannot be
  used to churn requests unbounded.
- **Information leakage** — `Server: pasla` (no version), no
  `sys_version`, no traceback on client RST, invalid path log
  redacted to a SHA-256 fingerprint of the requested path.
- **Local privilege isolation** — `REGISTRY_DIR` is UID-suffixed and
  `0o700`; ownership verified before write.  Registry JSON, log,
  cert, and key files are all `0o600` on POSIX (`fchmod` on the
  `mkstemp` fd, race-free against the umask).  On Windows the same
  restriction is applied via `icacls /inheritance:r /grant`.
- **Control plane** — bound exclusively to `127.0.0.1`, accept loop
  rejects non-loopback peers, shared-secret authentication via
  constant-time compare, command whitelist, message size cap, per-
  connection timeout.  On Windows the bind uses
  `SO_EXCLUSIVEADDRUSE` to prevent same-port hijack.
- **TLS** — TLS 1.2 minimum, ECDHE/AESGCM/CHACHA20 only, ephemeral
  ECDSA P-256 cert, 0o600 key file, fingerprint published.

### What is **not** protected

These are explicit non-goals:

- **Same-UID attackers** — anyone running as the same user can read
  the registry JSON (and therefore `ctrl_secret`) and stop the
  server.  Use a dedicated service user if this matters.
- **Resolver MitM** — the public-IP resolvers (`api.ipify.org`,
  `ident.me`, `icanhazip.com`) are HTTPS but not certificate-pinned;
  a network attacker can lie about your public IP, causing the
  banner to advertise the wrong URL.  Inspect the URL before
  sharing it.
- **`--trust-proxy` directly internet-facing** — when this flag is
  on, an attacker can spoof `X-Forwarded-For` to skirt rate-limits
  and bans on the *XFF* identity.  `pasla` mitigates this by also
  banning the socket peer after `BAN_THRESHOLD` failures and by
  applying separate aggregate caps to the proxy IP, but the only
  fully safe deployment is behind a real proxy that strips/rewrites
  the header.
- **Capped server availability under token leak** — once a token
  has been disclosed, anyone holding it can drain the
  `max_downloads` budget by making partial downloads (any byte
  delivered consumes a slot, by design — this is what stops
  bandwidth-burning).  Treat URL leakage as game-over.

### `--trust-proxy` checklist

Only enable `--trust-proxy` when **all** of the following hold:

1. There is a real reverse proxy (Nginx, Cloudflare, ALB, …) in front
   of `pasla`.
2. That proxy **rewrites** `X-Forwarded-For` (does not append the
   client-supplied value blindly).
3. `pasla` is bound on a loopback or internal interface so clients
   cannot reach it without going through the proxy.
4. You're combining `--trust-proxy` with `--allow-ip` set to the
   proxy's network range (so the socket-peer allowlist also fires).
5. If the edge provider sets a single-value header (Cloudflare →
   `CF-Connecting-IP`, Fastly → `Fastly-Client-IP`, Fly.io →
   `Fly-Client-IP`, Nginx → `X-Real-IP`), pass it via
   `--trust-header` so pasla reads that header instead of XFF.
   Without `--trust-header`, only XFF (rightmost) is used.

---

## Configuration

### Config file

Optional INI file, read-only, never created or modified by `pasla`.

| Platform | Path |
|---|---|
| POSIX | `~/.config/pasla` |
| Windows | `%USERPROFILE%\.pasla` |
| Override | `PASLA_CONFIG=/some/path` |

See [`.pasla.example`](.pasla.example) for a fully commented config
template with every option documented.  Quick start:

```bash
# POSIX
cp .pasla.example ~/.config/pasla

# Windows (PowerShell)
Copy-Item .pasla.example $env:USERPROFILE\.pasla
```

```ini
[server]
duration = 30
max_downloads = 5
port = 8080

[security]
trust_proxy = false
# trust_header = CF-Connecting-IP

[tls]
https = false
# cert = /etc/letsencrypt/live/share.example.com/fullchain.pem
# key  = /etc/letsencrypt/live/share.example.com/privkey.pem
```

### Environment overrides

The variables below are environment-only: they have no CLI flag and no
config-file key.  Each resolves as `PASLA_<NAME>` environment variable
> built-in default.

| Variable | Default | Purpose |
|---|---|---|
| `PASLA_CONFIG` | — | Override config-file path. |
| `PASLA_TLS_KEY_PASSWORD` | — | Decrypt an encrypted PEM private key (used with `--tls-key`). |
| `PASLA_SOCKET_TIMEOUT` | `30` | Per-connection socket timeout (s). |
| `PASLA_HEADER_READ_TIMEOUT` | `10` | Header parse deadline (s). |
| `PASLA_TRANSFER_STALL_TIMEOUT` | `60` | Per-chunk send deadline (s); slow-read defence. |
| `PASLA_MAX_GLOBAL_CONNECTIONS` | `100` | Total active connections cap. |
| `PASLA_MAX_CONNECTIONS_PER_IP` | `20` | Per-IP concurrent cap. |
| `PASLA_MAX_REQUESTS_PER_PROXY_IP` | `200` | Aggregate proxy-peer rate cap. |
| `PASLA_MAX_CONNECTIONS_PER_PROXY_IP` | `100` | Aggregate proxy-peer concurrent cap. |
| `PASLA_RATE_LIMIT_WINDOW` | `60` | Rate-limit window (s). |
| `PASLA_RATE_LIMIT_MAX_REQUESTS` | `20` | Requests per window per IP. |
| `PASLA_BAN_THRESHOLD` | `5` | Wrong-token attempts before ban. |
| `PASLA_MAX_BANNED_IPS` | `10000` | Ban list cap (LRU). |
| `PASLA_MAX_TRACKED_IPS` | `50000` | Rate-/failure-track cap (LRU). |
| `PASLA_CHUNK_SIZE` | `262144` | Streaming buffer (bytes). |

pasla has two independent configuration tracks — there is no single
linear precedence chain:

- **Serving options** (`duration`, `max_downloads`, `port`, `ip_mode`,
  `trust_proxy`, `trust_header`, `https`, `cert`, `key`) — set via CLI
  flags or the config file above: **CLI argument > config file >
  built-in default**.  These have *no* environment-variable override.
- **Tuning constants** (the `PASLA_*` table above) — set only via the
  environment: **environment variable > built-in default**.  These
  have *no* CLI flag and *no* config-file key.

---

## Examples

### Share a build artefact with QA

```bash
pasla --https --single --allow-ip 10.0.0.0/8 build.tar.zst 60
```

TLS, single-use link, restricted to the corporate network.  Banner
prints the cert fingerprint; QA verifies it out-of-band.

### Drop a file on an isolated host

```bash
pasla -p 8080 -4 --allow-ip 192.168.42.0/24 image.qcow2 240 1
```

Bind to a known port, IPv4 only, restricted to the lab VLAN, valid
for 4 hours, single use.

### Hand the world file to a player from a game server

```bash
# Stop the game server first so the world isn't mid-write,
# then hand pasla the directory.  It auto-archives and detaches.
pasla -d --https --single --allow-ip 10.0.0.0/8 worlds/ 30
```

The server already produced the artefact (a game-world snapshot, a
save, a generated config, an export from any service it hosts).
The admin only needs to *pass it* to one specific player or
co-admin who will run the world locally.  Token URL goes in chat,
link self-destructs after the first download or 30 minutes,
whichever comes first.

The same pattern fits any "the server made this, hand it off"
workflow: nightly backup snapshot, generated PDF report, build
artefact from a long-running CI runner, packet capture from a
diagnostic session.

### Cron-driven nightly transfer

```bash
JSON=$(pasla -d --json --allow-ip 10.0.0.0/8 backup.tar.gz 30 1)
URL=$(echo "$JSON" | jq -r '.url_ipv4')
curl -fsSL --output /backups/today.tar.gz "$URL"
```

`--json` emits one line, machine-parseable; `--dry-run` lets you
validate the call before launching the server.

### Behind nginx

```nginx
location /share/ {
    proxy_pass         http://127.0.0.1:47391/;
    proxy_set_header   X-Forwarded-For $remote_addr;   # rewrite, don't append
    proxy_set_header   Host            $host;
    proxy_buffering    off;
    proxy_request_buffering off;
}
```

```bash
pasla -p 47391 --trust-proxy --allow-ip 127.0.0.1/32 file.zip
```

The `proxy_buffering off` directives matter — without them nginx
buffers the streamed body and breaks resumable downloads on
multi-GB files.

### Resumable multi-GB download

No flags needed.  `pasla` always advertises `Accept-Ranges: bytes` and
implements `206 Partial Content` correctly.  `curl -C -` Just Works™.

```bash
curl -C - -o video.mkv 'https://203.0.113.5:47391/<token>/video.mkv'
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                            pasla                                │
│                                                                 │
│   CLI                                                           │
│    │                                                            │
│    ▼                                                            │
│   parse_and_validate ──► cmd_serve ────────────┐                │
│                          cmd_list   ──┐        │                │
│                          cmd_stop   ──┤        │                │
│                          cmd_detach ──┤        │                │
│                                       │        │                │
│                                       ▼        ▼                │
│                              ┌──────────────────────────────┐   │
│                              │   DualStackHTTPServer        │   │
│                              │   (ThreadingMixIn,           │   │
│                              │    daemon_threads=False)     │   │
│                              └──────────────────────────────┘   │
│                                       │        │                │
│                                       │        │                │
│                       ┌───────────────┘        └────────────┐   │
│                       ▼                                     ▼   │
│              SecureHandler (per-conn)             Control plane │
│              ├─ pre-thread global cap             (127.0.0.1    │
│              ├─ header deadline (slowloris)        TCP, JSON)   │
│              ├─ ban / rate / cap gates            ├─ status     │
│              ├─ path normalize + token cmp        └─ stop       │
│              ├─ identity check + open(O_NOFOLLOW)               │
│              ├─ Range parse + send headers                      │
│              └─ stream (readinto, 256 KB chunks)                │
│                                                                 │
│   Background daemon threads:                                    │
│     ├─ maintenance       (header reaper, time-limit watchdog,   │
│     │                     ctrl-plane watchdog, state cleanup,   │
│     │                     graceful shutdown)                    │
│     ├─ status-bar        (foreground TUI redraw)                │
│     └─ ctrl-plane        (accept loop)                          │
│                                                                 │
│   Locks (independent, never nested):                            │
│     security_lock  → banned_ips, failed_attempts                │
│     rate_lock      → request_log, active_connections,           │
│                       global_connections                        │
│     transfer_lock  → download_count, bytes_transferred,         │
│                       active_transfers, download_history        │
│     reaper_lock    → _header_deadlines (slowloris reaper)       │
└─────────────────────────────────────────────────────────────────┘

Per-instance disk artefacts (under $TMPDIR/pasla_registry_<uid>/):

   pasla_<id>.json      ← registry pointer (pid, ctrl_port, ctrl_secret)
   pasla_<id>.log       ← daemon mode only
   pasla_<id>_tls/      ← --https only (cert.pem + key.pem, 0o600)
   .tmp_<hex>/          ← directory-share tar workspace
```

`pasla list` and `pasla stop` reach instances over the loopback
control plane (PID liveness check + authenticated TCP/JSON), and
sweep orphaned artefacts whose registry entry is gone.

---

## Performance and limits

- **Streaming** — `bytearray(CHUNK_SIZE)` allocated per request,
  `readinto()` over a `memoryview` slice; no full-file load, no
  `sendfile` dependency, multi-TB tested.
- **TTFB** — under 100 ms on loopback for a typical request.
- **Concurrency** — one OS thread per request.  Periodic work (header
  reaper, watchdogs, state cleanup) shares a single `maintenance`
  thread instead of spawning a timer per connection.  Default global
  cap is 100; per-IP cap 20.
- **HEAD requests** — answered without reserving a download slot,
  so metadata probes (file size, digest, content type) never
  count against `max_downloads`.
- **Lock granularity** — three independent locks, each held only for
  the minimum window needed.  Status bar reads are snapshotted
  outside the bar lock so log emit never serialises against transfer
  threads.
- **Free-threaded Python** — runs unchanged under `python3.14t`;
  lock-protected access patterns are explicit and audited.

---

## Cross-platform notes

| Concern | Linux | macOS | Windows |
|---|---|---|---|
| SIGTERM | reliable | reliable | best-effort (Python translates a few signals; `taskkill /F` still bypasses cleanup) |
| Ctrl+Break / SIGBREAK | n/a | n/a | wired to graceful shutdown |
| ANSI / OSC 8 | native | native | auto-enabled on Win10+ via `SetConsoleMode` |
| Dual-stack bind | yes | yes | Vista+ |
| `O_NOFOLLOW` | yes | yes | not available — TOCTOU defence relies on the identity check only |
| `os.fchmod` registry write | yes | yes | no-op (ACL via `icacls` instead) |
| Control-plane bind | `SO_REUSEADDR` | `SO_REUSEADDR` | `SO_EXCLUSIVEADDRUSE` |
| `pid_is_alive` | `os.kill(pid, 0)` | same | `OpenProcess` + `GetExitCodeProcess` via `ctypes` |
| File index for identity | `st_ino` | `st_ino` | `st_ino` (3.12+) or `GetFileInformationByHandle` (<3.12) |

When in doubt, run `pasla --dry-run --json some/file 60 1` first — it
exercises every platform-conditional path except the actual server
loop.

---

## Development

```bash
git clone https://github.com/Fix3dll/pasla.git
cd pasla
python -m pytest -q
python -m pytest --cov=. --cov-report=term-missing
python -c "import py_compile; py_compile.compile('pasla', doraise=True)"
```

The test suite lives in `tests/`:

| File | Scope | Server required |
|---|---|---|
| `test_unit.py` | pure functions, TUI, slot lifecycle | no |
| `test_integration.py` | end-to-end HTTP against a real threaded server | yes (port 0) |
| `test_platform.py` | OS-specific behaviour, signal handlers, registry | mixed |
| `conftest.py` | shared fixtures, autouse state reset | n/a |

Contribution rules and codebase conventions are documented in
[`AGENTS.md`](AGENTS.md): single-file, zero-deps, no nested locks,
no `time.sleep` in tests, narrow exception clauses.

---

## Limitations and known constraints

- **Daemon SIGKILL** — the registry file, log file, temp archive, and
  TLS material are removed lazily by the next `pasla list` /
  `pasla stop` invocation, not immediately.  This is intentional;
  there is no filesystem watcher.
- **Bans are session-permanent** — `banned_ips` is not time-decayed.
  For an instance whose maximum lifetime is `duration` minutes, a
  time-based expiry would only kick in after the server had already
  shut down.
- **DualStack fallback is silent** — if the kernel does not report
  dual-stack support, or if the IPv6 bind fails at runtime (e.g.
  `sysctl net.ipv6.conf.all.disable_ipv6=1`), `pasla` falls back to
  IPv4 and logs a warning.  No exception escapes.  Use `-4` to skip
  the probe entirely.
- **Instance ID is 24 bits** — `secrets.token_hex(3)`, ~16 M space.
  Birthday collision around 4 K live instances; not a concern for
  realistic operator workloads.
- **TLS validity is 365 days** — the cert is ephemeral in the sense
  that it is cleaned on shutdown, but the validity window is long
  so a SIGKILL-leaked key remains technically valid until the next
  `pasla list`.
- **Resolver no cert pinning** — see Security model.
- **Capped server availability under token leak** — see Security
  model.

---

## License

`pasla` is licensed under the **GNU Affero General Public License v3.0**.
See [`LICENSE.md`](LICENSE.md) for the full text.
