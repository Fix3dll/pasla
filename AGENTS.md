# AGENTS.md

## 1. Project Identity and Purpose

**Definition:** `pasla` — single-file, zero-dependency, security-hardened ephemeral file-sharing CLI tool. Serves a single file or directory (auto-archived as tar) over HTTP with a time-limited, token-protected URL.
* **Target Audience:** Developers, system administrators, and DevOps engineers needing instant, ad-hoc file transfers across networks.
* **Problem Solved:** Securely sharing files across networks without relying on third-party cloud storage (e.g., Google Drive, WeTransfer) or complex configurations (FTP, SCP, SMB).
* **Environment:** Production (directly internet-facing, no reverse proxy assumed).
* **Success Criteria:**
  - 0 external dependencies (Python standard library only).
  - 100% functionality parity across Windows, Linux, and macOS.
  - Time-to-first-byte (TTFB) < 100ms.
  - 0 resource leaks (no zombie processes, orphaned temp files, or stale registry entries).

---

## 2. Architecture Overview

* **Architectural Pattern:** Monolithic script, layered via code comment rulers.
* **Components and Responsibilities:**
  - `CLI Parser`: Argument extraction and validation.
  - `ThreadingHTTPServer`: Binds IPv4 and IPv6 transparently.
  - `SecureHandler`: Request validation, security enforcement (rate limiting/bans), and chunked file transfer.
  - `Control Plane`: Loopback-bound TCP socket server for IPC (`status`, `stop`).
  - `StatusBar`: Foreground live terminal UI renderer.
  - `Daemon logic`: Background process management and registry tracking.
* **Data Flow:** CLI Invocation -> Arguments Parsed -> Route to Subcommand (serve, list, stop) -> HTTP Server / Control Plane / UI.
* **Synchronous / Asynchronous:** Synchronous threaded architecture (`ThreadingMixIn`) with exactly one thread per HTTP request. Concurrency state is protected by explicit atomic locks (`security_lock`, `rate_lock`, `transfer_lock`, `reaper_lock`).
* **Critical Technical Decisions:**
  - **Chunk-based UI tracking:** Avoided `sendfile()` in favor of `bytearray()` + `readinto()` to enable real-time UI byte tracking and cross-platform compatibility (Windows lacks robust `sendfile`).
  - **Shared Memory IPC:** Used JSON files (`$TMPDIR`) plus loopback TCP instead of complex memory-mapped files for cross-process communication.
* **Scalability Approach:** Vertical scaling. Performance relies on OS thread scheduling and Python's (eventual) free-threaded mode (3.14t).

```text
[CLI Invocation] -> [Parse Args]
       |
       +---> cmd_serve --> [Threaded HTTP Server] <==> [Client Requests]
       |                   |-- [Transfer Core]
       |                   +-- [Foreground TUI]
       |
       +---> cmd_list  --> [IPC: TCP Loopback] <==> [Target Daemon]
       |
       +---> cmd_stop  --> [IPC: TCP Loopback] <==> [Target Daemon]
```

---

## 3. Technology Stack

* **Backend:** Python Standard Library
  * **Version:** 3.9+ (3.14 recommended)
  * **Why:** The sole fundamental requirement of this project is absolute zero dependencies.
  * **Alternatives Rejected:** FastAPI, Flask, aiohttp (all require `pip install`).
* **Frontend:** ANSI Escape Sequence TUI
  * **Version:** Terminal Native
  * **Why:** Cross-platform CLI compatibility without compiling dependencies.
  * **Alternatives Rejected:** `curses` (lacks native Windows support), `rich` (external dependency).
* **Database:** Temporary JSON Registry files
  * **Version:** Standard Library `json`
  * **Why:** Lightweight, human-readable transient state tracking.
  * **Alternatives Rejected:** SQLite (overkill, creates locking complexities for ephemeral scripts).
* **Cache:** None
* **Message Queue:** None
* **LLM / AI Components:** None
* **CI/CD:** GitHub Actions (active — see `.github/workflows/ci.yml`)
  * **Why:** Standard, integrates natively with repository for cross-platform test matrix.
* **Containerization:** None

---

## 4. Coding Rules (Mandatory Standards)

* **Naming Rules:** Use `UPPER_SNAKE_CASE` for configuration constants. Use `snake_case` for variables and functions. Use `PascalCase` for classes. Prefix internal functions/variables with `_`.
* **File Organization:** ALL application code MUST reside in the single `pasla` file. Code MUST be organized sequentially, separated by `# ---------------------------------------------------------------------------` rulers.
* **Layer Dependency Rules:** Global utility functions MUST NOT call class instance methods.
* **SOLID / Clean Code:** Functions MUST have a single responsibility. Cleanup operations MUST be explicitly defined and guaranteed via `finally` blocks.
* **Logging Standard:** Use the standard `logging` module via the `LOG_FORMAT` / `LOG_DATEFMT` module-level constants.
  - Use `log.info` for normal operational flow.
  - Use `log.warning` for security violations or fallback actions.
  - Use `log.error` for fatal faults.
  - Use `log.debug` for cleanup failure diagnostics inside `finally` blocks.
  - Use `print()` ONLY for direct user output (interactive prompts, compression progress with `\r` overwrite, startup banners). Do NOT use `print()` for anything that should be logged.
* **Exception Handling:**
  - Always wrap cleanup steps in `finally` blocks with independent `try/except` statements inside them.
  - Target explicit exceptions (`OSError`, `PermissionError`). NEVER introduce bare `except:` blocks.
  - Suppressed exceptions in `finally` blocks MUST be logged via `log.debug(..., exc_info=True)`, never silently swallowed with `pass`.
* **Never Do These Actions:**
  - DO NOT add external `pip` dependencies.
  - DO NOT split the script into multiple files.
  - DO NOT nest `security_lock`, `rate_lock`, `transfer_lock`, or `reaper_lock`. Each lock protects an independent group of variables. Acquiring more than one simultaneously is a deadlock risk and is unconditionally prohibited.
  - DO NOT expose the control plane off localhost (`127.0.0.1`).
  - DO NOT introduce `time.sleep()` in test code. Use `time.monotonic` mocking or `threading.Event.wait()` with short timeouts instead.

---

## 5. AI Agent Behavior Rules

* **New File Creation:** You MUST NOT create new source code files for application logic. All business logic goes into `pasla`. Test files go into `tests/`.
* **Modifying Existing Files:** You MUST execute `python -c "import py_compile; py_compile.compile('pasla', doraise=True)"` to check syntax after EVERY code modification.
* **Refactoring Rules:** You MUST strictly preserve backward compatibility for CLI arguments. You MUST NOT break Windows behavior to satisfy POSIX patterns, or vice versa.
* **Test Writing:** When adding a new feature or fixing a bug, you MUST write or update the relevant tests in `pytest`.
* **Deprecated API:** You MUST NOT use APIs deprecated in Python 3.9+.
* **Version Compatibility:** You MUST NOT use Python 3.10+ syntax (e.g., `match/case`) as the script targets Python 3.9+. Use `from __future__ import annotations` for union (`|`) types.
* **Planning Requirement:** For architectural changes (networking, concurrency, logging), you MUST present a numbered markdown plan and wait for USER approval before writing code.
* **Platform-Specific Code:** When modifying any code path that uses `sys.platform`, `os.name`, `ctypes`, `signal`, or conditional imports, you MUST verify the behavior is correct on **both** POSIX and Win32 before committing. If you cannot test on both, explicitly note the untested platform in a code comment. Common divergence points:
  - `signal.SIGWINCH`, `signal.SIGTERM` — different semantics on Windows
  - `os.chmod` — no-op for permission bits on Windows
  - `os.kill(pid, 0)` — works differently on Windows (use `ctypes.windll.kernel32` path instead)
  - `subprocess.Popen` — `start_new_session` vs `creationflags=DETACHED_PROCESS`
  - Symlink creation — requires elevated privileges on Windows

### Security Control Checklist

When modifying security-relevant code, verify every item below. This is not optional.

1. **Token comparison timing safety:** All path/token comparisons MUST use `hmac.compare_digest()` to prevent timing side-channels. Direct `==` comparison on tokens or URL paths is a vulnerability.
2. **X-Forwarded-For isolation:** `X-Forwarded-For` MUST be read ONLY when `trust_proxy=True` (a closure parameter set at handler creation time, not a runtime global). The **rightmost** entry is used (standard secure choice per RFC 7239).
3. **Path traversal defense:** Incoming paths go through strict UTF-8 `unquote` (rejects over-long encodings such as the `%c0%ae` form of `..`), null byte rejection, backslash-to-slash conversion, `posixpath.normpath`, then `hmac.compare_digest` against the expected path. ALL five steps are required. Removing any one of them opens a traversal vector.
4. **Lock acquisition order:** `security_lock`, `rate_lock`, and `transfer_lock` MUST NEVER be nested. Each protects an independent variable group. A function that holds one lock MUST NOT acquire another.
5. **Registry file integrity:** Registry JSON files are written atomically via `tempfile.mkstemp` + `os.replace`. The `write_registry` function uses a `closed` flag to prevent double `os.close()` on error paths. Do not simplify this pattern.
6. **Control plane authentication:** The control plane binds exclusively to `127.0.0.1`. The accept loop additionally verifies `addr[0] == "127.0.0.1"` and rejects non-loopback connections. Both checks are required — removing either one is a vulnerability.
7. **Response header hygiene:** `server_version = "pasla"` (without version number) and `sys_version = ""` suppress Python and pasla version leakage in HTTP response headers. The version is intentionally omitted from HTTP responses to prevent targeted attacks based on fingerprinting a specific release. Version tracking is maintained internally via the control plane `get_status()` response and `--json` output. The empty `log_message()` and `log_request()` overrides suppress default `BaseHTTPRequestHandler` stderr output. Do not revert these.
8. **Connection teardown under partial reads:** The control plane caps inbound messages at `CTRL_MAX_MESSAGE_BYTES` and enforces `CTRL_TIMEOUT` per connection. `SecureHandler.setup()` sets `SOCKET_TIMEOUT` on every connection socket to prevent slowloris attacks. Removing these timeouts is a DoS vector.
9. **Global connection cap:** `_try_increment_global_connections()` is checked in `process_request()` BEFORE a worker thread is spawned. Connections at cap are hard-dropped via `request.close()` without creating a thread or reading any data. If thread creation fails (`RuntimeError: can't start new thread`), the counter is decremented in a `try/except` block before re-raising. This is the DDoS pre-filter — it must remain the first check.
10. **Variable leak prevention:** Mutable shared state (`banned_ips`, `failed_attempts`, `request_log`, `active_connections`, `download_count`, `completed_downloads`, `bytes_transferred`, `global_connections`, `active_transfers`) MUST only be accessed while holding the corresponding lock.

---

## 6. Test Strategy

### Test Organization

| File | Scope | Server Required | Key Rule |
|---|---|---|---|
| `test_unit.py` | Pure function tests, TUI components | No | No I/O, no network, no subprocess |
| `test_integration.py` | End-to-end HTTP tests | Yes (real server) | Uses `live_server` fixtures from conftest |
| `test_platform.py` | OS-specific behavior | Mixed | Platform-conditional `@pytest.mark.skipif` |
| `conftest.py` | Shared fixtures, state reset | N/A | Single `_start_server()` helper, no hotswap |

### Server Fixtures

Integration tests spin up a **real** `ThreadingHTTPServer` on **port 0** (OS-assigned random port). This is not a mock — it is a full threaded server bound to `127.0.0.1`. Each test gets its own server instance via function-scoped fixtures. The three fixture variants:
- `live_server` — default config (unlimited downloads, trust_proxy=False)
- `live_server_trusted_proxy` — trust_proxy=True
- `live_server_capped` — max_downloads=100

Handler configuration (trust_proxy, max_downloads) MUST be set at server creation time via `_start_server()` parameters. Runtime handler hotswapping (replacing `server.RequestHandlerClass` on a running server) is **prohibited** — it is thread-unsafe with `ThreadingMixIn`.

### State Isolation

The `reset_state` fixture (autouse) clears all mutable global state before and after each test: `download_count`, `completed_downloads`, `bytes_transferred`, `global_connections`, `banned_ips`, `failed_attempts`, `request_log`, `active_connections`, `active_transfers`, `download_history`, and `shutting_down`. It also resets `ALLOWED_ROOT` to the current working directory and snapshots/restores the `pasla` logger's handlers and `propagate` flag, so foreground/TUI tests that mutate the logger cannot leak that state into later tests.

### Timing-Sensitive Tests

- MUST NOT use `time.sleep()` for synchronization. Use `threading.Event.wait(timeout)` or `monkeypatch` `time.monotonic`.
- For tests that depend on elapsed time (e.g., `_fmt_remaining`), add a buffer of ≥1s to the target duration to absorb execution drift between setup and assertion.
- For timeout tests (e.g., slowloris protection), `monkeypatch` the timeout constant to ≤2s to keep the test fast.

### Coverage

* **Target:** 85%+ overall line coverage.
* **Measurement:** `pytest --cov=. --cov-report=term-missing`
* **Coverage drop below 85%:** Target only — there is no automated gate (`pyproject.toml` has no `fail_under`, CI has no coverage threshold). Regression below the target is caught by PR review, not enforced by tooling.
* **Untestable regions:** `main()`, `cmd_serve()`, `cmd_detach()`, `cmd_list()`, `cmd_stop()`, and `detect_public_ips()` involve subprocess orchestration, real network I/O, and signal handling. These are excluded from the 85% target but should be covered by integration tests where feasible.

### CI Matrix

# Confirmed against `.github/workflows/ci.yml`.
```yaml
os: [ubuntu-latest, macos-latest, windows-latest]
python-version: ["3.9", "3.12", "3.14"]
```
All three axes MUST pass before merge. Platform-conditional skips (`@pytest.mark.skipif`) are acceptable for genuinely platform-specific tests (e.g., `SIGWINCH`, `os.chmod`).

### Test Naming

Use descriptive names: `test_<function_or_scenario>_<expected_behavior>` (e.g., `test_dead_pid_returns_false`, `test_idle_connection_terminated`).

---

## 7. Security and Data Policy

* **Sensitive Data Definition:** Client public IP addresses, absolute paths of shared files, URL access tokens, and the raw content of shared files.
* **Unloggable Data:** You MUST NOT log file payloads, HTTP request bodies, or URL tokens.
* **Encryption Rules:** Authentication tokens MUST be generated via cryptographically secure RNG (`secrets.token_urlsafe`). String comparisons of paths/tokens MUST utilize constant-time comparison (`hmac.compare_digest`).
* **Rate Limiting:** Enforce a hard cap of `MAX_GLOBAL_CONNECTIONS` (100) active connections globally. Enforce per-IP connection limits (`MAX_CONNECTIONS_PER_IP`). Ban IPs after `BAN_THRESHOLD` (5) failed token attempts. Bans are permanent for the lifetime of the server instance.
* **Input Validation:** All incoming HTTP paths MUST be aggressively sanitized: strict UTF-8 `unquote` → null byte rejection → backslash-to-slash conversion → `posixpath.normpath` → `hmac.compare_digest` against expected path. This is a fixed pipeline — do not reorder or skip steps.
* **OWASP Principles:**
  - Implement robust rate limiting (DDoS mitigation).
  - Loopback-only binding for control interfaces (Security Misconfiguration).
  - Explicit and immediate resource release upon connection drops (Resource Exhaustion).
  - `Cache-Control: no-store` and `X-Content-Type-Options: nosniff` on all file responses.

---

## 8. Performance Policy

* **Maximum Response Time:** Time-to-first-byte (TTFB) MUST remain under 100ms on loopback interfaces.
* **Maximum Memory Usage:** Memory footprint per active connection MUST remain bounded to the buffer size (`CHUNK_SIZE`, exactly 256 KB). The script MUST NEVER load entire files into memory.
* **Maximum CPU Usage:** Uses plain uncompressed tar (`tarfile.open(..., 'w')`) for directory archiving — no compression overhead. Buffer transfers MUST use zero-copy `readinto()` over memory views where applicable.
* **Large Data Processing:** Indefinitely scale to multi-terabyte files by maintaining strictly streaming I/O loops.
* **Cache Invalidation Strategy:** Not applicable; zero cache architecture.

---

## 9. Versioning and Branch Strategy

* **Git Branch Model:** Trunk-Based Development. All commits land in `main` or short-lived feature branches (< 1 day lifetime).
* **Commit Message Format:** `<type>(<scope>): <subject>` (e.g., `fix(security): resolve timing attack in path matching`).
* **Versioning (CalVer):** The scheme is `YYYY.MINOR.MICRO` (e.g. `2026.1.0` — the first feature release of 2026). The repo-root `VERSION` file is the single source of truth; the `__version__` constant in `pasla` MUST match it and a consistency test enforces that. The version is exposed via `pasla -v` / `--version`, the control plane `get_status()`, and `--json` output. The HTTP `Server` header intentionally omits the version number (`server_version = "pasla"`) to prevent fingerprinting — see Security Control Checklist item 7.
* **Breaking Change Policy:** The CLI argument interface (`file`, `duration`, `max_downloads`, `-d`, `-v`/`--version`, `-4`, `-6`, `--trust-proxy`, `list`, `stop`) MUST NOT break. Internal background flags (e.g., `--_daemon`, `--_instance_id`, `--_temp_tar`) are exempt and may be refactored freely.

### PR and Merge Rules

# inferred — confirm with maintainer
* Feature branches require a PR to `main`. Direct pushes to `main` are acceptable ONLY for single-commit fixes (typos, comment updates, version bumps).
* A PR MUST NOT be merged until:
  1. `pytest` passes on all CI matrix entries (all OS × Python version combinations).
  2. No new bare `except:` blocks are introduced.
  3. No new lock nesting violations are introduced (verifiable via grep for lock acquisition patterns).
  4. Control plane remains bound to `127.0.0.1` only.
* Direct Commit is acceptable for: comment-only updates, version string bumps, `AGENTS.md` / `README.md` updates.

### Release Checklist

1. Bump the `VERSION` file and the `__version__` constant in `pasla` together — the consistency test fails if they drift. Verify the new value appears in `pasla --version` and the control plane `get_status()` response.
2. Update `CHANGELOG.md` (if exists) or create a git tag with release notes.
3. Verify `pytest` passes on all CI matrix entries.
4. Verify CLI help output (`pasla --help`, `pasla list --help`, `pasla stop --help`) reflects any argument changes.
5. Tag the release: `git tag -a vX.Y -m "Release vX.Y"`.

---

## 10. Done Definition

A given task is considered complete ONLY when ALL of the following are true:

1. `python -c "import py_compile; py_compile.compile('pasla', doraise=True)"` passes gracefully.
2. `pytest` passes with 0 failures on the local platform.
3. Changes function identically on Windows and Linux/macOS. If you modified a platform-specific code path, you MUST note which platforms were tested.
4. No external/third-party dependencies were introduced into the codebase.
5. The single-file distribution paradigm (`pasla` script has no sibling utility modules) is strictly maintained.
6. The TUI correctly functions visually without tearing or freezing.
7. No new bare `except:` blocks were introduced. All exception handlers either target specific exceptions or log via `log.debug(..., exc_info=True)`.
8. All lock nesting rules are respected — no function acquires more than one of `security_lock`, `rate_lock`, `transfer_lock`.
9. The control plane remains bound exclusively to `127.0.0.1` after the change.
10. If the change is user-visible (new feature, changed behavior, new CLI argument), `__version__` is bumped (with the `VERSION` file) and the README reflects the change.
11. No regression in test coverage below the 85% target. # inferred — confirm with maintainer

---

## 11. Observability and Debugging

### Enabling Verbose Logging

Set log level to `DEBUG` for full request lifecycle visibility:
```python
log.setLevel(logging.DEBUG)
```
In daemon mode, logs are written to `REGISTRY_DIR / pasla_<id>.log`. In foreground mode, logs are printed to stderr via `_LiveLogHandler` (which coordinates with the status bar to prevent visual tearing).

### Request Lifecycle Log Points

A complete successful request should produce log entries at these stages:
1. **Connection accepted** — `handle()` increments global + per-IP counters
2. **Request validated** — `validate_and_register_request()` checks ban list, rate limit, connection limit
3. **Path verified** — `hmac.compare_digest` against expected path
4. **Transfer started** — slot reserved via `ensure_slot_reserved()`
5. **Transfer complete** — `release_transfer()` with `completed=True`, download count logged
6. **Graceful shutdown** — if download cap reached, `_request_shutdown()` triggered

If any stage fails, the corresponding error response (400, 403, 404, 410, 416, 429, 503) is logged with the client IP.

### Common Debugging Scenarios

**Server hangs / stops accepting connections:**
1. Check `global_connections` — if it equals `MAX_GLOBAL_CONNECTIONS`, connections are being leaked (not decremented in `finally` block of `process_request_thread()`).
2. Check `shutting_down.is_set()` — if True, the server is in graceful shutdown mode and will return 503 for new requests.
3. Check `daemon_threads` — it MUST be `False`. If `True`, the server kills in-progress transfers on shutdown.

**Stale daemon registry entries:**
- `pasla list` performs a two-phase liveness check: first `pid_is_alive()`, then control plane TCP reachability (`ctrl_status()`). Entries failing either check are auto-cleaned.
- If a process was killed with `SIGKILL` (or `taskkill /F` on Windows), the registry JSON persists because the `finally` block in `cmd_serve()` never runs. `pasla list` handles this case automatically.

**Status bar visual glitches:**
- `_LiveLogHandler` holds `_bar._lock` for the entire clear → log → redraw sequence. If the lock is removed or the sequence is reordered, log messages and the status bar will interleave on stdout.

---

## 12. Known Constraints and Intentional Workarounds

These are sharp edges in the codebase that exist for good reasons. Do not "fix" them without understanding why they exist.

### Daemon Registry Stale on SIGKILL

**What:** If the pasla process is killed with `SIGKILL` (POSIX) or `taskkill /F` (Windows), the `finally` block in `cmd_serve()` does not execute. The registry JSON file (`pasla_<id>.json`) and any temporary archive files persist on disk.

**Why it's acceptable:** `pasla list` and `pasla stop` perform active liveness checks (PID + control plane TCP) and auto-clean stale entries. The orphaned files are tiny (< 1 KB JSON, temp archives in `REGISTRY_DIR`) and are cleaned on next `list` invocation or system reboot (`$TMPDIR` is ephemeral).

**Do not:** Add a filesystem watcher or periodic background sweep. The lazy cleanup on `list` is intentional and sufficient.

### DualStack Bind Fallback

**What:** `_make_server()` checks `socket.has_dualstack_ipv6()` before attempting IPv6 bind. If it returns `False`, the server silently falls back to IPv4 with a warning log. This is a **boolean branch**, not an exception catch.

**Why it was done this way:** `socket.has_dualstack_ipv6()` performs the platform check without attempting a bind. This avoids partially-initialized socket objects that would need cleanup on exception. The `__new__` + manual `__init__` pattern in `_make_server()` exists because `address_family` must be set BEFORE `HTTPServer.__init__()` creates the socket.

**Do not:** Replace the boolean check with a `try/except EAFNOSUPPORT` pattern. Do not remove the `__new__` pattern without understanding the initialization order dependency.

### TUI Renderer on Narrow Terminals

**What:** `_draw_unlocked()` truncates the status bar with `…` if it exceeds `os.get_terminal_size().columns`. On terminals narrower than ~20 columns, the bar degrades to a single character plus ellipsis.

**Why it's acceptable:** Terminals this narrow cannot display useful information regardless of formatting. The truncation prevents line wrapping, which would cause visual tearing on every 1-second redraw cycle.

**Do not:** Add multi-line wrapping for the status bar. It would conflict with the `\r` overwrite mechanism that is fundamental to the single-line bar design.

### Bans Are Permanent Per Session

**What:** `banned_ips` is a `_BannedIPs(OrderedDict)` with set-like API and LRU eviction at `MAX_BANNED_IPS`. Once an IP is banned, it stays banned until the server process exits. `_cleanup_state()` does **not** touch `banned_ips`.

**Why:** For an ephemeral server with a maximum lifetime of `duration` minutes, time-based ban expiry adds complexity without meaningful benefit. The server will shut down before any reasonable ban duration would expire anyway.

**Do not:** Add timestamp-based ban expiry or make `_cleanup_state()` purge banned IPs. If this behavior ever changes, it requires a design discussion, not a quick fix.

### `write_registry` Double-Close Guard

**What:** The `closed` flag in `write_registry()` prevents `os.close(fd)` from being called twice when `os.replace()` fails after the file descriptor was already closed.

**Why:** `os.close()` on an already-closed fd raises `OSError: [Errno 9] Bad file descriptor`. On some platforms, the fd number may have been reused by another thread between the first close and the error handler, causing the wrong file to be closed.

**Do not:** Simplify this to a single `finally: os.close(fd)` block. The two-phase pattern with the `closed` flag is correct.

### Update Check Makes One Outbound Request

**What:** On `serve` startup pasla spawns a background daemon thread that fetches the repo-root `VERSION` file from `raw.githubusercontent.com` (once per 24h, throttled via a cache file in `REGISTRY_DIR`) and logs a notice if a newer release exists. It is opt-out — disabled by setting `check = false` under `[update]` in the config file.

**Why notify-only:** Automatic self-update is intentionally not implemented, for security reasons — pasla only *notifies*, and the user applies the update manually. This is not a categorical rejection; a well-designed auto-update may be added in the future. The checker treats the fetched body as untrusted (size-capped read, strict three-component parsing) and only ever compares and displays it — it never downloads or runs code. TLS validation is left at the stdlib default; the request runs off-thread and never blocks serving, and every failure is swallowed at `log.debug`.

**Do not:** Disable TLS certificate validation or add a custom `ssl` context for the check. Do not let it block the serve path. Do not add a CLI flag or env var to toggle it — disabling is a deliberate, persistent choice the user makes in their own config file.
