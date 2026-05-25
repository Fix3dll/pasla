"""
conftest.py — shared fixtures for the pasla test suite.

Design decisions
────────────────
* pasla has no .py extension — importlib loads it by path.
* All module-level state is reset before each test via the
  `reset_state` fixture so tests are fully independent.
* The `live_server` fixture starts a real ThreadingHTTPServer on
  a random OS-assigned port (port=0) and tears it down after each test.
* Variant fixtures (`live_server_trusted_proxy`, `live_server_capped`)
  use a shared `_start_server` helper — NO runtime handler hotswap.
* Network I/O during unit tests is blocked by monkeypatching
  urllib.request.urlopen to prevent accidental outbound calls in CI.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import socket
import sys
import tempfile
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Generator, NamedTuple

import pytest

# ---------------------------------------------------------------------------
# Module loading
# ---------------------------------------------------------------------------

def _load_pasla():
    """Load the pasla script as a module despite having no .py extension.

    spec_from_file_location() requires the file to have a recognised extension
    on some Python versions.  We use SourceFileLoader directly which works
    regardless of extension.
    """
    import importlib.machinery

    script = Path(__file__).parent.parent / "pasla"
    if not script.exists():
        pytest.skip(f"pasla script not found at {script}")

    loader = importlib.machinery.SourceFileLoader("pasla", str(script.resolve()))
    spec   = importlib.util.spec_from_loader("pasla", loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules["pasla"] = module
    spec.loader.exec_module(module)
    return module


# Load once at collection time.
pasla = _load_pasla()


def ipv6_usable() -> bool:
    """Return True only if the kernel can actually create an AF_INET6
    socket.

    ``socket.has_ipv6`` reports build-time support, which is not the
    same as runtime availability: some environments (e.g. WSL2 with
    IPv6 disabled, hardened containers) build Python with IPv6 yet have
    the address family disabled in the kernel.  IPv6 tests skip on
    those hosts instead of failing.
    """
    if not socket.has_ipv6:
        return False
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.close()
        return True
    except OSError:
        return False


def wait_until(predicate, timeout=3.0, interval=0.02):
    """Block until ``predicate()`` is truthy or ``timeout`` elapses.

    Test code avoids ``time.sleep()`` for synchronisation; this polls
    with ``threading.Event.wait()`` as the tick instead.  Returns the
    final predicate value so callers can assert on the outcome directly.
    """
    deadline = time.monotonic() + timeout
    tick = threading.Event()
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        tick.wait(interval)
    return predicate()


# ---------------------------------------------------------------------------
# State reset
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_state():
    """
    Reset all global mutable state in the pasla module before and after
    each test.  Without this, bans, rate-limit counters, and transfer
    slots bleed between tests.

    The pasla logger is global mutable state too: foreground/TUI tests
    add handlers and flip ``log.propagate``.  Its handlers and
    ``propagate`` flag are snapshotted before the test and restored
    after, so a polluted logger cannot make a later caplog-based
    assertion order-dependent.
    """
    def _reset():
        pasla.download_count     = 0
        pasla.bytes_transferred  = 0
        pasla.global_connections = 0
        pasla.banned_ips.clear()
        pasla.failed_attempts.clear()
        pasla.request_log.clear()
        pasla.active_connections.clear()
        pasla.active_transfers.clear()
        pasla.download_history.clear()
        pasla.shutting_down.clear()
        # Reset ALLOWED_ROOT to current working dir.
        pasla.ALLOWED_ROOT = os.path.realpath(os.getcwd())

    _reset()
    saved_handlers  = pasla.log.handlers[:]
    saved_propagate = pasla.log.propagate
    yield
    _reset()
    pasla.log.handlers[:] = saved_handlers
    pasla.log.propagate   = saved_propagate

# ---------------------------------------------------------------------------
# Temporary files
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_file(tmp_path: Path):
    """A small temporary file with known content and SHA-256 digest."""
    content = b"pasla test payload 1234567890\n" * 100
    p = tmp_path / "testfile.bin"
    p.write_bytes(content)
    return p, hashlib.sha256(content).hexdigest()


@pytest.fixture()
def tmp_dir_with_files(tmp_path: Path):
    """A temporary directory with a few files of varying types."""
    d = tmp_path / "share_dir"
    d.mkdir()
    (d / "hello.txt").write_text("hello world\n", encoding="utf-8")
    (d / "data.bin").write_bytes(os.urandom(4096))
    sub = d / "sub"
    sub.mkdir()
    (sub / "nested.txt").write_text("nested\n", encoding="utf-8")
    return d

# ---------------------------------------------------------------------------
# Live server helpers
#
# All fixtures use a shared _start_server() helper.  Different handler
# configurations (trust_proxy, max_downloads) are done at server creation
# time — never via runtime handler hotswap.
# ---------------------------------------------------------------------------

class ServerInfo(NamedTuple):
    host: str
    port: int
    token: str
    file_name: str
    file_path: str
    file_sha256: str
    server: object          # ThreadingHTTPServer instance


def _start_server(
    file_path: Path,
    file_sha256: str,
    tmp_path: Path,
    *,
    max_downloads: int = 0,
    trust_proxy: bool = False,
    allowed_networks: list | None = None,
    file_hash_b64: str | None = None,
) -> Generator[ServerInfo, None, None]:
    """
    Start a real pasla HTTP server on a random loopback port.

    This is the single source of truth for server creation.  All fixture
    variants call this helper with different parameters rather than
    swapping the handler class at runtime (which is thread-unsafe with
    ThreadingMixIn).
    """
    file_name = file_path.name
    pasla.ALLOWED_ROOT = str(tmp_path)
    token = pasla.secrets.token_urlsafe(16)

    # Bind to port 0 → OS assigns a free port.
    server = pasla._make_server(0, pasla.BaseHTTPRequestHandler, ip_mode="4")
    try:
        actual_port = server.server_address[1]

        server.RequestHandlerClass = pasla.make_handler(
            file_path     = str(file_path),
            file_name     = file_name,
            token         = token,
            max_downloads = max_downloads,
            trust_proxy   = trust_proxy,
            allowed_networks = allowed_networks,
            file_hash_b64 = file_hash_b64,
        )
        server.timeout = 2

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            yield ServerInfo(
                host        = "127.0.0.1",
                port        = actual_port,
                token       = token,
                file_name   = file_name,
                file_path   = str(file_path),
                file_sha256 = file_sha256,
                server      = server,
            )
        finally:
            # Guarantee server teardown even if assertions fail in the test.
            pasla.shutting_down.set()
            server.shutdown()
            thread.join(timeout=5)
    finally:
        server.server_close()


@pytest.fixture()
def live_server(tmp_file, tmp_path) -> Generator[ServerInfo, None, None]:
    """Server with unlimited downloads and trust_proxy=False (default)."""
    file_path, file_sha256 = tmp_file
    yield from _start_server(file_path, file_sha256, tmp_path)


@pytest.fixture()
def live_server_trusted_proxy(tmp_file, tmp_path) -> Generator[ServerInfo, None, None]:
    """Server with trust_proxy=True — client IP is read from XFF header."""
    file_path, file_sha256 = tmp_file
    yield from _start_server(file_path, file_sha256, tmp_path, trust_proxy=True)


@pytest.fixture()
def live_server_capped(tmp_file, tmp_path) -> Generator[ServerInfo, None, None]:
    """Server with max_downloads=100 (high cap so shutdown never fires)."""
    file_path, file_sha256 = tmp_file
    yield from _start_server(
        file_path, file_sha256, tmp_path, max_downloads=100,
    )


@pytest.fixture()
def live_server_allowlist_loopback(tmp_file, tmp_path) -> Generator[ServerInfo, None, None]:
    """Server restricted to 127.0.0.0/8 — only loopback clients allowed."""
    import ipaddress
    file_path, file_sha256 = tmp_file
    yield from _start_server(
        file_path, file_sha256, tmp_path,
        allowed_networks=[ipaddress.ip_network("127.0.0.0/8")],
    )


@pytest.fixture()
def live_server_allowlist_blocked(tmp_file, tmp_path) -> Generator[ServerInfo, None, None]:
    """Server restricted to 10.0.0.0/8 — loopback clients are NOT allowed."""
    import ipaddress
    file_path, file_sha256 = tmp_file
    yield from _start_server(
        file_path, file_sha256, tmp_path,
        allowed_networks=[ipaddress.ip_network("10.0.0.0/8")],
    )


@pytest.fixture()
def live_server_trusted_proxy_allowlist(
    tmp_file, tmp_path,
) -> Generator[ServerInfo, None, None]:
    """Trust-proxy server restricted to 10.0.0.0/8 — the loopback peer
    is NOT in the allowlist, so an attacker who spoofs XFF=10.0.0.x
    must still be rejected because the socket peer (127.0.0.1) is
    outside the allowlist."""
    import ipaddress
    file_path, file_sha256 = tmp_file
    yield from _start_server(
        file_path, file_sha256, tmp_path,
        trust_proxy=True,
        allowed_networks=[ipaddress.ip_network("10.0.0.0/8")],
    )


@pytest.fixture()
def live_server_with_checksum(tmp_file, tmp_path) -> Generator[ServerInfo, None, None]:
    """Server with SHA-256 Digest header enabled."""
    import base64
    file_path, file_sha256 = tmp_file
    # Convert hex digest to base64 for the Digest header.
    b64 = base64.b64encode(bytes.fromhex(file_sha256)).decode("ascii")
    yield from _start_server(
        file_path, file_sha256, tmp_path, file_hash_b64=b64,
    )


# ---------------------------------------------------------------------------
# Network blocker (unit tests must not make real HTTP calls)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def block_outbound_network(monkeypatch):
    """
    Replace urllib.request.urlopen with a stub that raises immediately.
    Tests that deliberately need network access override this fixture.
    """
    def _blocked(url, *args, **kwargs):
        raise OSError(f"Outbound network blocked in tests: {url}")

    monkeypatch.setattr(pasla.urllib.request, "urlopen", _blocked)