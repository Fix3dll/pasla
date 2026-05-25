"""
test_integration.py — Integration tests against a real HTTP server.

Each test uses a fixture from conftest.py that binds to port 0 (OS-assigned)
and tears the server down after the test.

Server configuration variants (trust_proxy, max_downloads) use dedicated
fixtures — NOT runtime handler hotswap — to avoid thread-safety issues
with ThreadingMixIn.

HTTP requests use http.client (standard library only, consistent with the
project's zero-dependency philosophy).
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import struct
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from tests.conftest import pasla, wait_until

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(host: str, port: int, path: str, headers: dict | None = None):
    """Raw HTTP GET via http.client — gives us full response control."""
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("GET", path, headers=headers or {})
    return conn.getresponse()


def _download(host: str, port: int, path: str, headers: dict | None = None) -> bytes:
    """Download the full body and return it."""
    resp = _get(host, port, path, headers)
    return resp.read()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# ---------------------------------------------------------------------------
# Basic download
# ---------------------------------------------------------------------------

class TestBasicDownload:

    def test_200_ok(self, live_server):
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}")
        assert resp.status == 200

    def test_content_disposition(self, live_server):
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}")
        cd = resp.getheader("Content-Disposition", "")
        assert live_server.file_name in cd

    def test_file_content_correct(self, live_server):
        data = _download(live_server.host, live_server.port,
                         f"/{live_server.token}/{live_server.file_name}")
        assert _sha256(data) == live_server.file_sha256

    def test_content_length_matches_body(self, live_server):
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}")
        declared = int(resp.getheader("Content-Length", 0))
        body = resp.read()
        assert declared == len(body)

    def test_accept_ranges_advertised(self, live_server):
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}")
        assert resp.getheader("Accept-Ranges") == "bytes"

    def test_cache_control_no_store(self, live_server):
        """Ephemeral files must never be cached by intermediaries."""
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}")
        assert "no-store" in resp.getheader("Cache-Control", "")

    def test_x_content_type_options(self, live_server):
        """Prevents MIME-type sniffing attacks in browsers."""
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}")
        assert resp.getheader("X-Content-Type-Options") == "nosniff"

    def test_transfer_id_header_returned(self, live_server):
        """Server must issue a unique transfer ID for resume correlation."""
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}")
        assert resp.getheader("X-Transfer-ID")

    def test_referrer_policy_header(self, live_server):
        """Referrer-Policy: no-referrer prevents token leakage via Referer."""
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}")
        assert resp.getheader("Referrer-Policy") == "no-referrer"

# ---------------------------------------------------------------------------
# HEAD request
# ---------------------------------------------------------------------------

class TestHeadRequest:

    def test_head_200(self, live_server):
        conn = http.client.HTTPConnection(live_server.host, live_server.port, timeout=10)
        conn.request("HEAD", f"/{live_server.token}/{live_server.file_name}")
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.read() == b""   # HEAD must return no body

    def test_head_content_length(self, live_server):
        """HEAD response Content-Length must match actual file size."""
        conn = http.client.HTTPConnection(live_server.host, live_server.port, timeout=10)
        conn.request("HEAD", f"/{live_server.token}/{live_server.file_name}")
        resp = conn.getresponse()
        file_size = Path(live_server.file_path).stat().st_size
        assert int(resp.getheader("Content-Length", 0)) == file_size

    def test_head_does_not_consume_download_slot(self, live_server_capped):
        """HEAD is metadata-only; it must not count against max_downloads.

        Repeatedly probing with HEAD on a capped link would otherwise
        let any client with the URL exhaust the quota without ever
        transferring a byte and trip graceful shutdown.
        """
        s = live_server_capped
        pasla.download_count = 0
        path = f"/{s.token}/{s.file_name}"

        for _ in range(5):
            conn = http.client.HTTPConnection(s.host, s.port, timeout=10)
            conn.request("HEAD", path)
            resp = conn.getresponse()
            resp.read()
            assert resp.status == 200
            conn.close()

        assert pasla._current_download_count() == 0, (
            "HEAD must not consume download slots"
        )
        assert not pasla.shutting_down.is_set(), (
            "Graceful shutdown must not fire from HEAD traffic alone"
        )

    def test_head_does_not_register_transfer(self, live_server):
        """HEAD must leave ``active_transfers`` untouched.

        The transfer-slot table is the source of truth for
        concurrent-download accounting; HEAD bypasses it entirely so
        a metadata probe cannot collide with an in-flight GET that
        happens to share an X-Transfer-ID.
        """
        s = live_server
        before = pasla._current_active_transfers()

        conn = http.client.HTTPConnection(s.host, s.port, timeout=10)
        conn.request(
            "HEAD",
            f"/{s.token}/{s.file_name}",
            headers={"X-Transfer-ID": "client-supplied-head-id"},
        )
        resp = conn.getresponse()
        resp.read()
        conn.close()

        assert pasla._current_active_transfers() == before

# ---------------------------------------------------------------------------
# Range requests (resumable downloads)
# ---------------------------------------------------------------------------

class TestRangeRequests:

    def test_206_for_valid_range(self, live_server):
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}",
                    headers={"Range": "bytes=0-99"})
        assert resp.status == 206

    def test_range_body_correct(self, live_server):
        """Returned bytes must exactly match the requested file slice."""
        full = Path(live_server.file_path).read_bytes()
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}",
                    headers={"Range": "bytes=10-19"})
        assert resp.read() == full[10:20]

    def test_content_range_header(self, live_server):
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}",
                    headers={"Range": "bytes=0-9"})
        file_size = Path(live_server.file_path).stat().st_size
        assert resp.getheader("Content-Range") == f"bytes 0-9/{file_size}"

    def test_416_for_invalid_range(self, live_server):
        """Range starting beyond EOF must be rejected."""
        file_size = Path(live_server.file_path).stat().st_size
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}",
                    headers={"Range": f"bytes={file_size}-{file_size+100}"})
        assert resp.status == 416

    def test_suffix_range(self, live_server):
        """bytes=-50 means the last 50 bytes of the file."""
        full = Path(live_server.file_path).read_bytes()
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}",
                    headers={"Range": "bytes=-50"})
        assert resp.status == 206
        assert resp.read() == full[-50:]

    def test_open_end_range(self, live_server):
        """bytes=100- means from offset 100 to end of file."""
        full = Path(live_server.file_path).read_bytes()
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}",
                    headers={"Range": "bytes=100-"})
        assert resp.status == 206
        assert resp.read() == full[100:]

    def test_two_segments_reconstruct_file(self, live_server):
        """Simulate a download manager fetching two non-overlapping ranges.

        Each segment gets its own server-generated transfer_id (no
        X-Transfer-ID header).  This validates that independent range
        requests work correctly — the old approach of sharing a single
        transfer_id between concurrent segments was a security hole
        (download cap bypass) and is now rejected.
        """
        full  = Path(live_server.file_path).read_bytes()
        mid   = len(full) // 2

        r1 = _get(live_server.host, live_server.port,
                  f"/{live_server.token}/{live_server.file_name}",
                  headers={"Range": f"bytes=0-{mid-1}"})
        r2 = _get(live_server.host, live_server.port,
                  f"/{live_server.token}/{live_server.file_name}",
                  headers={"Range": f"bytes={mid}-"})
        assert r1.status == 206
        assert r2.status == 206
        assert r1.read() + r2.read() == full

# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------

class TestAccessControl:

    def test_wrong_token_404(self, live_server):
        resp = _get(live_server.host, live_server.port,
                    f"/wrongtoken/{live_server.file_name}")
        assert resp.status == 404

    def test_root_path_404(self, live_server):
        resp = _get(live_server.host, live_server.port, "/")
        assert resp.status == 404

    def test_traversal_attempt_rejected(self, live_server):
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/../../../etc/passwd")
        assert resp.status in (404, 400)

    def test_null_byte_rejected(self, live_server):
        # %00 in path — should be caught before any file access.
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}%00.evil")
        assert resp.status in (400, 404)

    def test_method_not_allowed(self, live_server):
        conn = http.client.HTTPConnection(live_server.host, live_server.port, timeout=10)
        conn.request("POST", f"/{live_server.token}/{live_server.file_name}")
        resp = conn.getresponse()
        assert resp.status == 405

    def test_banned_ip_gets_403(self, live_server):
        pasla.banned_ips.add("127.0.0.1")
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}")
        assert resp.status == 403

    def test_x_forwarded_for_ignored_when_proxy_untrusted(self, live_server):
        """When trust_proxy=False, XFF header must be strictly ignored.

        The request originates from 127.0.0.1.  Even though XFF claims
        the banned IP 192.0.2.0, the server must use the real socket IP
        and serve the file successfully.
        """
        fake_ip = "192.0.2.0"
        pasla.banned_ips.add(fake_ip)
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}",
                    headers={"X-Forwarded-For": fake_ip})
        assert resp.status == 200

    def test_x_forwarded_for_respected_when_proxy_trusted(self, live_server_trusted_proxy):
        """When trust_proxy=True, XFF header is used for client IP.

        Uses a dedicated fixture with trust_proxy=True — no handler
        hotswap (AP-2 fix).  The banned fake IP in XFF must trigger 403.
        """
        s = live_server_trusted_proxy
        fake_ip = "192.0.2.0"
        pasla.banned_ips.add(fake_ip)
        resp = _get(s.host, s.port,
                    f"/{s.token}/{s.file_name}",
                    headers={"X-Forwarded-For": fake_ip})
        assert resp.status == 403

# ---------------------------------------------------------------------------
# Error response format
# ---------------------------------------------------------------------------

class TestErrorFormat:
    """All error responses must return JSON body with {"error": <code>}."""

    def test_error_body_is_json(self, live_server):
        resp = _get(live_server.host, live_server.port, "/invalid/path")
        body = json.loads(resp.read())
        assert body == {"error": 404}

    def test_error_content_type_is_json(self, live_server):
        resp = _get(live_server.host, live_server.port, "/invalid/path")
        assert "application/json" in resp.getheader("Content-Type", "")

    def test_405_error_body(self, live_server):
        conn = http.client.HTTPConnection(live_server.host, live_server.port, timeout=10)
        conn.request("DELETE", f"/{live_server.token}/{live_server.file_name}")
        resp = conn.getresponse()
        body = json.loads(resp.read())
        assert body == {"error": 405}

    def test_403_error_body(self, live_server):
        """Banned IP error response must be JSON, not HTML."""
        pasla.banned_ips.add("127.0.0.1")
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}")
        body = json.loads(resp.read())
        assert body == {"error": 403}

# ---------------------------------------------------------------------------
# Download cap
# ---------------------------------------------------------------------------

class TestDownloadCap:
    """
    Strategy
    ────────
    The live_server_capped fixture starts with max_downloads=100 (high
    enough that shutdown never fires during tests).

    1. State-level (deterministic): Pre-set download_count to cap so the
       next request is over quota and gets 410 immediately.  No shutdown
       race.

    2. Counter accuracy: verify the counter after N downloads complete.
    """

    def test_410_when_cap_full(self, live_server_capped):
        """
        Pre-fill download_count to match max_downloads (100) so the very
        first request is over cap and gets 410 immediately.

        Key insight: quota is checked BEFORE any data is transferred, so
        the request is rejected before a download slot is consumed and
        before graceful shutdown is ever triggered.
        """
        s = live_server_capped
        # The capped fixture uses max_downloads=100.
        pasla.download_count = 100

        path = f"/{s.token}/{s.file_name}"
        r = _get(s.host, s.port, path)
        r.read()
        assert r.status == 410, f"Expected 410, got {r.status}"

        # Server must still be running — shutdown was never triggered.
        assert not pasla.shutting_down.is_set(), (
            "Graceful shutdown must not fire when no download completes"
        )

    def test_download_count_increments_when_capped(self, live_server_capped):
        """
        download_count only increments when max_downloads > 0.

        Uses the live_server_capped fixture (max_downloads=100) so
        shutdown never fires.  Verifies the counter rises after 2
        successful downloads.
        """
        s = live_server_capped
        path   = f"/{s.token}/{s.file_name}"
        before = pasla._current_download_count()
        _download(s.host, s.port, path)
        _download(s.host, s.port, path)
        assert pasla._current_download_count() == before + 2

    def test_aborted_partial_transfer_consumes_slot(self, tmp_path):
        """A client that drops mid-stream after receiving payload bytes
        must NOT get its download slot refunded.

        Without this guarantee, an attacker could repeatedly request a
        capped link, drain most of the file, and disconnect — burning
        bandwidth indefinitely while ``download_count`` stays at zero
        and the cap never trips.

        Uses a >2 MB payload so the file is larger than the default
        TCP send buffer; the kernel cannot hand the whole response to
        the client at once, leaving the server still inside
        ``_stream_file`` when the client RSTs.
        """
        big = tmp_path / "big_payload.bin"
        big.write_bytes(b"X" * (4 * 1024 * 1024))
        big_sha = hashlib.sha256(big.read_bytes()).hexdigest()
        # Spin up an isolated server with max_downloads=1 so the
        # refund vs. consume distinction is unambiguous.
        from tests.conftest import _start_server
        gen = _start_server(big, big_sha, tmp_path, max_downloads=1)
        s = next(gen)
        try:
            pasla.download_count = 0
            path = f"/{s.token}/{s.file_name}"

            sock = socket.create_connection((s.host, s.port), timeout=5)
            try:
                sock.sendall(
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {s.host}\r\n\r\n".encode()
                )
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                # Read a single body byte so the server has actually
                # written payload to the wire.
                first = sock.recv(1)
                assert first, "expected body bytes from server"
            finally:
                # Force RST so the server's next write fails fast.
                sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER,
                    struct.pack("ii", 1, 0),
                )
                sock.close()

            # Wait for the server's finally block to release the
            # transfer.  The slot must remain consumed because the
            # client received payload bytes before disconnecting.
            wait_until(lambda: pasla._current_download_count() == 1)

            assert pasla._current_download_count() == 1, (
                "Aborted transfer with bytes-sent > 0 must consume the "
                "download slot, not refund it"
            )
        finally:
            for _ in gen:
                pass

    def test_bytes_transferred_increments(self, live_server):
        """bytes_transferred always increments regardless of cap setting."""
        s         = live_server
        file_size = Path(s.file_path).stat().st_size
        path      = f"/{s.token}/{s.file_name}"

        before = pasla._current_bytes_transferred()
        _download(s.host, s.port, path)
        _download(s.host, s.port, path)
        assert pasla._current_bytes_transferred() == before + file_size * 2

    def test_cap_state_deterministic(self):
        """
        Pure state test — no server involved.
        ensure_slot_reserved must return False when download_count == max.
        """
        pasla.download_count = 5
        tid = pasla.secrets.token_urlsafe(16)
        pasla._register_transfer(tid)
        assert pasla._ensure_slot_reserved(tid, max_downloads=5) is False
        assert pasla.download_count == 5   # must not change

# ---------------------------------------------------------------------------
# Shutting down flag
# ---------------------------------------------------------------------------

class TestGracefulShutdown:

    def test_503_when_shutting_down(self, live_server):
        """Active server in shutdown state must reject new requests with 503."""
        pasla.shutting_down.set()
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}")
        assert resp.status == 503

# ---------------------------------------------------------------------------
# Bytes transferred counter
# ---------------------------------------------------------------------------

class TestBytesTransferred:

    def test_counter_incremented_after_download(self, live_server):
        file_size = Path(live_server.file_path).stat().st_size
        _download(live_server.host, live_server.port,
                  f"/{live_server.token}/{live_server.file_name}")
        assert pasla._current_bytes_transferred() == file_size

    def test_partial_range_counted(self, live_server):
        """Even partial range downloads must be accounted for."""
        _download(live_server.host, live_server.port,
                  f"/{live_server.token}/{live_server.file_name}",
                  headers={"Range": "bytes=0-99"})
        assert pasla._current_bytes_transferred() == 100

# ---------------------------------------------------------------------------
# Rate limiting (integration — pre-fill the sliding window)
# ---------------------------------------------------------------------------

class TestRateLimiting:

    def test_rate_limit_returns_429(self, live_server):
        """Pre-fill the rate-limit window so the next unauthenticated
        request is rate-limited.  Authenticated downloads are exempt,
        so the probe deliberately uses a wrong path."""
        ip  = "127.0.0.1"
        now = time.monotonic()
        # Pre-fill with exactly RATE_LIMIT_MAX_REQUESTS timestamps.
        pasla.request_log[ip] = [now] * pasla.RATE_LIMIT_MAX_REQUESTS
        resp = _get(live_server.host, live_server.port, "/wrong/path")
        assert resp.status == 429

    def test_authenticated_request_exempt_from_rate_limit(self, live_server):
        """A client holding the correct token is performing a genuine
        download and is never throttled, even with the rate-limit
        window already full."""
        ip  = "127.0.0.1"
        now = time.monotonic()
        pasla.request_log[ip] = [now] * (pasla.RATE_LIMIT_MAX_REQUESTS * 5)
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}")
        assert resp.status == 200

# ---------------------------------------------------------------------------
# Control plane
# ---------------------------------------------------------------------------

class TestControlPlane:

    @pytest.fixture()
    def ctrl_server(self, live_server, tmp_path):
        """Start a control plane alongside the live server."""
        instance_id = "test01"
        ctrl_secret = "test_secret_token"

        def get_status():
            return {
                "id":                instance_id,
                "file":              live_server.file_name,
                "port":              live_server.port,
                "remaining_seconds": 3600,
                "duration":          3600,
                "download_count":    pasla._current_download_count(),
                "max_downloads":     0,
                "bytes_transferred": pasla._current_bytes_transferred(),
                "active_transfers":  0,
                "banned_ips":        0,
                "trust_proxy":       False,
                "url_ipv4":          f"http://127.0.0.1:{live_server.port}/",
            }

        ctrl_port, _ = pasla.start_control_plane(
            instance_id,
            get_status_fn=get_status,
            stop_fn=lambda: None,
            ctrl_secret=ctrl_secret,
        )
        yield ctrl_port, ctrl_secret

        # Teardown: cleanly stop the control plane thread.
        try:
            pasla._ctrl_send(ctrl_port, "stop", secret=ctrl_secret)
        except Exception:
            pass

    def test_status_returns_dict(self, ctrl_server):
        port, secret = ctrl_server
        result = pasla.ctrl_status(port, secret=secret)
        assert isinstance(result, dict)
        assert "id" in result

    def test_status_contains_file(self, live_server, ctrl_server):
        port, secret = ctrl_server
        result = pasla.ctrl_status(port, secret=secret)
        assert result["file"] == live_server.file_name

    def test_unknown_command_returns_error(self, ctrl_server):
        port, secret = ctrl_server
        result = pasla._ctrl_send(port, "reboot", secret=secret)
        assert result is not None
        assert "error" in result

    def test_stop_returns_shutting_down(self, ctrl_server):
        port, secret = ctrl_server
        result = pasla._ctrl_send(port, "stop", secret=secret)
        assert result is not None
        assert result.get("status") == "shutting_down"

    def test_auth_rejected_without_secret(self, ctrl_server):
        """Control plane must reject commands that lack the shared secret."""
        port, _secret = ctrl_server
        # Attempt without secret — must return auth_failed error.
        result = pasla._ctrl_send(port, "status", secret="")
        assert result is not None
        assert result.get("error") == "auth_failed"

    def test_oversized_status_returns_error_not_truncation(
        self, live_server, monkeypatch
    ):
        """When the status payload exceeds CTRL_MAX_MESSAGE_BYTES the
        server must reply with a structured error rather than
        truncating the JSON.  A truncated reply would make the client
        decoder fail and the caller declare the instance stale,
        deleting an otherwise-healthy registry entry."""
        # Build a status callable whose JSON body is much larger than
        # the cap, simulating e.g. a long allowlist or many recent
        # downloads.
        big = {"id": "big01", "blob": "X" * (
            pasla.CTRL_MAX_MESSAGE_BYTES + 1024
        )}
        port, _ = pasla.start_control_plane(
            "big01",
            get_status_fn=lambda: big,
            stop_fn=lambda: None,
            ctrl_secret="s",
        )
        try:
            result = pasla.ctrl_status(port, secret="s")
            assert result is not None
            assert result.get("error") == "response_too_large"
        finally:
            pasla._ctrl_send(port, "stop", secret="s")

    def test_handler_survives_get_status_exception(self, monkeypatch):
        """If ``get_status_fn`` raises, the control plane handler
        thread must NOT die — otherwise ``pasla stop`` and ``pasla
        list`` permanently lose this instance until the daemon is
        killed.
        """
        calls = {"n": 0}

        def flaky_status():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("status callable broken")
            return {"id": "flaky01"}

        port, _ = pasla.start_control_plane(
            "flaky01",
            get_status_fn=flaky_status,
            stop_fn=lambda: None,
            ctrl_secret="s",
        )
        try:
            # First status request hits the buggy branch → connection
            # closed without reply (None).
            first = pasla.ctrl_status(port, secret="s")
            assert first is None
            # Second request must succeed: the handler thread is
            # still alive.
            second = pasla.ctrl_status(port, secret="s")
            assert second is not None
            assert second.get("id") == "flaky01"
        finally:
            pasla._ctrl_send(port, "stop", secret="s")

    def test_control_plane_binds_exclusively_to_loopback(self, monkeypatch):
        """Control plane must bind exclusively to 127.0.0.1 for security.

        We spy on socket.bind calls to verify the host IP without needing
        to connect from a remote address.
        """
        bound_addresses = []
        original_bind = socket.socket.bind

        def spy_bind(sock, address):
            bound_addresses.append(address)
            return original_bind(sock, address)

        monkeypatch.setattr(socket.socket, "bind", spy_bind)

        test_secret = "bind_test_secret"
        port, _ = pasla.start_control_plane(
            "test_bind_security", lambda: {}, lambda: None,
            ctrl_secret=test_secret,
        )
        try:
            assert any(host == "127.0.0.1" for host, _ in bound_addresses), (
                "Security violation: control plane failed to bind to localhost!"
            )
        finally:
            pasla._ctrl_send(port, "stop", secret=test_secret)

# ---------------------------------------------------------------------------
# Concurrent downloads
# ---------------------------------------------------------------------------

class TestConcurrency:

    def test_concurrent_downloads_all_correct(self, live_server):
        """Eight concurrent downloads must all return identical content."""
        results = []
        lock = threading.Lock()

        def worker():
            data = _download(live_server.host, live_server.port,
                             f"/{live_server.token}/{live_server.file_name}")
            with lock:
                results.append(_sha256(data))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        assert len(results) == 8
        assert all(d == live_server.file_sha256 for d in results)


# ---------------------------------------------------------------------------
# Global connection cap — handler drops connection at capacity
# ---------------------------------------------------------------------------

class TestGlobalConnectionDrop:
    """Verify SecureHandler.handle() hard-drops connections at the global cap.

    When global_connections >= MAX_GLOBAL_CONNECTIONS, the handler must call
    connection.close() without reading HTTP headers or touching disk/RAM.
    This is the DDoS mitigation path.
    """

    def test_connection_dropped_at_cap(self, live_server, monkeypatch):
        """At MAX_GLOBAL_CONNECTIONS, new TCP connections must be dropped."""
        # Saturate the counter just below cap to avoid interfering with
        # the server's own bookkeeping.
        monkeypatch.setattr(pasla, "MAX_GLOBAL_CONNECTIONS", 1)
        pasla.global_connections = 1

        sock = socket.create_connection(
            (live_server.host, live_server.port), timeout=5
        )
        try:
            # Send a valid HTTP request — the handler should drop us
            # before even reading this because the cap is already full.
            sock.sendall(
                f"GET /{live_server.token}/{live_server.file_name} HTTP/1.1\r\n"
                f"Host: {live_server.host}\r\n\r\n".encode()
            )
            # Give the server a moment to process and drop.
            data = sock.recv(4096)
            # Server dropped without sending any HTTP response.
            assert data == b""
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            # Connection forcefully reset — also acceptable behaviour.
            pass
        finally:
            sock.close()
            pasla.global_connections = 0

    def test_normal_request_works_below_cap(self, live_server, monkeypatch):
        """Sanity check: requests succeed when below the cap."""
        monkeypatch.setattr(pasla, "MAX_GLOBAL_CONNECTIONS", 100)
        pasla.global_connections = 0

        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}")
        assert resp.status == 200

    def test_global_counter_survives_setup_failure(self, live_server):
        """Global connection counter must not leak when the client aborts
        before HTTP headers are parsed (setup() failure path).

        Previously, _decrement_global_connections() lived inside
        SecureHandler.handle()'s finally block.  If setup() raised
        (e.g. ConnectionResetError from a TCP RST), handle() was never
        reached and the counter permanently leaked.  The fix moves the
        decrement to ThreadingHTTPServer.process_request_thread().
        """
        before = pasla.global_connections

        # Open a TCP connection and immediately close it with RST
        # (SO_LINGER with timeout 0) to trigger a setup() failure.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((live_server.host, live_server.port))
        # Force RST on close instead of graceful FIN.
        sock.setsockopt(
            socket.SOL_SOCKET, socket.SO_LINGER,
            struct.pack("ii", 1, 0)
        )
        sock.close()

        # Wait for the server thread to process the aborted connection.
        wait_until(lambda: pasla.global_connections == before)

        # The counter must return to its original value — no leak.
        assert pasla.global_connections == before, (
            f"Global connection counter leaked: "
            f"before={before}, after={pasla.global_connections}"
        )


# ---------------------------------------------------------------------------
# Slowloris protection — socket timeout enforcement
# ---------------------------------------------------------------------------

class TestSlowlorisProtection:
    """Verify SecureHandler.setup() enforces HEADER_READ_TIMEOUT on connections.

    A slowloris attack holds connections open by sending data very slowly.
    The settimeout() call in setup() uses the shorter HEADER_READ_TIMEOUT
    for the header-parsing phase, ensuring idle connections are killed
    quickly.  We monkeypatch the timeout to 1s to keep the test fast.
    """

    def test_idle_connection_terminated(self, live_server, monkeypatch):
        """A connection that sends nothing must be dropped after timeout."""
        # Use a very short timeout so the test doesn't take 10 seconds.
        monkeypatch.setattr(pasla, "HEADER_READ_TIMEOUT", 1)

        sock = socket.create_connection(
            (live_server.host, live_server.port), timeout=5
        )
        try:
            # Don't send any HTTP data — simulate a slowloris client.
            # The server should kill us after HEADER_READ_TIMEOUT (1 second).
            sock.settimeout(5)  # Our timeout is higher than the server's.
            start = time.monotonic()
            data = sock.recv(1024)
            elapsed = time.monotonic() - start

            # Server closed the connection (empty recv) within ~1-2 seconds.
            assert data == b""
            assert elapsed < 4, f"Server took {elapsed:.1f}s to drop idle connection"
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            # Forceful close — also acceptable.
            elapsed = time.monotonic() - start
            assert elapsed < 4
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# File identity mismatch — TOCTOU / symlink swap detection
#
# The handler captures the file's kernel-assigned identity (dev, ino) at
# startup and verifies it on every request.  If the file is replaced
# between requests, the identity changes → 500.
# ---------------------------------------------------------------------------

class TestFileIdentityMismatch:
    """Verify that replacing the served file mid-session triggers 500."""

    def test_replaced_file_returns_500(self, tmp_file, tmp_path):
        """Atomically replacing the served file must cause a 500 error.

        This is the core defense against symlink-swap and TOCTOU attacks:
        the kernel assigns a new inode to the replacement file, so the
        identity tuple changes even if content and size are identical.
        """
        file_path, file_sha256 = tmp_file

        # Start the server — it captures the file identity at this point.
        pasla.ALLOWED_ROOT = str(tmp_path)
        token = pasla.secrets.token_urlsafe(16)
        server = pasla._make_server(0, pasla.BaseHTTPRequestHandler, ip_mode="4")
        try:
            port = server.server_address[1]

            server.RequestHandlerClass = pasla.make_handler(
                file_path=str(file_path),
                file_name=file_path.name,
                token=token,
                max_downloads=0,
                trust_proxy=False,
            )
            server.timeout = 2

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            try:
                # Sanity check: first request works.
                resp = _get("127.0.0.1", port, f"/{token}/{file_path.name}")
                resp.read()
                assert resp.status == 200

                # Atomically replace the file — new inode, same content.
                replacement = tmp_path / "replacement.bin"
                replacement.write_bytes(file_path.read_bytes())
                import os as _os
                _os.replace(str(replacement), str(file_path))

                # Next request must detect the identity mismatch → 500.
                resp2 = _get("127.0.0.1", port, f"/{token}/{file_path.name}")
                resp2.read()
                assert resp2.status == 500
            finally:
                pasla.shutting_down.set()
                server.shutdown()
                thread.join(timeout=5)
        finally:
            server.server_close()


# ---------------------------------------------------------------------------
# File open failure — unreadable or deleted file
#
# If the served file becomes inaccessible after server startup (deleted,
# permissions changed), the handler must return 500 instead of crashing.
# ---------------------------------------------------------------------------

class TestFileOpenFailure:
    """Verify the handler returns 500 when the file cannot be opened."""

    def test_deleted_file_returns_500(self, tmp_file, tmp_path):
        """Deleting the served file must cause a 500 error."""
        file_path, file_sha256 = tmp_file

        pasla.ALLOWED_ROOT = str(tmp_path)
        token = pasla.secrets.token_urlsafe(16)
        server = pasla._make_server(0, pasla.BaseHTTPRequestHandler, ip_mode="4")
        try:
            port = server.server_address[1]

            server.RequestHandlerClass = pasla.make_handler(
                file_path=str(file_path),
                file_name=file_path.name,
                token=token,
                max_downloads=0,
                trust_proxy=False,
            )
            server.timeout = 2

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            try:
                # Delete the file after server startup.
                import os as _os
                _os.unlink(str(file_path))

                resp = _get("127.0.0.1", port, f"/{token}/{file_path.name}")
                resp.read()
                assert resp.status == 500
            finally:
                pasla.shutting_down.set()
                server.shutdown()
                thread.join(timeout=5)
        finally:
            server.server_close()


class TestSymlinkSwapResistance:
    """Verify that replacing the path with a symlink (or atomic
    replace) is rejected by the per-request identity check or the
    O_NOFOLLOW open, never silently serving substituted content."""

    @pytest.mark.skipif(os.name == "nt",
                        reason="symlink creation requires elevated privileges on Windows")
    def test_symlink_swap_rejected(self, tmp_file, tmp_path):
        """If the served path is replaced with a symlink to a
        different file after startup, the handler must reject the
        request rather than serving the symlink target.
        """
        file_path, _ = tmp_file
        decoy = tmp_path / "decoy.bin"
        decoy.write_bytes(b"NOT-WHAT-YOU-ASKED-FOR" * 100)

        pasla.ALLOWED_ROOT = str(tmp_path)
        token = pasla.secrets.token_urlsafe(16)
        server = pasla._make_server(0, pasla.BaseHTTPRequestHandler, ip_mode="4")
        try:
            port = server.server_address[1]

            server.RequestHandlerClass = pasla.make_handler(
                file_path=str(file_path),
                file_name=file_path.name,
                token=token,
                max_downloads=0,
                trust_proxy=False,
            )
            server.timeout = 2

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            try:
                file_path.unlink()
                os.symlink(decoy, file_path)

                resp = _get("127.0.0.1", port, f"/{token}/{file_path.name}")
                resp.read()
                # O_NOFOLLOW makes the open() fail outright, OR the
                # identity check catches the swap.  Either path
                # surfaces as 500 — what matters is that the decoy
                # bytes are NEVER served under the original token.
                assert resp.status == 500
            finally:
                pasla.shutting_down.set()
                server.shutdown()
                thread.join(timeout=5)
        finally:
            server.server_close()


# ---------------------------------------------------------------------------
# Content-Disposition header sanitization
#
# The handler sanitises filenames for the Content-Disposition header:
# - Strips quotes, newlines, carriage returns, and semicolons from
#   the ASCII fallback name.
# - Falls back to "download" if nothing remains after stripping.
# - Always includes a RFC 5987 filename*=UTF-8'' parameter.
# ---------------------------------------------------------------------------

class TestContentDisposition:
    """Verify Content-Disposition header is safe with adversarial filenames."""

    def test_special_chars_stripped(self, tmp_path):
        """Quotes, newlines, and semicolons must be stripped from filename."""
        # Create a file with adversarial characters in the name.
        # On Windows, some characters are invalid in filenames, so we
        # use a simulated approach: create a normal file, then set up
        # the handler with a crafted file_name parameter.
        f = tmp_path / "normal.txt"
        f.write_text("test content", encoding="utf-8")

        pasla.ALLOWED_ROOT = str(tmp_path)
        token = pasla.secrets.token_urlsafe(16)
        # The key trick: file_path is the real file, but file_name is adversarial.
        adversarial_name = 'evil";injected\r\nHeader: bad'
        expected_path = f"/{token}/{adversarial_name}"

        server = pasla._make_server(0, pasla.BaseHTTPRequestHandler, ip_mode="4")
        try:
            port = server.server_address[1]

            server.RequestHandlerClass = pasla.make_handler(
                file_path=str(f),
                file_name=adversarial_name,
                token=token,
                max_downloads=0,
                trust_proxy=False,
            )
            server.timeout = 2

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            try:
                from urllib.parse import quote as _quote
                encoded_name = _quote(adversarial_name, safe="")
                resp = _get("127.0.0.1", port, f"/{token}/{encoded_name}")
                resp.read()
                if resp.status == 200:
                    cd = resp.getheader("Content-Disposition", "")
                    # The handler strips ", ;, \r, \n from the ASCII fallback name.
                    # Extract the ASCII filename value from filename="<value>".
                    import re
                    m = re.search(r'filename="([^"]*)"', cd)
                    assert m is not None, f"No filename found in: {cd}"
                    ascii_name = m.group(1)
                    # The sanitized name must not contain the injection chars.
                    assert '"' not in ascii_name, f"Quote in filename: {ascii_name}"
                    assert ';' not in ascii_name, f"Semicolon in filename: {ascii_name}"
                    assert '\r' not in ascii_name, f"CR in filename: {ascii_name}"
                    assert '\n' not in ascii_name, f"LF in filename: {ascii_name}"
                    # CRLF injection must be impossible in the full header.
                    assert "\r\n" not in cd
            finally:
                pasla.shutting_down.set()
                server.shutdown()
                thread.join(timeout=5)
        finally:
            server.server_close()

    def test_non_ascii_only_name_uses_download_fallback(self, tmp_path):
        """A filename with zero ASCII chars must fall back to 'download'."""
        f = tmp_path / "normal2.txt"
        f.write_text("content", encoding="utf-8")

        pasla.ALLOWED_ROOT = str(tmp_path)
        token = pasla.secrets.token_urlsafe(16)
        # A name with only non-ASCII characters.
        unicode_name = "日本語ファイル.txt"

        server = pasla._make_server(0, pasla.BaseHTTPRequestHandler, ip_mode="4")
        try:
            port = server.server_address[1]

            server.RequestHandlerClass = pasla.make_handler(
                file_path=str(f),
                file_name=unicode_name,
                token=token,
                max_downloads=0,
                trust_proxy=False,
            )
            server.timeout = 2

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            try:
                from urllib.parse import quote as _quote
                encoded_name = _quote(unicode_name, safe="")
                resp = _get("127.0.0.1", port, f"/{token}/{encoded_name}")
                resp.read()
                if resp.status == 200:
                    cd = resp.getheader("Content-Disposition", "")
                    # The ASCII fallback must be "download" since stripping
                    # non-ASCII from the name leaves only ".txt".
                    assert 'filename="' in cd
                    # UTF-8 filename* must have the original name, percent-encoded.
                    assert "filename*=UTF-8''" in cd
            finally:
                pasla.shutting_down.set()
                server.shutdown()
                thread.join(timeout=5)
        finally:
            server.server_close()



# ---------------------------------------------------------------------------
# Control plane edge cases
#
# The control plane handler loop enforces:
# - CTRL_MAX_MESSAGE_BYTES cap on inbound messages
# - JSON validity on inbound messages
# - Auth via hmac.compare_digest before processing any command
# ---------------------------------------------------------------------------

class TestControlPlaneEdgeCases:
    """Verify control plane handles oversized, malformed, and unauthorized requests."""

    @pytest.fixture()
    def ctrl_server(self, live_server, tmp_path):
        """Start a control plane with a known secret."""
        instance_id = "edge01"
        ctrl_secret = "edge_secret"

        def get_status():
            return {"id": instance_id, "status": "running"}

        ctrl_port, _ = pasla.start_control_plane(
            instance_id,
            get_status_fn=get_status,
            stop_fn=lambda: None,
            ctrl_secret=ctrl_secret,
        )
        yield ctrl_port, ctrl_secret

        try:
            pasla._ctrl_send(ctrl_port, "stop", secret=ctrl_secret)
        except Exception:
            pass

    def test_oversized_message_rejected(self, ctrl_server):
        """Messages exceeding CTRL_MAX_MESSAGE_BYTES must be rejected."""
        port, secret = ctrl_server
        # Send a message that exceeds the cap (CTRL_MAX_MESSAGE_BYTES = 4096 by default).
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            # Send more than CTRL_MAX_MESSAGE_BYTES of data.
            huge_payload = b"A" * (pasla.CTRL_MAX_MESSAGE_BYTES + 1000) + b"\n"
            sock.sendall(huge_payload)
            resp = sock.recv(8192)
            # Should get an error response about message being too large,
            # or connection closed.
            if resp:
                import json as _json
                # The response may contain multiple newline-delimited JSON lines;
                # parse only the first one.
                first_line = resp.decode(errors="replace").strip().split("\n")[0]
                result = _json.loads(first_line)
                assert result.get("error") == "message_too_large"
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            # Server forcefully closed — also acceptable.
            pass
        finally:
            sock.close()

    def test_invalid_json_rejected(self, ctrl_server):
        """Non-JSON messages must return an error."""
        port, _secret = ctrl_server
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            sock.sendall(b"THIS IS NOT JSON\n")
            resp = sock.recv(4096)
            if resp:
                import json as _json
                result = _json.loads(resp.decode().strip())
                assert result.get("error") == "invalid_json"
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            pass
        finally:
            sock.close()

    def test_wrong_secret_rejected(self, ctrl_server):
        """Commands with wrong secret must be rejected with auth_failed."""
        port, _secret = ctrl_server
        result = pasla._ctrl_send(port, "status", secret="wrong_secret")
        assert result is not None
        assert result.get("error") == "auth_failed"

    def test_empty_secret_rejected(self, ctrl_server):
        """Commands with empty secret must be rejected."""
        port, _secret = ctrl_server
        result = pasla._ctrl_send(port, "status", secret="")
        assert result is not None
        assert result.get("error") == "auth_failed"

    def test_json_array_payload_rejected(self, ctrl_server):
        """A JSON array payload must return invalid_json, not crash the daemon."""
        port, secret = ctrl_server
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            sock.sendall(b'[]\n')
            resp = sock.recv(4096)
            result = json.loads(resp.decode().strip())
            assert result.get("error") == "invalid_json"
        finally:
            sock.close()

        # The daemon thread must still be alive after the invalid payload.
        result = pasla._ctrl_send(port, "status", secret=secret)
        assert result is not None
        assert "error" not in result or result.get("error") != "auth_failed"

    def test_json_string_payload_rejected(self, ctrl_server):
        """A JSON string payload must return invalid_json."""
        port, _secret = ctrl_server
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            sock.sendall(b'"hello"\n')
            resp = sock.recv(4096)
            result = json.loads(resp.decode().strip())
            assert result.get("error") == "invalid_json"
        finally:
            sock.close()

    def test_json_number_payload_rejected(self, ctrl_server):
        """A JSON number payload must return invalid_json."""
        port, _secret = ctrl_server
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            sock.sendall(b'42\n')
            resp = sock.recv(4096)
            result = json.loads(resp.decode().strip())
            assert result.get("error") == "invalid_json"
        finally:
            sock.close()

    def test_idle_connection_dropped_within_read_timeout(
        self, ctrl_server, monkeypatch,
    ):
        """A connection that never sends a command must be dropped after
        CTRL_READ_TIMEOUT, not held for the full client-side CTRL_TIMEOUT.
        This bounds how long a silent peer can occupy the single-threaded
        accept loop."""
        port, _secret = ctrl_server
        # _handle_ctrl_connection reads CTRL_READ_TIMEOUT at call time,
        # so a fresh connection picks up this shortened value.
        monkeypatch.setattr(pasla, "CTRL_READ_TIMEOUT", 0.5)
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            sock.settimeout(5)
            start = time.monotonic()
            # Send nothing; the server must close the connection itself.
            data = sock.recv(64)
            elapsed = time.monotonic() - start
            assert data == b""           # server closed without a reply
            assert elapsed < 3           # dropped well before the 5s cap
        finally:
            sock.close()

    def test_integer_secret_rejected_without_crash(self, ctrl_server):
        """An integer secret must return auth_failed, not crash the daemon.

        hmac.compare_digest() raises TypeError when given a non-string
        argument.  The str() wrapping on msg.get("secret", "") prevents
        this from killing the control plane thread.
        """
        port, secret = ctrl_server
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            payload = json.dumps({"command": "status", "secret": 123}) + "\n"
            sock.sendall(payload.encode())
            resp = sock.recv(4096)
            result = json.loads(resp.decode().strip())
            assert result.get("error") == "auth_failed"
        finally:
            sock.close()

        # The daemon thread must still be alive after the integer secret.
        result = pasla._ctrl_send(port, "status", secret=secret)
        assert result is not None
        assert "id" in result


# ---------------------------------------------------------------------------
# Invalid client IP handling
#
# _handle_request_inner validates the client IP with ipaddress.ip_address().
# If validation fails (e.g. XFF contains garbage), the request gets 400.
# ---------------------------------------------------------------------------

class TestInvalidClientIP:
    """Verify requests with invalid client IP get 400."""

    def test_invalid_xff_with_trusted_proxy(self, live_server_trusted_proxy):
        """When trust_proxy=True and XFF contains a non-IP, expect fallback or 400.

        With trust_proxy=True, the server reads XFF.  If the XFF value is
        not a valid IP, get_client_ip falls back to the socket IP (127.0.0.1).
        The request should succeed since 127.0.0.1 is a valid IP.
        """
        s = live_server_trusted_proxy
        # "not_an_ip" is not a valid IP — get_client_ip should fall back.
        resp = _get(s.host, s.port,
                    f"/{s.token}/{s.file_name}",
                    headers={"X-Forwarded-For": "not_an_ip"})
        # The fallback means socket IP (127.0.0.1) is used — request succeeds.
        assert resp.status == 200
        resp.read()


# ---------------------------------------------------------------------------
# Per-IP connection limit enforcement (integration)
#
# Verify that per-IP connection limiting works end-to-end, not just
# at the state-management level (which is covered by unit tests).
# ---------------------------------------------------------------------------

class TestPerIPConnectionLimit:
    """Verify per-IP connection limit enforcement.

    Both gates use the SAME comparison (``> MAX_CONNECTIONS_PER_IP``)
    so they enforce one consistent ceiling.  The counter includes the
    current connection, so a count equal to the limit is AT the
    ceiling (allowed); only a count above it is rejected.
    1. Pre-header: handle() silently drops (TCP RST) connections when
       active_connections[ip] > MAX_CONNECTIONS_PER_IP, before reading
       any HTTP headers — closes the slowloris window.
    2. Post-header: _validate_and_register_request() returns 429 when
       active_connections[ip] > MAX_CONNECTIONS_PER_IP.  With both
       gates aligned this is a backstop for the race window between
       the pre-header check and validation.
    """

    def test_pre_header_drop_when_over_limit(self, live_server):
        """Connections exceeding the per-IP limit must be dropped before
        header parsing — no HTTP response, just a closed socket."""
        # Set to MAX+1 so after handle() increments it, the check
        # active_connections[ip] > MAX triggers immediately.
        pasla.active_connections["127.0.0.1"] = pasla.MAX_CONNECTIONS_PER_IP

        sock = socket.create_connection(
            (live_server.host, live_server.port), timeout=5
        )
        try:
            sock.sendall(
                f"GET /{live_server.token}/{live_server.file_name} HTTP/1.1\r\n"
                f"Host: {live_server.host}\r\n\r\n".encode()
            )
            data = sock.recv(4096)
            # Server dropped without sending any HTTP response.
            assert data == b""
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            # Connection forcefully reset — also acceptable.
            pass
        finally:
            sock.close()

    def test_at_limit_allowed(self, live_server):
        """A connection that brings the per-IP count to exactly the
        limit is AT the ceiling, not over it, and must be served."""
        # Set to MAX-1 so handle() increments it to exactly MAX; both
        # the pre-header gate and the validation gate use ``> MAX``, so
        # the request is allowed through.
        pasla.active_connections["127.0.0.1"] = pasla.MAX_CONNECTIONS_PER_IP - 1
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}")
        resp.read()
        assert resp.status == 200


# ---------------------------------------------------------------------------
# Ban accumulation via repeated failed requests (integration)
#
# Verify that BAN_THRESHOLD wrong-token attempts from the same IP
# result in a ban (403) on subsequent requests.
# ---------------------------------------------------------------------------

class TestBanAccumulation:
    """Verify that repeated failed token attempts trigger a ban."""

    def test_ban_after_threshold_wrong_tokens(self, live_server):
        """BAN_THRESHOLD wrong-token requests must trigger a permanent ban."""
        for _ in range(pasla.BAN_THRESHOLD):
            resp = _get(live_server.host, live_server.port,
                        "/wrong_token/wrong_file")
            resp.read()
            # Each should be 404 until the ban kicks in.

        # Now the IP should be banned → 403.
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}")
        resp.read()
        assert resp.status == 403


# ---------------------------------------------------------------------------
# Multiple HTTP methods rejected (integration)
#
# Beyond POST (already tested), verify that PUT, DELETE, OPTIONS, PATCH,
# and TRACE all return 405.
# ---------------------------------------------------------------------------

class TestMultipleMethodsRejected:
    """Verify all disallowed HTTP methods return 405."""

    @pytest.mark.parametrize("method", ["PUT", "DELETE", "OPTIONS", "PATCH"])
    def test_method_returns_405(self, live_server, method):
        """HTTP methods other than GET/HEAD must return 405."""
        conn = http.client.HTTPConnection(live_server.host, live_server.port, timeout=10)
        conn.request(method, f"/{live_server.token}/{live_server.file_name}")
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 405

    def test_method_rate_limited_when_window_full(self, live_server):
        """Unsupported methods are subject to rate limiting: with the
        rate-limit window already full, a POST is rejected with 429
        instead of 405 - it can no longer churn unbounded."""
        ip  = "127.0.0.1"
        now = time.monotonic()
        pasla.request_log[ip] = [now] * pasla.RATE_LIMIT_MAX_REQUESTS
        conn = http.client.HTTPConnection(
            live_server.host, live_server.port, timeout=10)
        conn.request("POST", f"/{live_server.token}/{live_server.file_name}")
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 429


# ---------------------------------------------------------------------------
# IP/CIDR allowlist enforcement (integration)
#
# Verify that --allow-ip restricts access at the HTTP level.  Tests use
# fixtures from conftest.py that create servers with specific allowlists.
# ---------------------------------------------------------------------------

class TestAllowlistEnforcement:
    """Verify IP/CIDR allowlist blocks or permits clients correctly."""

    def test_loopback_allowed_when_in_allowlist(self, live_server_allowlist_loopback):
        """Requests from 127.0.0.1 must succeed when 127.0.0.0/8 is allowed."""
        s = live_server_allowlist_loopback
        resp = _get(s.host, s.port, f"/{s.token}/{s.file_name}")
        body = resp.read()
        assert resp.status == 200
        assert len(body) > 0

    def test_loopback_blocked_when_not_in_allowlist(self, live_server_allowlist_blocked):
        """Requests from 127.0.0.1 must be rejected when only 10.0.0.0/8 is allowed."""
        s = live_server_allowlist_blocked
        resp = _get(s.host, s.port, f"/{s.token}/{s.file_name}")
        resp.read()
        assert resp.status == 403

    def test_no_allowlist_permits_any_client(self, live_server):
        """Without --allow-ip, all clients must be permitted (default behavior)."""
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}")
        body = resp.read()
        assert resp.status == 200
        assert len(body) > 0

    def test_blocked_ip_does_not_accumulate_bans(self, live_server_allowlist_blocked):
        """Allowlist rejections must NOT count toward the ban threshold.

        Ban accumulation is for wrong tokens, not network-level restrictions.
        A blocked IP that retries should keep getting 403 (not 403 from ban).
        """
        s = live_server_allowlist_blocked
        for _ in range(pasla.BAN_THRESHOLD + 2):
            resp = _get(s.host, s.port, f"/{s.token}/{s.file_name}")
            resp.read()
            assert resp.status == 403

        # Verify the IP was NOT added to banned_ips.
        assert "127.0.0.1" not in pasla.banned_ips

    def test_head_also_blocked_by_allowlist(self, live_server_allowlist_blocked):
        """HEAD requests must also be subject to the allowlist."""
        s = live_server_allowlist_blocked
        conn = http.client.HTTPConnection(s.host, s.port, timeout=10)
        conn.request("HEAD", f"/{s.token}/{s.file_name}")
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 403

    def test_xff_spoof_cannot_bypass_allowlist_under_trust_proxy(
        self, live_server_trusted_proxy_allowlist,
    ):
        """When --trust-proxy is on, the allowlist must apply to BOTH
        the resolved client IP (from XFF) and the underlying socket
        peer.  An attacker who spoofs an allowlisted address in the
        XFF header should still be rejected because the real TCP peer
        (127.0.0.1) is outside the configured 10.0.0.0/8 network.
        """
        s = live_server_trusted_proxy_allowlist
        resp = _get(
            s.host, s.port, f"/{s.token}/{s.file_name}",
            headers={"X-Forwarded-For": "10.0.0.5"},
        )
        resp.read()
        assert resp.status == 403


# ---------------------------------------------------------------------------
# SHA-256 Digest header
# ---------------------------------------------------------------------------

class TestDigestHeader:
    """Verify the Digest header is present when checksum is active."""

    def test_digest_header_present(self, live_server_with_checksum):
        """Full download should include sha-256 Digest header."""
        s = live_server_with_checksum
        conn = http.client.HTTPConnection(s.host, s.port, timeout=10)
        conn.request("GET", f"/{s.token}/{s.file_name}")
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 200
        digest = resp.getheader("Digest")
        assert digest is not None
        assert digest.startswith("sha-256=")
        # Verify the base64 value matches the file content.
        import base64
        actual_hash = hashlib.sha256(body).digest()
        expected_b64 = base64.b64encode(actual_hash).decode("ascii")
        assert digest == f"sha-256={expected_b64}"

    def test_digest_header_not_on_range(self, live_server_with_checksum):
        """Range requests should NOT include the Digest header."""
        s = live_server_with_checksum
        conn = http.client.HTTPConnection(s.host, s.port, timeout=10)
        conn.request("GET", f"/{s.token}/{s.file_name}",
                     headers={"Range": "bytes=0-9"})
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 206
        assert resp.getheader("Digest") is None


class TestNoDigestHeaderWhenDisabled:
    """Verify no Digest header when checksum is not configured."""

    def test_no_digest_header(self, live_server):
        """Default server should not include Digest header."""
        s = live_server
        conn = http.client.HTTPConnection(s.host, s.port, timeout=10)
        conn.request("GET", f"/{s.token}/{s.file_name}")
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 200
        assert resp.getheader("Digest") is None


# ---------------------------------------------------------------------------
# Download history
# ---------------------------------------------------------------------------

class TestDownloadHistoryStatus:
    """Verify download history is populated after transfers."""

    def test_history_after_download(self, live_server):
        """After a successful download, download_history should have an entry."""
        s = live_server
        conn = http.client.HTTPConnection(s.host, s.port, timeout=10)
        conn.request("GET", f"/{s.token}/{s.file_name}")
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 200

        # Wait for the transfer to finalize and append to history.
        wait_until(lambda: len(pasla.download_history) >= 1)

        assert len(pasla.download_history) >= 1
        ts, ip, nbytes = pasla.download_history[-1]
        assert ip == "127.0.0.1"
        assert nbytes > 0


# ---------------------------------------------------------------------------
# XFF rotation ban evasion
# ---------------------------------------------------------------------------

class TestXFFRotationBan:
    """Verify that rotating X-Forwarded-For from a single TCP peer cannot
    evade ban accumulation when ``trust_proxy=True``.

    Without socket-IP failure tracking, an attacker could rotate the
    XFF header on every request and never trip the per-IP ban
    threshold.  The handler accumulates failures against BOTH the XFF
    IP and the socket IP, so BAN_THRESHOLD wrong-token requests from
    a single peer ban that peer regardless of header rotation.
    """

    def test_rotating_xff_still_bans_socket_ip(
        self, live_server_trusted_proxy, monkeypatch
    ):
        # Lower the threshold so the test stays fast.
        monkeypatch.setattr(pasla, "BAN_THRESHOLD", 3)
        s = live_server_trusted_proxy
        wrong_path = f"/wrongtoken/{s.file_name}"

        # Send BAN_THRESHOLD requests from the same socket peer with
        # different XFF values each time.  Each XFF is unique, so no
        # single XFF IP would accumulate enough failures to be banned —
        # but the socket IP (127.0.0.1) sees them all.
        for i in range(3):
            resp = _get(
                s.host, s.port, wrong_path,
                headers={"X-Forwarded-For": f"203.0.113.{i + 1}"},
            )
            resp.read()
            assert resp.status == 404

        # The socket IP (127.0.0.1) should now be banned.  Even a
        # request with a fresh XFF IP must return 403 because the
        # socket peer is banned.
        assert "127.0.0.1" in pasla.banned_ips

        resp = _get(
            s.host, s.port, f"/{s.token}/{s.file_name}",
            headers={"X-Forwarded-For": "203.0.113.99"},
        )
        resp.read()
        assert resp.status == 403

    def test_xff_ip_also_banned_independently(
        self, live_server_trusted_proxy, monkeypatch
    ):
        """When the same XFF IP repeats, it accumulates its own ban
        independent of the socket IP."""
        monkeypatch.setattr(pasla, "BAN_THRESHOLD", 3)
        s = live_server_trusted_proxy
        wrong_path = f"/wrongtoken/{s.file_name}"
        xff_ip = "198.51.100.7"

        for _ in range(3):
            resp = _get(
                s.host, s.port, wrong_path,
                headers={"X-Forwarded-For": xff_ip},
            )
            resp.read()

        assert xff_ip in pasla.banned_ips
        assert "127.0.0.1" in pasla.banned_ips

    def test_proxy_aggregate_rate_limit_caps_unauthenticated_burst(
        self, live_server_trusted_proxy, monkeypatch
    ):
        """A single TCP peer cannot burst unauthenticated requests
        beyond ``MAX_REQUESTS_PER_PROXY_IP`` by rotating XFF.

        Per-XFF rate-limit accepts each fresh XFF as its own bucket;
        only the proxy-aggregate ceiling stops the abuse.  A
        single-segment path keeps the probes unauthenticated and
        rate-limited without also tripping the ban threshold.
        """
        monkeypatch.setattr(pasla, "MAX_REQUESTS_PER_PROXY_IP", 5)
        s = live_server_trusted_proxy

        statuses = []
        for i in range(8):
            resp = _get(
                s.host, s.port, "/probe",
                headers={"X-Forwarded-For": f"203.0.113.{100 + i}"},
            )
            resp.read()
            statuses.append(resp.status)

        # First five answered (404); sixth onwards hit the proxy
        # aggregate rate limit.
        assert statuses[:5] == [404, 404, 404, 404, 404]
        assert 429 in statuses[5:]

# ---------------------------------------------------------------------------
# Ban-shape heuristic — browser noise must not lock a visitor out
# ---------------------------------------------------------------------------

class TestBanShapeHeuristic:
    """A token mismatch only counts toward the ban threshold when the
    path looks like a token guess.  Browser/scanner noise does not."""

    def test_browser_noise_path_never_bans(self, live_server):
        """Single-segment noise paths (favicon, robots.txt) return 404
        but never ban - so a legitimate visitor cannot lock themselves
        out by opening the link in a browser."""
        for _ in range(pasla.BAN_THRESHOLD + 3):
            resp = _get(live_server.host, live_server.port, "/favicon.ico")
            resp.read()
            assert resp.status == 404
        assert "127.0.0.1" not in pasla.banned_ips
        # The correct token still works - the client was never banned.
        resp = _get(live_server.host, live_server.port,
                    f"/{live_server.token}/{live_server.file_name}")
        assert resp.status == 200

    def test_token_guess_shape_still_bans(self, live_server):
        """A wrong path with the same segment shape as the real URL is
        a token guess and still trips the ban threshold."""
        for _ in range(pasla.BAN_THRESHOLD):
            resp = _get(live_server.host, live_server.port,
                        f"/wrongtoken/{live_server.file_name}")
            resp.read()
        assert "127.0.0.1" in pasla.banned_ips


# ---------------------------------------------------------------------------
# HTTPS end-to-end transfer
#
# Exercises the real TLS path: _setup_https generates an ephemeral
# self-signed cert, wraps the listener socket, and a TLS client
# downloads the file and verifies its SHA-256.  Skipped when the
# openssl CLI is unavailable.
# ---------------------------------------------------------------------------

class TestHTTPSTransfer:
    """Verify a file can be downloaded over a real TLS connection."""

    def test_https_download_end_to_end(self, tmp_file, tmp_path, monkeypatch):
        import shutil
        import ssl

        if shutil.which("openssl") is None:
            pytest.skip("openssl CLI not available")

        file_path, file_sha256 = tmp_file
        file_name = file_path.name
        instance_id = "tlstest"

        # Keep all TLS material inside the test's tmp_path.
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")
        monkeypatch.setattr(pasla, "ALLOWED_ROOT", str(tmp_path))
        (tmp_path / "registry").mkdir(parents=True, exist_ok=True)

        token = pasla.secrets.token_urlsafe(16)
        server = pasla._make_server(0, pasla.BaseHTTPRequestHandler, ip_mode="4")
        cert_dir = None
        thread = None
        try:
            cert_dir, _cert, _key, ephemeral = pasla._setup_https(
                server, instance_id,
            )
            assert ephemeral is True
            server.RequestHandlerClass = pasla.make_handler(
                file_path=str(file_path), file_name=file_name,
                token=token, max_downloads=0, trust_proxy=False,
            )
            server.timeout = 2
            port = server.server_address[1]

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(
                "127.0.0.1", port, timeout=10, context=ctx,
            )
            conn.request("GET", f"/{token}/{file_name}")
            resp = conn.getresponse()
            body = resp.read()
            conn.close()

            assert resp.status == 200
            assert _sha256(body) == file_sha256
        finally:
            pasla.shutting_down.set()
            server.shutdown()
            if thread is not None:
                thread.join(timeout=5)
            server.server_close()
            if cert_dir:
                shutil.rmtree(cert_dir, ignore_errors=True)
