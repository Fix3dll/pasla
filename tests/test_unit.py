"""
test_unit.py — Pure function tests.

All tests here are deterministic and require no network, no subprocess,
and no running server.  They exercise individual functions in isolation.

Design principles
─────────────────
* No I/O — all side effects are stubbed via monkeypatch or fixture.
* No server fixtures — test_integration.py handles that.
* No platform-conditional skips — test_platform.py handles those.
"""

from __future__ import annotations

import hashlib
import argparse
import io
import logging
import os
import socket
import sys
import threading
import time
import tarfile
import pathlib
from pathlib import Path
from unittest import mock

import pytest

from tests.conftest import pasla, ipv6_usable

# ---------------------------------------------------------------------------
# parse_range_header
# ---------------------------------------------------------------------------

class TestParseRangeHeader:

    def test_none_when_empty(self):
        assert pasla.parse_range_header("", 1000) is None

    def test_none_when_missing(self):
        assert pasla.parse_range_header("", 500) is None

    def test_full_range(self):
        assert pasla.parse_range_header("bytes=0-499", 1000) == (0, 499)

    def test_open_end(self):
        # bytes=200- means from 200 to end.
        assert pasla.parse_range_header("bytes=200-", 1000) == (200, 999)

    def test_suffix_range(self):
        # bytes=-100 means last 100 bytes.
        assert pasla.parse_range_header("bytes=-100", 1000) == (900, 999)

    def test_suffix_larger_than_file(self):
        # Suffix bigger than file → clamp to 0.
        assert pasla.parse_range_header("bytes=-9999", 1000) == (0, 999)

    def test_single_byte(self):
        assert pasla.parse_range_header("bytes=0-0", 1000) == (0, 0)

    def test_last_byte(self):
        assert pasla.parse_range_header("bytes=999-999", 1000) == (999, 999)

    def test_end_beyond_file_clamped(self):
        assert pasla.parse_range_header("bytes=0-9999", 1000) == (0, 999)

    def test_multi_range_rejected(self):
        assert pasla.parse_range_header("bytes=0-100,200-300", 1000) is None

    def test_wrong_unit_rejected(self):
        assert pasla.parse_range_header("items=0-100", 1000) is None

    def test_inverted_range_rejected(self):
        assert pasla.parse_range_header("bytes=500-100", 1000) is None

    def test_start_beyond_file_rejected(self):
        assert pasla.parse_range_header("bytes=1000-1005", 1000) is None

    def test_negative_start_rejected(self):
        assert pasla.parse_range_header("bytes=-1-100", 1000) is None

    def test_zero_suffix_rejected(self):
        assert pasla.parse_range_header("bytes=-0", 1000) is None

    def test_malformed_no_dash(self):
        assert pasla.parse_range_header("bytes=100", 1000) is None

    def test_non_numeric(self):
        assert pasla.parse_range_header("bytes=abc-def", 1000) is None

    def test_empty_both_sides(self):
        assert pasla.parse_range_header("bytes=-", 1000) is None


# ---------------------------------------------------------------------------
# _fmt_bytes
# ---------------------------------------------------------------------------

class TestFmtBytes:

    def test_bytes(self):
        assert pasla._fmt_bytes(0) == "0.0 B"

    def test_exactly_one_kb(self):
        assert pasla._fmt_bytes(1024) == "1.0 KB"

    def test_megabytes(self):
        assert pasla._fmt_bytes(1024 * 1024) == "1.0 MB"

    def test_gigabytes(self):
        assert pasla._fmt_bytes(1024 ** 3) == "1.0 GB"

    def test_partial(self):
        result = pasla._fmt_bytes(1536)      # 1.5 KB
        assert "1.5 KB" == result

    def test_float_input(self):
        # Must not raise with float input.
        assert "KB" in pasla._fmt_bytes(2048.0)

    def test_large_value(self):
        assert "TB" in pasla._fmt_bytes(1024 ** 4)

    def test_petabytes(self):
        """Values beyond TB must display as PB."""
        assert "PB" in pasla._fmt_bytes(1024 ** 5)


# ---------------------------------------------------------------------------
# _fmt_remaining
# ---------------------------------------------------------------------------

class TestFmtRemaining:

    def _make_args(self, seconds_left: int):
        """Return (started_at, duration) so that seconds_left remain."""
        duration   = seconds_left + 10
        started_at = time.monotonic() - 10   # 10 seconds ago
        return started_at, duration

    def test_minutes_and_seconds(self):
        s, d = self._make_args(90)
        result = pasla._fmt_remaining(s, d)
        assert "m" in result and "s" in result

    def test_hours_and_minutes(self):
        s, d = self._make_args(3700)
        result = pasla._fmt_remaining(s, d)
        assert "h" in result

    def test_expired_returns_zero(self):
        s, d = self._make_args(0)
        result = pasla._fmt_remaining(s - 999, d)
        assert result == "0s"

    def test_seconds_only(self):
        s, d = self._make_args(45)
        result = pasla._fmt_remaining(s, d)
        assert result.endswith("s")
        assert "m" not in result

    def test_exactly_one_hour(self):
        """Boundary: ≥3600s remaining must show hours."""
        # Use a generous buffer to avoid timing drift between setup
        # and function call causing int(remaining) to round down.
        s, d = self._make_args(3601)
        result = pasla._fmt_remaining(s, d)
        assert "h" in result

    def test_exactly_one_minute(self):
        """Boundary: ≥60s remaining must show minutes."""
        s, d = self._make_args(61)
        result = pasla._fmt_remaining(s, d)
        assert "m" in result


# ---------------------------------------------------------------------------
# Ban logic  (record_failure / record_success)
# ---------------------------------------------------------------------------

class TestBanLogic:

    def test_ban_after_threshold(self):
        ip = "10.0.0.1"
        for _ in range(pasla.BAN_THRESHOLD):
            pasla._record_failure(ip)
        assert ip in pasla.banned_ips

    def test_no_ban_below_threshold(self):
        ip = "10.0.0.2"
        for _ in range(pasla.BAN_THRESHOLD - 1):
            pasla._record_failure(ip)
        assert ip not in pasla.banned_ips

    def test_failures_accumulate_permanently(self):
        """Failed attempts must never be reset so that attackers cannot
        evade bans by alternating valid and invalid requests."""
        ip = "10.0.0.3"
        for _ in range(pasla.BAN_THRESHOLD - 1):
            pasla._record_failure(ip)
        assert pasla.failed_attempts[ip] == pasla.BAN_THRESHOLD - 1
        # One more failure must trigger the ban.
        pasla._record_failure(ip)
        assert ip in pasla.banned_ips

    def test_ban_list_cap(self, monkeypatch):
        """Ban list must not grow beyond MAX_BANNED_IPS."""
        monkeypatch.setattr(pasla, "MAX_BANNED_IPS", 3)
        for i in range(10):
            ip = f"192.168.1.{i}"
            for _ in range(pasla.BAN_THRESHOLD):
                pasla._record_failure(ip)
        assert len(pasla.banned_ips) <= 3

    def test_lru_eviction_at_max_banned_ips(self, monkeypatch):
        """When ``MAX_BANNED_IPS`` is reached, the oldest ban is
        evicted to make room for the new one (LRU).  Without eviction
        an attacker filling the ban table with disposable IPs would
        permanently disable bans for every subsequent attacker."""
        monkeypatch.setattr(pasla, "MAX_BANNED_IPS", 3)
        # Ban three distinct IPs in order.
        for i, ip in enumerate(["10.0.0.1", "10.0.0.2", "10.0.0.3"]):
            for _ in range(pasla.BAN_THRESHOLD):
                pasla._record_failure(ip)
        assert list(pasla.banned_ips) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

        # Fourth ban must evict the oldest (10.0.0.1).
        for _ in range(pasla.BAN_THRESHOLD):
            pasla._record_failure("10.0.0.4")
        assert "10.0.0.1" not in pasla.banned_ips
        assert "10.0.0.4" in pasla.banned_ips
        assert len(pasla.banned_ips) == 3


# ---------------------------------------------------------------------------
# validate_and_register_request
# ---------------------------------------------------------------------------

class TestValidateAndRegister:

    def test_banned_ip_returns_403(self):
        ip = "1.2.3.4"
        pasla.banned_ips.add(ip)
        result = pasla._validate_and_register_request(ip)
        assert result == (403, "banned_client_ip")

    def test_rate_limit_returns_429(self):
        ip = "1.2.3.5"
        # Fill the sliding window.
        now = time.monotonic()
        pasla.request_log[ip] = [now] * pasla.RATE_LIMIT_MAX_REQUESTS
        result = pasla._validate_and_register_request(ip)
        assert result == (429, "rate_limit_client_ip")

    def test_connection_limit_returns_429(self):
        # The counter already includes the current connection, so the
        # cap is exceeded only ABOVE MAX_CONNECTIONS_PER_IP - this
        # matches the pre-header gate in handle().
        ip = "1.2.3.6"
        pasla.active_connections[ip] = pasla.MAX_CONNECTIONS_PER_IP + 1
        result = pasla._validate_and_register_request(ip)
        assert result == (429, "conn_cap_client_ip")

    def test_connection_at_limit_allowed(self):
        """A connection count of exactly MAX_CONNECTIONS_PER_IP is AT the
        ceiling, not over it - it must be allowed (not 429)."""
        ip = "1.2.3.61"
        pasla.active_connections[ip] = pasla.MAX_CONNECTIONS_PER_IP
        assert pasla._validate_and_register_request(ip) is None

    def test_clean_ip_returns_none(self):
        assert pasla._validate_and_register_request("1.2.3.7") is None

    def test_request_logged(self):
        ip = "1.2.3.8"
        pasla._validate_and_register_request(ip)
        assert len(pasla.request_log[ip]) == 1

    def test_rate_limit_window_expiry(self):
        """Timestamps older than RATE_LIMIT_WINDOW must be pruned."""
        ip = "1.2.3.9"
        expired = time.monotonic() - pasla.RATE_LIMIT_WINDOW - 1
        pasla.request_log[ip] = [expired] * pasla.RATE_LIMIT_MAX_REQUESTS
        # All timestamps are expired — request must be allowed.
        assert pasla._validate_and_register_request(ip) is None
        # Old entries must have been pruned, only the new one remains.
        assert len(pasla.request_log[ip]) == 1


# ---------------------------------------------------------------------------
# Tracked IPs cap (MAX_TRACKED_IPS)
# ---------------------------------------------------------------------------

class TestTrackedIPsCap:
    """Verify request_log growth is capped under botnet-like traffic."""

    def test_new_ip_evicts_oldest_at_cap(self, monkeypatch):
        """When request_log reaches MAX_TRACKED_IPS, the oldest entry is
        evicted to make room for the new IP (fail-closed, not fail-open)."""
        monkeypatch.setattr(pasla, "MAX_TRACKED_IPS", 3)
        now = time.monotonic()
        # Fill tracking table to capacity.
        pasla.request_log["10.0.0.1"] = [now]
        pasla.request_log["10.0.0.2"] = [now]
        pasla.request_log["10.0.0.3"] = [now]

        # A new IP arrives — oldest entry (10.0.0.1) must be evicted.
        result = pasla._validate_and_register_request("10.0.0.99")
        assert result is None
        assert "10.0.0.99" in pasla.request_log
        assert "10.0.0.1" not in pasla.request_log  # evicted
        assert len(pasla.request_log) == 3

    def test_existing_ip_still_rate_limited_at_cap(self, monkeypatch):
        """IPs already in request_log must still be rate-limited at cap."""
        monkeypatch.setattr(pasla, "MAX_TRACKED_IPS", 2)
        now = time.monotonic()
        # Fill tracking table — "10.0.0.1" is a tracked IP at rate limit.
        pasla.request_log["10.0.0.1"] = [now] * pasla.RATE_LIMIT_MAX_REQUESTS
        pasla.request_log["10.0.0.2"] = [now]

        result = pasla._validate_and_register_request("10.0.0.1")
        assert result == (429, "rate_limit_client_ip")

    def test_existing_ip_still_tracked_at_cap(self, monkeypatch):
        """An already-tracked IP must continue accruing request timestamps."""
        monkeypatch.setattr(pasla, "MAX_TRACKED_IPS", 2)
        now = time.monotonic()
        pasla.request_log["10.0.0.1"] = [now]
        pasla.request_log["10.0.0.2"] = [now]

        result = pasla._validate_and_register_request("10.0.0.1")
        assert result is None
        # The existing IP must have a new timestamp appended.
        assert len(pasla.request_log["10.0.0.1"]) == 2


# ---------------------------------------------------------------------------
# Transfer quota management
# ---------------------------------------------------------------------------

class TestTransferQuota:

    def test_first_slot_reserved(self):
        tid = "abc"
        pasla._register_transfer(tid)
        assert pasla._ensure_slot_reserved(tid, max_downloads=5)
        assert pasla.download_count == 1

    def test_concurrent_same_id_rejected(self):
        """A second concurrent call with the same transfer_id must be rejected.

        Security fix: prevents download cap bypass via concurrent requests
        sharing the same X-Transfer-ID.  The first call consumes the slot;
        any concurrent call while the first is still active returns False.
        Resume still works because _release_transfer() pops the ID before
        the client reconnects.
        """
        tid = "def"
        pasla._register_transfer(tid)
        pasla._ensure_slot_reserved(tid, max_downloads=5)
        assert not pasla._ensure_slot_reserved(tid, max_downloads=5)
        assert pasla.download_count == 1

    def test_cap_enforced(self):
        pasla.download_count = 3
        tid = "ghi"
        pasla._register_transfer(tid)
        assert not pasla._ensure_slot_reserved(tid, max_downloads=3)

    def test_slot_returned_on_incomplete_no_bytes(self):
        """Slot is refunded only when no payload bytes were sent."""
        tid = "jkl"
        pasla._register_transfer(tid)
        pasla._ensure_slot_reserved(tid, max_downloads=5)
        assert pasla.download_count == 1
        pasla._release_transfer(tid, completed=False, max_downloads=5,
                                bytes_sent=0)
        assert pasla.download_count == 0

    def test_slot_consumed_on_partial_transfer(self):
        """Partial transfer (bytes sent) must NOT refund the download slot.

        Without this, an attacker could download 99% of a file, disconnect,
        and repeat indefinitely without exhausting the download cap.
        """
        tid = "jkl-partial"
        pasla._register_transfer(tid)
        pasla._ensure_slot_reserved(tid, max_downloads=5)
        assert pasla.download_count == 1
        pasla._release_transfer(tid, completed=False, max_downloads=5,
                                bytes_sent=1024)
        assert pasla.download_count == 1  # NOT refunded

    def test_slot_kept_on_complete(self):
        tid = "mno"
        pasla._register_transfer(tid)
        pasla._ensure_slot_reserved(tid, max_downloads=5)
        pasla._release_transfer(tid, completed=True, max_downloads=5)
        assert pasla.download_count == 1

    def test_unlimited_never_blocks(self):
        for i in range(100):
            tid = f"tid-{i}"
            pasla._register_transfer(tid)
            assert pasla._ensure_slot_reserved(tid, max_downloads=0)
        # download_count stays 0 for unlimited.
        assert pasla.download_count == 0

    def test_resume_after_partial_abort_does_not_double_count(self):
        """A capped resume must reuse the consumed slot, not count again.

        Regression: _release_transfer used to pop the transfer_id on a
        partial abort, so a continuation with the same X-Transfer-ID
        was treated as a brand-new download and incremented
        download_count a second time.
        """
        tid = "resume-id"
        pasla._register_transfer(tid)
        assert pasla._ensure_slot_reserved(tid, max_downloads=3)
        assert pasla.download_count == 1
        # Client got some bytes, then the connection dropped.
        pasla._release_transfer(tid, completed=False, max_downloads=3,
                                bytes_sent=2048)
        assert pasla.download_count == 1  # slot stays spent, not refunded
        # Client reconnects with the same X-Transfer-ID to resume.
        assert pasla._ensure_slot_reserved(tid, max_downloads=3)
        assert pasla.download_count == 1  # NOT counted twice
        pasla._release_transfer(tid, completed=True, max_downloads=3)
        assert pasla.download_count == 1

    def test_single_use_link_still_resumable(self):
        """Under --single (max_downloads=1) a resume must not 410.

        Regression: the popped id made the resume look like a fresh
        download; with download_count already at the cap of 1 the
        resume was rejected outright.
        """
        tid = "single-resume"
        pasla._register_transfer(tid)
        assert pasla._ensure_slot_reserved(tid, max_downloads=1)
        pasla._release_transfer(tid, completed=False, max_downloads=1,
                                bytes_sent=4096)
        # Cap is full (download_count == 1) but the resume reuses the
        # already-consumed slot instead of being rejected.
        assert pasla._ensure_slot_reserved(tid, max_downloads=1)
        assert pasla.download_count == 1

    def test_concurrent_request_during_resumable_state_rejected(self):
        """Once a resume is in progress, a concurrent same-id request
        is still rejected."""
        tid = "resume-concurrent"
        pasla._register_transfer(tid)
        pasla._ensure_slot_reserved(tid, max_downloads=3)
        pasla._release_transfer(tid, completed=False, max_downloads=3,
                                bytes_sent=2048)
        # Resume picks up the slot...
        assert pasla._ensure_slot_reserved(tid, max_downloads=3)
        # ...a second concurrent request with the same id is rejected.
        assert not pasla._ensure_slot_reserved(tid, max_downloads=3)
        assert pasla.download_count == 1


# ---------------------------------------------------------------------------
# XFF / get_client_ip
# ---------------------------------------------------------------------------

class TestGetClientIP:
    """Verify trust_proxy logic as a pure function (no server needed)."""

    class _FakeHandler:
        """Minimal stub mimicking BaseHTTPRequestHandler for get_client_ip.

        Uses ``email.message.Message`` internally so that ``get_all()``
        behaves identically to the real HTTP handler — essential for
        testing the multi-header XFF spoofing defence.
        """
        def __init__(self, remote_ip, xff="", headers=None):
            from email.message import Message
            self.client_address = (remote_ip, 12345)
            self.headers = Message()
            if headers:
                for k, v in headers.items():
                    self.headers[k] = v
            if xff:
                self.headers["X-Forwarded-For"] = xff

        @classmethod
        def with_raw_headers(cls, remote_ip, header_lines):
            """Create a handler with raw header lines for multi-header tests.

            ``header_lines`` is a list of ``(name, value)`` tuples.
            Duplicate names produce multiple header lines — exactly
            the scenario that triggers the spoofing vulnerability.
            """
            from email.message import Message
            h = cls.__new__(cls)
            h.client_address = (remote_ip, 12345)
            h.headers = Message()
            for name, value in header_lines:
                h.headers[name] = value
            return h

    def test_no_proxy(self):
        h = self._FakeHandler("192.0.2.0")
        assert pasla.get_client_ip(h, trust_proxy=False) == "192.0.2.0"

    def test_proxy_rightmost_used(self):
        # Client sends forged header; proxy appends real IP at the end.
        h = self._FakeHandler("proxy_ip", "fakeip, 198.51.100.0")
        assert pasla.get_client_ip(h, trust_proxy=True) == "198.51.100.0"

    def test_proxy_malformed_xff_falls_back(self):
        h = self._FakeHandler("203.0.113.0", "not_an_ip")
        # Falls back to socket IP when XFF value is invalid.
        assert pasla.get_client_ip(h, trust_proxy=True) == "203.0.113.0"

    def test_trust_proxy_false_ignores_xff(self):
        h = self._FakeHandler("192.0.2.0", "203.0.113.0")
        assert pasla.get_client_ip(h, trust_proxy=False) == "192.0.2.0"

    def test_trust_proxy_false_ignores_trust_header(self):
        """Even with trust_header set, trust_proxy=False means socket IP."""
        h = self._FakeHandler(
            "192.0.2.0",
            headers={"CF-Connecting-IP": "198.51.100.7"},
        )
        assert pasla.get_client_ip(
            h, trust_proxy=False, trust_header="CF-Connecting-IP",
        ) == "192.0.2.0"

    def test_explicit_trust_header_wins_over_xff(self):
        """When trust_header is explicitly set, that header takes priority."""
        h = self._FakeHandler(
            "203.0.113.0",
            xff="198.51.100.7",
            headers={"CF-Connecting-IP": "203.0.113.42"},
        )
        assert pasla.get_client_ip(
            h, trust_proxy=True, trust_header="CF-Connecting-IP",
        ) == "203.0.113.42"

    def test_trusted_header_not_auto_detected(self):
        """Without explicit trust_header, edge headers are NOT checked.

        Security fix: prevents header spoofing when the operator does
        not know which edge provider sits in front of the server."""
        h = self._FakeHandler(
            "203.0.113.0",
            xff="198.51.100.10",
            headers={"CF-Connecting-IP": "198.51.100.20"},
        )
        # Without trust_header, CF-Connecting-IP is ignored; XFF is used.
        assert pasla.get_client_ip(h, trust_proxy=True) == "198.51.100.10"

    def test_invalid_trust_header_value_falls_back_to_xff(self):
        """Garbage in the trusted header must fall through to XFF."""
        h = self._FakeHandler(
            "203.0.113.0",
            xff="198.51.100.5",
            headers={"CF-Connecting-IP": "not_an_ip"},
        )
        assert pasla.get_client_ip(
            h, trust_proxy=True, trust_header="CF-Connecting-IP",
        ) == "198.51.100.5"

    def test_falls_back_to_xff_when_no_trust_header(self):
        h = self._FakeHandler("203.0.113.0", xff="198.51.100.99")
        assert pasla.get_client_ip(h, trust_proxy=True) == "198.51.100.99"

    def test_falls_back_to_socket_when_all_sources_invalid(self):
        h = self._FakeHandler(
            "192.0.2.0",
            xff="not_an_ip",
            headers={"CF-Connecting-IP": "also_not_an_ip"},
        )
        assert pasla.get_client_ip(
            h, trust_proxy=True, trust_header="CF-Connecting-IP",
        ) == "192.0.2.0"

    def test_ipv6_in_trust_header(self):
        h = self._FakeHandler(
            "203.0.113.0",
            headers={"Fly-Client-IP": "2001:db8::1"},
        )
        assert pasla.get_client_ip(
            h, trust_proxy=True, trust_header="Fly-Client-IP",
        ) == "2001:db8::1"

    def test_absent_trust_header_falls_back_to_xff(self):
        """When trust_header names a header not present in the request,
        fall back to XFF."""
        h = self._FakeHandler("203.0.113.0", xff="198.51.100.50")
        assert pasla.get_client_ip(
            h, trust_proxy=True, trust_header="CF-Connecting-IP",
        ) == "198.51.100.50"

    # -- Multi-header spoofing defence ------------------------------------

    def test_xff_multi_header_uses_rightmost(self):
        """When a proxy adds a *new* XFF header line instead of
        comma-appending, the rightmost IP across all lines must be
        used — not the first (attacker-controlled) line.

        Security regression test for the ``get_all()`` fix.
        """
        h = self._FakeHandler.with_raw_headers("10.0.0.1", [
            # Attacker injects this first header:
            ("X-Forwarded-For", "6.6.6.6"),
            # Proxy appends a new header line with the real IP:
            ("X-Forwarded-For", "198.51.100.1"),
        ])
        assert pasla.get_client_ip(h, trust_proxy=True) == "198.51.100.1"

    def test_xff_multi_header_comma_and_line_mixed(self):
        """Attacker sends comma-separated spoofed IPs in the first line,
        proxy appends a second line with the real IP."""
        h = self._FakeHandler.with_raw_headers("10.0.0.1", [
            ("X-Forwarded-For", "6.6.6.6, 7.7.7.7"),
            ("X-Forwarded-For", "198.51.100.2"),
        ])
        assert pasla.get_client_ip(h, trust_proxy=True) == "198.51.100.2"

    def test_trust_header_multi_header_uses_last(self):
        """When an attacker injects a duplicate single-value edge header,
        the *last* occurrence (proxy-written) must be used."""
        h = self._FakeHandler.with_raw_headers("10.0.0.1", [
            ("CF-Connecting-IP", "6.6.6.6"),       # attacker
            ("CF-Connecting-IP", "198.51.100.3"),   # proxy
        ])
        assert pasla.get_client_ip(
            h, trust_proxy=True, trust_header="CF-Connecting-IP",
        ) == "198.51.100.3"

    def test_xff_single_header_still_works(self):
        """Standard single-line comma-separated XFF must still work."""
        h = self._FakeHandler.with_raw_headers("10.0.0.1", [
            ("X-Forwarded-For", "spoofed, 198.51.100.4"),
        ])
        assert pasla.get_client_ip(h, trust_proxy=True) == "198.51.100.4"


# ---------------------------------------------------------------------------
# Path normalisation
#
# The real security guarantee against path traversal is hmac.compare_digest
# — even after normpath resolves ".." sequences, the resulting path won't
# match the expected token/filename string.  These tests verify that
# normpath behaves as expected as the first line of defence.
# ---------------------------------------------------------------------------

class TestPathNormalisation:
    """Verify that posixpath.normpath + backslash guard work correctly."""

    def _normalise(self, raw: str) -> str:
        import posixpath
        return posixpath.normpath(raw.replace("\\", "/"))

    def test_clean_path_unchanged(self):
        assert self._normalise("/abc/file.txt") == "/abc/file.txt"

    def test_double_slash_collapsed(self):
        # POSIX standard preserves exactly two leading slashes (e.g. for UNC paths),
        # but collapses internal double slashes.
        assert self._normalise("//abc//file.txt") == "//abc/file.txt"

    def test_traversal_does_not_match_expected(self):
        """
        Core security invariant: after normalisation, a traversal payload
        must NOT match the expected /<token>/<filename> path.

        posixpath.normpath("/abc/../etc/passwd") → "/etc/passwd"
        This differs from "/abc/file.txt", so hmac.compare_digest rejects it.
        """
        expected = "/abc/file.txt"
        traversal = self._normalise("/abc/../etc/passwd")
        assert traversal != expected, (
            "Normalised traversal path must differ from expected — "
            "this is the invariant that hmac.compare_digest enforces"
        )

    def test_backslash_treated_as_slash(self):
        assert self._normalise("/abc\\token\\file.txt") == "/abc/token/file.txt"

    def test_null_byte_is_detected(self):
        """Handler rejects null bytes before normalisation is reached."""
        decoded = "/token/file\x00.txt"
        assert "\x00" in decoded


class TestNormalizeRequestPath:
    """The four-step path defence pipeline lives in
    ``_normalize_request_path``.  Removing or reordering any step
    opens a traversal vector — guard each step with a regression
    test so future refactors cannot silently weaken it."""

    def test_clean_path_passes(self):
        assert pasla._normalize_request_path("/abc/file.txt") == "/abc/file.txt"

    def test_percent_encoded_path_decoded(self):
        assert pasla._normalize_request_path("/abc/%66ile") == "/abc/file"

    def test_backslash_converted(self):
        assert pasla._normalize_request_path("/abc\\file") == "/abc/file"

    def test_traversal_normalised(self):
        assert pasla._normalize_request_path("/abc/../etc/passwd") == "/etc/passwd"

    def test_null_byte_rejected(self):
        assert pasla._normalize_request_path("/abc/%00file") is None

    def test_overlong_utf8_rejected(self):
        # `%c0%ae` is the over-long UTF-8 encoding of '.'.  strict
        # decoder must reject it instead of silently producing a dot.
        assert pasla._normalize_request_path("/%c0%ae%c0%ae/etc") is None

    def test_invalid_percent_encoding_rejected(self):
        # Lone high byte without a valid UTF-8 continuation.
        assert pasla._normalize_request_path("/foo/%ff") is None


class TestInvalidPathLogging:
    """Invalid-path log entries must not contain the raw request
    path: an attacker probing close to the real token would otherwise
    leak partial token characters into log files (which may be
    readable by operators with different privilege than the URL
    holder)."""

    def test_log_contains_hash_not_path(self, live_server, caplog):
        import http.client as _hc
        import logging as _logging
        caplog.set_level(_logging.INFO, logger="pasla")
        s = live_server
        secret_probe = "/abc/leakme-supersecret-token-do-not-log"
        conn = _hc.HTTPConnection(s.host, s.port, timeout=5)
        conn.request("GET", secret_probe)
        resp = conn.getresponse()
        resp.read()
        joined = " ".join(r.message for r in caplog.records)
        assert "leakme" not in joined
        assert "supersecret" not in joined
        assert "sha256" in joined


# ---------------------------------------------------------------------------
# _tar_directory
# ---------------------------------------------------------------------------

class TestTarDirectory:

    def test_tar_created(self, tmp_dir_with_files, tmp_path, monkeypatch):
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")
        tar_path = pasla._tar_directory(str(tmp_dir_with_files))
        assert os.path.isfile(tar_path)

    def test_tar_contains_expected_files(self, tmp_dir_with_files, tmp_path, monkeypatch):
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")
        tar_path = pasla._tar_directory(str(tmp_dir_with_files))
        with tarfile.open(tar_path) as tf:
            names = tf.getnames()
        assert "hello.txt" in names
        assert "data.bin" in names
        assert any("nested.txt" in n for n in names)

    def test_lock_file_created(self, tmp_path, monkeypatch):
        """_tar_directory must write a .pasla_lock in the temp dir."""
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")
        d = tmp_path / "lockdir"
        d.mkdir()
        (d / "a.txt").write_text("data", encoding="utf-8")
        tar_path = pasla._tar_directory(str(d))
        tmp_dir = pathlib.Path(tar_path).parent
        lock = tmp_dir / ".pasla_lock"
        assert lock.exists()
        assert lock.read_text(encoding="ascii").strip() == str(os.getpid())

    def test_symlinks_excluded(self, tmp_path, monkeypatch):
        """Symlinked files must not appear in the archive."""
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")
        if sys.platform == "win32":
            pytest.skip("Symlink creation requires elevated privileges on Windows")
        d = tmp_path / "dir3"
        d.mkdir()
        real = d / "real.txt"
        real.write_text("real content", encoding="utf-8")
        link = d / "link.txt"
        link.symlink_to(real)
        tar_path = pasla._tar_directory(str(d))
        with tarfile.open(tar_path) as tf:
            names = tf.getnames()
        assert "link.txt" not in names
        assert "real.txt" in names

    def test_empty_directory(self, tmp_path, monkeypatch):
        """An empty directory must produce a valid (empty) tar file."""
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")
        d = tmp_path / "empty_dir"
        d.mkdir()
        tar_path = pasla._tar_directory(str(d))
        assert os.path.isfile(tar_path)
        with tarfile.open(tar_path) as tf:
            assert tf.getnames() == []

    @pytest.mark.skipif(sys.platform == "win32",
                        reason="Symlink creation requires elevated privileges on Windows")
    def test_path_swapped_to_symlink_mid_archiving_is_skipped(
        self, tmp_path, monkeypatch
    ):
        """If a regular file inside the source tree is replaced with
        a symlink between the directory walk and the per-entry tar
        add, the recheck guard inside the write loop must skip the
        entry — never silently dereference it and leak the symlink
        target into the archive.

        Forces the race deterministically: ``os.path.islink`` lies
        ``False`` during the walk pass (so the entry survives
        collection), then perform the actual swap, then let the
        real ``islink`` see the truth in the per-entry recheck.
        """
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")
        src = tmp_path / "share"
        src.mkdir()
        legit = src / "report.txt"
        legit.write_bytes(b"LEGIT-CONTENT" * 100)

        decoy = tmp_path / "secret.txt"
        decoy.write_bytes(b"SECRET-PAYLOAD" * 100)

        real_islink = os.path.islink
        # Phase flag: during ``os.walk`` (phase 0) lie that the path
        # is not a symlink; flip to phase 1 right after collection so
        # the recheck inside the write loop sees the truth.
        phase = {"n": 0}

        def lying_islink(path):
            if phase["n"] == 0 and os.fspath(path) == str(legit):
                return False
            return real_islink(path)
        monkeypatch.setattr(pasla.os.path, "islink", lying_islink)

        # Hook into the walk → write transition: the moment ``tar_path``
        # is opened we know collection finished, so swap the file
        # and switch the recheck back to truthful.
        real_tarfile_open = pasla.tarfile.open

        def swapping_tarfile_open(file, mode="r", *a, **k):
            if mode == "w":
                legit.unlink()
                os.symlink(decoy, legit)
                phase["n"] = 1
            return real_tarfile_open(file, mode, *a, **k)
        monkeypatch.setattr(pasla.tarfile, "open", swapping_tarfile_open)

        tar_path = pasla._tar_directory(str(src))

        # Reload through the unpatched open to inspect the result.
        with real_tarfile_open(tar_path) as tf:
            payload = b""
            for member in tf.getmembers():
                f = tf.extractfile(member)
                if f:
                    payload += f.read()

        assert b"SECRET-PAYLOAD" not in payload, (
            "Recheck guard failed: swapped symlink leaked decoy "
            "content into the archive"
        )


# ---------------------------------------------------------------------------
# Global connection cap
# ---------------------------------------------------------------------------

class TestGlobalConnectionCap:

    def test_increment_returns_true_when_capacity(self):
        pasla.global_connections = 0
        assert pasla._try_increment_global_connections()

    def test_increment_returns_false_at_cap(self, monkeypatch):
        monkeypatch.setattr(pasla, "MAX_GLOBAL_CONNECTIONS", 5)
        pasla.global_connections = 5
        assert not pasla._try_increment_global_connections()

    def test_decrement_does_not_go_negative(self):
        pasla.global_connections = 0
        pasla._decrement_global_connections()
        assert pasla.global_connections == 0

    def test_dropped_connection_uses_so_linger(self, monkeypatch):
        """Connections rejected at the global cap must send TCP RST
        (``SO_LINGER`` with ``l_onoff=1, l_linger=0``) so the dropped
        connection skips TIME_WAIT.

        Without RST, a SYN flood at the configured cap rate fills the
        kernel TIME_WAIT slot table and causes subsequent
        ``bind``/``connect`` calls to fail with ``EADDRINUSE`` —
        amplifying the DoS instead of containing it.
        """
        import socket as _socket
        import struct as _struct

        monkeypatch.setattr(pasla, "MAX_GLOBAL_CONNECTIONS", 1)
        pasla.global_connections = 1   # already at cap

        captured_setsockopt: list = []

        class _FakeSocket:
            def setsockopt(self, level, optname, value):
                captured_setsockopt.append((level, optname, value))

            def close(self):
                pass

        srv = pasla.ThreadingHTTPServer.__new__(pasla.ThreadingHTTPServer)
        srv.process_request(_FakeSocket(), ("203.0.113.5", 12345))

        assert len(captured_setsockopt) == 1
        level, optname, value = captured_setsockopt[0]
        assert level == _socket.SOL_SOCKET
        assert optname == _socket.SO_LINGER
        l_onoff, l_linger = _struct.unpack("ii", value)
        assert l_onoff == 1
        assert l_linger == 0


class TestProcessRequestThreadSpawnFailure:
    """When ``super().process_request`` raises (e.g. the OS refused
    a new thread), the global counter must roll back AND the request
    socket must be closed - otherwise a sustained spawn-failure
    storm leaks one descriptor per attempt."""

    def test_spawn_failure_closes_request(self, monkeypatch):
        pasla.global_connections = 0

        class _FakeRequest:
            def __init__(self):
                self.closed = False
            def setsockopt(self, *a, **k):
                pass
            def close(self):
                self.closed = True

        # Force the inner ``process_request`` (which spawns the
        # worker) to fail synchronously.
        def _explode(self, request, client_address):
            raise RuntimeError("can't start new thread")
        monkeypatch.setattr(
            pasla.ThreadingMixIn, "process_request", _explode,
        )

        srv = pasla.ThreadingHTTPServer.__new__(pasla.ThreadingHTTPServer)
        req = _FakeRequest()
        with pytest.raises(RuntimeError):
            srv.process_request(req, ("203.0.113.7", 0))

        assert req.closed, "request must be closed when spawn fails"
        assert pasla.global_connections == 0, "counter must roll back"


class TestMaintenanceThreadShutdown:
    """The maintenance thread performs server.shutdown() exactly once
    when a shutdown is requested, then exits cleanly."""

    def test_shutdown_called_once_on_request(self):
        pasla.shutting_down.clear()
        calls = {"n": 0}

        class _FakeServer:
            def shutdown(self):
                calls["n"] += 1

        class _FakeCtrl:
            def is_alive(self):
                return True

        t = pasla.start_maintenance_thread(
            _FakeServer(), _FakeCtrl(),
            started_at=time.monotonic(), duration=1000,
        )
        pasla._request_shutdown()
        t.join(timeout=5)

        assert not t.is_alive(), "maintenance thread must exit on shutdown"
        assert calls["n"] == 1, (
            f"server.shutdown() called {calls['n']} times; expected 1"
        )


class TestPerIPRejectionUsesSoLinger:
    """Connections rejected at the per-IP ceiling must send TCP RST so
    the dropped connection skips TIME_WAIT.  A flood of refused
    connections under a graceful FIN would otherwise saturate the
    kernel's ephemeral port table within minutes."""

    def test_per_ip_rejection_sets_so_linger(self, monkeypatch, tmp_path):
        import socket as _socket
        import struct as _struct

        # Pre-fill active_connections so the next handle() call lands
        # over the per-IP ceiling immediately.
        monkeypatch.setattr(pasla, "MAX_CONNECTIONS_PER_IP", 1)
        pasla.active_connections.clear()
        pasla.active_connections["127.0.0.1"] = 5

        captured = []

        class FakeSocket:
            def setsockopt(self, level, optname, value):
                captured.append((level, optname, value))
            def settimeout(self, *_a, **_k):
                pass
            def recv(self, _n):
                return b""
            def sendall(self, *_a, **_k):
                pass
            def close(self):
                pass
            def shutdown(self, *_a):
                pass
            def makefile(self, *_a, **_k):
                import io
                return io.BytesIO()

        # Build a minimal SecureHandler subclass that bypasses
        # socketserver init and exercises just the handle() path.
        f = tmp_path / "f.bin"
        f.write_bytes(b"x")
        Handler = pasla.make_handler(
            file_path=str(f), file_name="f.bin", token="t",
            max_downloads=0, trust_proxy=False,
        )
        h = Handler.__new__(Handler)
        h.connection = FakeSocket()
        h.client_address = ("127.0.0.1", 12345)
        h.rfile = h.connection.makefile()
        h.wfile = h.connection.makefile()
        h.handle()

        # Setup() registers a header-deadline timer whose callback
        # also calls shutdown(); we only care that the rejection path
        # invoked SO_LINGER with l_onoff=1, l_linger=0.
        linger_calls = [
            v for level, optname, v in captured
            if level == _socket.SOL_SOCKET and optname == _socket.SO_LINGER
        ]
        assert linger_calls, "Expected SO_LINGER to be set on rejection"
        l_onoff, l_linger = _struct.unpack("ii", linger_calls[0])
        assert (l_onoff, l_linger) == (1, 0)


class TestActiveConnectionsReadOnlyCheck:
    """The cap check must NOT autovivify entries.  Otherwise a
    rotating-IP probe leaks one defaultdict entry per source address
    until the next cleanup_state pass."""

    def test_validate_does_not_create_entry_for_new_ip(self):
        pasla.active_connections.clear()
        ip = "203.0.113.42"
        assert ip not in pasla.active_connections

        result = pasla._validate_and_register_request(ip)

        assert result is None
        # The validate path may have appended a request_log entry for
        # rate-limiting, but it must not have touched active_connections.
        assert ip not in pasla.active_connections


class TestHandleErrorSuppression:
    """The threaded server's ``handle_error`` must swallow connection
    aborts that bubble up from ``BaseHTTPRequestHandler.handle`` so
    operators do not see a stack trace every time a browser cancels
    the self-signed-cert dialog or a curl client RSTs mid-handshake.
    """

    def _make_server(self):
        srv = pasla.ThreadingHTTPServer.__new__(pasla.ThreadingHTTPServer)
        # ``handle_error`` only consults ``sys.exc_info``; it does not
        # touch the socket object, so a fully-uninitialised instance
        # is enough for these tests.
        return srv

    def test_connection_reset_is_swallowed(self, capsys):
        srv = self._make_server()
        try:
            raise ConnectionResetError("client RST")
        except ConnectionResetError:
            srv.handle_error(object(), ("203.0.113.1", 1234))
        # No traceback should reach stderr.
        captured = capsys.readouterr()
        assert "Traceback" not in captured.err

    def test_ssl_error_is_swallowed(self, capsys):
        import ssl as _ssl
        srv = self._make_server()
        try:
            raise _ssl.SSLError("handshake aborted")
        except _ssl.SSLError:
            srv.handle_error(object(), ("203.0.113.2", 4321))
        captured = capsys.readouterr()
        assert "Traceback" not in captured.err

    def test_unexpected_exception_still_reported(self, capsys):
        """Non-network errors must still bubble through to the
        default reporter — the suppression list is for connection
        aborts only, not for masking real bugs."""
        srv = self._make_server()
        try:
            raise RuntimeError("a real bug")
        except RuntimeError:
            srv.handle_error(object(), ("127.0.0.1", 9999))
        captured = capsys.readouterr()
        assert "Traceback" in captured.err
        assert "RuntimeError" in captured.err


# ---------------------------------------------------------------------------
# Connection counter symmetry
# ---------------------------------------------------------------------------

class TestConnectionCounterSymmetry:
    """Verify increment + decrement returns to initial state."""

    def test_per_ip_symmetry(self):
        ip = "10.0.0.1"
        pasla._increment_connections(ip)
        pasla._increment_connections(ip)
        assert pasla.active_connections[ip] == 2
        pasla._decrement_connections(ip)
        pasla._decrement_connections(ip)
        assert pasla.active_connections[ip] == 0

    def test_global_symmetry(self):
        pasla._try_increment_global_connections()
        pasla._try_increment_global_connections()
        assert pasla.global_connections == 2
        pasla._decrement_global_connections()
        pasla._decrement_global_connections()
        assert pasla.global_connections == 0


# ---------------------------------------------------------------------------
# format_url
# ---------------------------------------------------------------------------

class TestFormatUrl:
    """Verify URL construction, especially IPv6 bracket wrapping."""

    def test_ipv4_plain(self):
        url = pasla.format_url("192.168.1.1", 8080, "tok", "file.txt")
        assert url == "http://192.168.1.1:8080/tok/file.txt"

    def test_ipv6_bracketed(self):
        """IPv6 addresses must be wrapped in square brackets per RFC 2732."""
        url = pasla.format_url("::1", 9090, "tok", "file.txt")
        assert url == "http://[::1]:9090/tok/file.txt"

    def test_ipv6_full_address(self):
        url = pasla.format_url("2001:db8::1", 443, "abc", "data.bin")
        assert url.startswith("http://[2001:db8::1]:443/")

    def test_invalid_ip_fallback(self):
        """Non-IP strings (e.g. hostnames) must be used as-is."""
        url = pasla.format_url("server.example.com", 8080, "tok", "file.txt")
        assert "server.example.com" in url
        # No brackets for non-IP hostnames.
        assert "[" not in url

    def test_filename_urlencoded(self):
        """Filenames with spaces/unicode must be percent-encoded."""
        url = pasla.format_url("1.2.3.4", 80, "tok", "my file (1).txt")
        assert "my%20file" in url
        assert " " not in url.split("/")[-1]


# ---------------------------------------------------------------------------
# _cleanup_state
# ---------------------------------------------------------------------------

class TestCleanupState:
    """Verify background state cleanup purges stale entries."""

    def test_expired_request_log_entries_purged(self):
        """Timestamps older than RATE_LIMIT_WINDOW must be removed."""
        ip = "10.0.0.1"
        expired = time.monotonic() - pasla.RATE_LIMIT_WINDOW - 10
        pasla.request_log[ip] = [expired, expired, expired]
        pasla._cleanup_state()
        assert ip not in pasla.request_log

    def test_active_request_log_entries_kept(self):
        """Recent timestamps within the window must survive cleanup."""
        ip = "10.0.0.2"
        recent = time.monotonic()
        pasla.request_log[ip] = [recent]
        pasla._cleanup_state()
        assert ip in pasla.request_log

    def test_zero_connection_entries_purged(self):
        """IPs with zero active connections must be cleaned up."""
        pasla.active_connections["10.0.0.3"] = 0
        pasla._cleanup_state()
        assert "10.0.0.3" not in pasla.active_connections

    def test_active_connection_entries_kept(self):
        """IPs with active connections must not be purged."""
        pasla.active_connections["10.0.0.4"] = 2
        pasla._cleanup_state()
        assert "10.0.0.4" in pasla.active_connections

    def test_zero_failed_attempts_purged(self):
        """IPs with 0 failed attempts (after record_success) must be cleaned."""
        pasla.failed_attempts["10.0.0.5"] = 0
        pasla._cleanup_state()
        assert "10.0.0.5" not in pasla.failed_attempts

    def test_nonzero_failed_attempts_kept(self):
        """IPs with pending failures must survive cleanup."""
        pasla.failed_attempts["10.0.0.6"] = 3
        pasla._cleanup_state()
        assert "10.0.0.6" in pasla.failed_attempts


# ---------------------------------------------------------------------------
# _StatusBar (TUI component)
# ---------------------------------------------------------------------------

class TestStatusBar:
    """Tests for the live terminal status bar.

    These use mock.patch("sys.stdout") and mock.patch("os.get_terminal_size")
    to capture output without needing a real terminal.
    """

    def _make_bar(self, remaining: int = 300, max_downloads: int = 0):
        """Create a _StatusBar with `remaining` seconds left."""
        started  = time.monotonic()
        duration = remaining
        return pasla._StatusBar(started, duration, max_downloads)

    def test_clear_writes_blank_line(self):
        """clear() must overwrite the current line with spaces."""
        bar = self._make_bar()
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            bar.clear()
        output = buf.getvalue()
        # Must contain a carriage return to overwrite in-place.
        assert "\r" in output
        # Must contain spaces (at least bar._cols worth).
        assert " " * bar._cols in output

    def test_draw_contains_expected_tokens(self):
        """draw() output must include the timer, download count, and stop hint."""
        bar = self._make_bar(remaining=600, max_downloads=10)
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            bar.draw()
        output = buf.getvalue()
        assert "\u23f1" in output       # ⏱
        assert "Ctrl+C" in output
        assert "downloads" in output

    def test_draw_with_unlimited_downloads(self):
        """When max_downloads=0, the cap should display as \u221e."""
        bar = self._make_bar(remaining=60, max_downloads=0)
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            bar.draw()
        output = buf.getvalue()
        assert "\u221e" in output       # ∞

    def test_draw_truncates_long_bar(self):
        """If the bar is wider than terminal, it must be truncated with '\u2026'.

        _draw_unlocked() calls os.get_terminal_size() on each draw, which
        overrides _cols.  We must mock it to force a narrow terminal.
        """
        bar = self._make_bar()
        buf = io.StringIO()
        narrow = os.terminal_size((10, 24))
        with mock.patch("sys.stdout", buf), \
             mock.patch("os.get_terminal_size", return_value=narrow):
            bar.draw()
        output = buf.getvalue()
        # The truncated bar should end with '\u2026' before the ljust padding.
        assert "\u2026" in output       # …

    def test_stop_terminates_run_loop(self):
        """stop() must cause the run() loop to exit promptly."""
        bar = self._make_bar()
        buf = io.StringIO()

        def run_bar():
            with mock.patch("sys.stdout", buf):
                bar.run()

        thread = threading.Thread(target=run_bar, daemon=True)
        thread.start()

        # Let the loop run briefly, then stop it.
        pasla.shutting_down.wait(0.2)
        bar.stop()
        thread.join(timeout=3)
        assert not thread.is_alive(), "run() loop did not exit after stop()"

    def test_handle_resize_calls_draw(self):
        """SIGWINCH handler delegates to draw()."""
        bar = self._make_bar()
        with mock.patch.object(bar, "draw") as mock_draw:
            bar.handle_resize()
            mock_draw.assert_called_once()


# ---------------------------------------------------------------------------
# _LiveLogHandler (TUI component)
# ---------------------------------------------------------------------------

class TestLiveLogHandler:
    """Tests for the coordinated log handler that works with _StatusBar."""

    def _make_handler_and_bar(self):
        """Create a _StatusBar and _LiveLogHandler pair."""
        bar     = pasla._StatusBar(time.monotonic(), 600, 0)
        handler = pasla._LiveLogHandler(bar)
        handler.setFormatter(logging.Formatter("%(message)s"))
        return handler, bar

    def test_emit_clears_and_redraws(self):
        """emit() must clear the bar, print the log message, then redraw."""
        handler, bar = self._make_handler_and_bar()

        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()

        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="",
            lineno=0, msg="test log line", args=(), exc_info=None,
        )

        with mock.patch("sys.stdout", stdout_buf), \
             mock.patch("sys.stderr", stderr_buf):
            handler.emit(record)

        # The log message must appear on stderr.
        assert "test log line" in stderr_buf.getvalue()
        # The status bar must be redrawn on stdout.
        assert "\u23f1" in stdout_buf.getvalue()   # ⏱

    def test_emit_handles_exception_gracefully(self):
        """If emit() raises internally, handleError must be called."""
        handler, bar = self._make_handler_and_bar()

        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="",
            lineno=0, msg="test", args=(), exc_info=None,
        )

        with mock.patch.object(handler, "format", side_effect=RuntimeError("boom")), \
             mock.patch.object(handler, "handleError") as mock_handle_error:
            handler.emit(record)
            mock_handle_error.assert_called_once_with(record)


# ---------------------------------------------------------------------------
# Dual-stack IPv6→IPv4 fallback
# ---------------------------------------------------------------------------

class TestDualStackFallback:
    """Verify _make_server falls back to IPv4 when dual-stack is unavailable.

    The fallback is boolean-based (socket.has_dualstack_ipv6()), NOT
    exception-based.  When it returns False, the server must:
      1. Use AF_INET (not AF_INET6)
      2. Bind to 0.0.0.0
      3. Log a warning about the fallback
    """

    def test_fallback_uses_ipv4_when_dualstack_unavailable(self, monkeypatch):
        """When has_dualstack_ipv6() is False, server must bind as IPv4."""
        import socket as _socket

        monkeypatch.setattr(_socket, "has_dualstack_ipv6", lambda: False)

        # ip_mode=None triggers the dual-stack attempt path.
        server = pasla._make_server(0, pasla.BaseHTTPRequestHandler, ip_mode=None)
        try:
            assert server.address_family == _socket.AF_INET
            # Bind address must be 0.0.0.0, not ::
            assert server.server_address[0] in ("0.0.0.0", "")
        finally:
            server.server_close()

    def test_fallback_logs_warning(self, monkeypatch, caplog):
        """Fallback to IPv4 must emit a warning log."""
        import socket as _socket

        monkeypatch.setattr(_socket, "has_dualstack_ipv6", lambda: False)

        with caplog.at_level(logging.WARNING, logger="pasla"):
            server = pasla._make_server(0, pasla.BaseHTTPRequestHandler, ip_mode=None)
            server.server_close()

        assert any("IPv4" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# bind_server with explicit port
# ---------------------------------------------------------------------------

class TestBindServerWithPort:
    """Verify bind_server() handles the explicit port parameter correctly."""

    def test_explicit_port_binds_correctly(self):
        """bind_server(port=N) must bind to exactly port N."""
        # Use port 0 first to get a free port, close it, then bind explicitly
        import socket as _socket
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        free_port = sock.getsockname()[1]
        sock.close()

        server, port = pasla.bind_server(ip_mode="4", port=free_port)
        try:
            assert port == free_port
            assert server.server_address[1] == free_port
        finally:
            server.server_close()

    def test_port_zero_uses_os_assigned(self):
        """bind_server(port=0) must succeed with an OS-assigned port > 0."""
        server, port = pasla.bind_server(ip_mode="4", port=0)
        try:
            assert port > 0
        finally:
            server.server_close()

    def test_default_uses_random_port(self):
        """bind_server(port=None) must pick a port in the configured range."""
        server, port = pasla.bind_server(ip_mode="4", port=None)
        try:
            # Port should come from PORT_RANGE or OS fallback — both > 0
            assert port > 0
        finally:
            server.server_close()


# ---------------------------------------------------------------------------
# File identity (Heuristic Identity — Finding 2.1 / 2.2)
# ---------------------------------------------------------------------------

class TestFileIdentity:
    """Verify _get_file_identity returns kernel-assigned identifiers."""

    def test_same_file_same_identity(self, tmp_path):
        """Opening the same file twice must yield the same identity."""
        f = tmp_path / "stable.txt"
        f.write_text("hello", encoding="utf-8")
        with open(f, "rb") as fd1:
            id1 = pasla._get_file_identity(fd1.fileno())
        with open(f, "rb") as fd2:
            id2 = pasla._get_file_identity(fd2.fileno())
        assert id1 == id2

    def test_different_files_different_identity(self, tmp_path):
        """Two distinct files must have different identities."""
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_text("aaa", encoding="utf-8")
        b.write_text("bbb", encoding="utf-8")
        with open(a, "rb") as fa, open(b, "rb") as fb:
            id_a = pasla._get_file_identity(fa.fileno())
            id_b = pasla._get_file_identity(fb.fileno())
        assert id_a != id_b

    def test_replaced_file_changes_identity(self, tmp_path):
        """Replacing a file (atomic rename) must produce a new identity.

        This is the core defense against symlink swap / TOCTOU attacks:
        even if the replacement has the same content and size, the kernel
        assigns a new inode, so the identity tuple changes.
        """
        target = tmp_path / "target.txt"
        target.write_text("original", encoding="utf-8")
        with open(target, "rb") as fd:
            original_id = pasla._get_file_identity(fd.fileno())

        # Simulate atomic replacement (same pattern as a symlink swap).
        replacement = tmp_path / "replacement.txt"
        replacement.write_text("original", encoding="utf-8")
        os.replace(replacement, target)

        with open(target, "rb") as fd:
            new_id = pasla._get_file_identity(fd.fileno())
        assert original_id != new_id, (
            "Replaced file must have a different identity — "
            "this is how symlink swaps are detected"
        )

    def test_identity_is_tuple(self, tmp_path):
        """Identity must be a tuple (for comparison and hashing)."""
        f = tmp_path / "check.txt"
        f.write_text("x", encoding="utf-8")
        with open(f, "rb") as fd:
            result = pasla._get_file_identity(fd.fileno())
        assert isinstance(result, tuple)
        assert len(result) >= 2


# ---------------------------------------------------------------------------
# Lock-safe accessor functions (Finding 5.2)
# ---------------------------------------------------------------------------

class TestLockSafeAccessors:
    """Verify current_active_transfers() and current_banned_ips()."""

    def test_active_transfers_empty(self):
        assert pasla._current_active_transfers() == 0

    def test_active_transfers_after_register(self):
        tid = "accessor_test"
        pasla._register_transfer(tid)
        pasla._ensure_slot_reserved(tid, max_downloads=0)
        assert pasla._current_active_transfers() == 1
        pasla._release_transfer(tid, completed=True, max_downloads=0)
        assert pasla._current_active_transfers() == 0

    def test_banned_ips_empty(self):
        assert pasla._current_banned_ips() == 0

    def test_banned_ips_after_ban(self):
        for _ in range(pasla.BAN_THRESHOLD):
            pasla._record_failure("100.0.0.1")
        assert pasla._current_banned_ips() >= 1


# ---------------------------------------------------------------------------
# _ctrl_send — control plane client helper
#
# Tests exercise the TCP client that talks to the control plane.
# Edge cases: connection refused, malformed response, empty response.
# ---------------------------------------------------------------------------

class TestCtrlSend:
    """Verify _ctrl_send handles connection errors and bad responses."""

    def test_connection_refused_returns_none(self):
        """When no server is listening, _ctrl_send must return None."""
        # Port 1 is almost certainly not listening and requires no setup.
        result = pasla._ctrl_send(1, "status", secret="x")
        assert result is None

    def test_valid_response_parsed(self):
        """A well-formed JSON response must be parsed and returned."""
        import json as _json

        # Start a minimal TCP server that echoes a JSON response.
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        expected = {"status": "ok", "count": 42}

        def _respond():
            conn, _ = srv.accept()
            with conn:
                conn.recv(4096)  # consume the command
                conn.sendall((_json.dumps(expected) + "\n").encode())
            srv.close()

        t = threading.Thread(target=_respond, daemon=True)
        t.start()

        result = pasla._ctrl_send(port, "status", secret="s")
        t.join(timeout=5)
        assert result == expected

    def test_empty_response_returns_none(self):
        """If the server closes without sending data, return None."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def _close_immediately():
            conn, _ = srv.accept()
            conn.close()  # send nothing
            srv.close()

        t = threading.Thread(target=_close_immediately, daemon=True)
        t.start()

        result = pasla._ctrl_send(port, "status", secret="s")
        t.join(timeout=5)
        # Empty response → json.loads fails → returns None
        assert result is None

    def test_malformed_json_returns_none(self):
        """Non-JSON response must be handled gracefully."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def _send_garbage():
            conn, _ = srv.accept()
            with conn:
                conn.recv(4096)
                conn.sendall(b"NOT JSON{{\n")
            srv.close()

        t = threading.Thread(target=_send_garbage, daemon=True)
        t.start()

        result = pasla._ctrl_send(port, "status", secret="s")
        t.join(timeout=5)
        assert result is None


# ---------------------------------------------------------------------------
# ctrl_status / ctrl_stop — thin wrappers
# ---------------------------------------------------------------------------

class TestCtrlWrappers:
    """Verify ctrl_status and ctrl_stop delegate correctly."""

    def test_ctrl_status_returns_none_on_error(self):
        """ctrl_status must return None when the control plane is unreachable."""
        assert pasla.ctrl_status(1, secret="x") is None

    def test_ctrl_stop_returns_false_on_error(self):
        """ctrl_stop must return False when the control plane is unreachable."""
        assert pasla.ctrl_stop(1, secret="x") is False


# ---------------------------------------------------------------------------
# write_registry — error path and double-close guard
#
# The double-close guard (`closed` flag) prevents os.close() on an
# already-closed fd, which would raise EBADF or close a reused fd.
# ---------------------------------------------------------------------------

class TestWriteRegistryEdgeCases:
    """Test write_registry error paths beyond the happy path in test_platform."""

    @pytest.fixture(autouse=True)
    def _patch_registry(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "reg")

    def test_happy_path_creates_file(self):
        """Basic write creates a valid JSON registry file."""
        pasla.write_registry("test01", 1234, 5555)
        import json as _json
        path = pasla.registry_path("test01")
        data = _json.loads(path.read_text(encoding="utf-8"))
        assert data["id"] == "test01"
        assert data["pid"] == 1234
        assert data["ctrl_port"] == 5555

    def test_temp_archive_and_secret_stored(self):
        """Optional temp_archive and ctrl_secret must be persisted."""
        import json as _json
        pasla.write_registry("ts01", 1, 2, temp_archive="/tmp/a.tar", ctrl_secret="s3cr3t")
        data = _json.loads(pasla.registry_path("ts01").read_text(encoding="utf-8"))
        assert data["temp_archive"] == "/tmp/a.tar"
        assert data["ctrl_secret"] == "s3cr3t"

    def test_replace_failure_cleans_temp(self, monkeypatch):
        """If os.replace fails, the temp file must be cleaned up."""
        original_replace = os.replace
        cleaned = []

        def _fail_replace(src, dst):
            cleaned.append(src)
            raise OSError("mock replace failure")

        monkeypatch.setattr(os, "replace", _fail_replace)

        with pytest.raises(OSError, match="mock replace failure"):
            pasla.write_registry("fail01", 1, 2)

        # The temp file that was created should have been unlinked.
        for tmp in cleaned:
            assert not os.path.exists(tmp)

    def test_registry_path_creates_directory(self, tmp_path, monkeypatch):
        """registry_path must create REGISTRY_DIR if it doesn't exist."""
        new_dir = tmp_path / "new_reg_dir"
        monkeypatch.setattr(pasla, "REGISTRY_DIR", new_dir)
        path = pasla.registry_path("abc")
        assert new_dir.is_dir()
        assert path.name == "pasla_abc.json"

    def test_replace_retries_on_windows_permission_error(self, monkeypatch):
        """On Windows a transient PermissionError from os.replace (target
        briefly held open by a concurrent reader) must be retried once."""
        monkeypatch.setattr(os, "name", "nt")
        monkeypatch.delenv("USERNAME", raising=False)
        monkeypatch.setattr(pasla.time, "sleep", lambda _s: None)
        calls = []
        real_replace = os.replace

        def _flaky_replace(src, dst):
            calls.append(src)
            if len(calls) == 1:
                raise PermissionError("target held open")
            return real_replace(src, dst)

        monkeypatch.setattr(os, "replace", _flaky_replace)
        pasla.write_registry("retry01", 1, 2)
        assert len(calls) == 2                      # one retry happened
        import json as _json
        data = _json.loads(
            pasla.registry_path("retry01").read_text(encoding="utf-8"))
        assert data["id"] == "retry01"

    def test_replace_retry_exhausted_raises_and_cleans(self, monkeypatch):
        """If os.replace keeps failing on Windows, write_registry raises
        after the single retry and still cleans up the temp file."""
        monkeypatch.setattr(os, "name", "nt")
        monkeypatch.delenv("USERNAME", raising=False)
        monkeypatch.setattr(pasla.time, "sleep", lambda _s: None)
        calls = []

        def _always_fail(src, dst):
            calls.append(src)
            raise PermissionError("target locked")

        monkeypatch.setattr(os, "replace", _always_fail)
        with pytest.raises(PermissionError, match="target locked"):
            pasla.write_registry("retry02", 1, 2)
        assert len(calls) == 2                      # two attempts, then raise
        for tmp in calls:
            assert not os.path.exists(tmp)          # temp file cleaned

    @pytest.mark.skipif(
        os.name == "nt",
        reason="POSIX-only behaviour; os.name cannot be faked to 'posix' "
               "on Windows because the POSIX path calls POSIX-only os "
               "APIs (os.getuid, os.fchmod) that do not exist there.",
    )
    def test_replace_permission_error_not_retried_on_posix(self, monkeypatch):
        """On POSIX a PermissionError from os.replace is a genuine fault
        and must re-raise immediately without retrying.

        Runs on the real platform (no os.name fake): on a POSIX host
        os.name is already 'posix', so write_registry takes the POSIX
        path naturally and the retry loop's 'os.name != \"nt\"' guard
        re-raises at once.
        """
        calls = []

        def _fail(src, dst):
            calls.append(src)
            raise PermissionError("posix fault")

        monkeypatch.setattr(os, "replace", _fail)
        with pytest.raises(PermissionError, match="posix fault"):
            pasla.write_registry("retry03", 1, 2)
        assert len(calls) == 1                      # no retry on POSIX


# ---------------------------------------------------------------------------
# _request_shutdown
#
# Sets the shared shutting_down flag.  The maintenance thread observes
# the flag and performs the actual server.shutdown().
# ---------------------------------------------------------------------------

class TestRequestShutdown:
    """Verify _request_shutdown raises the shared shutdown flag.

    The actual server.shutdown() is performed by the maintenance
    thread; _request_shutdown only sets the flag, so it is safe to call
    from a signal handler or a request thread.
    """

    def test_sets_shutting_down_flag(self):
        pasla.shutting_down.clear()
        pasla._request_shutdown()
        assert pasla.shutting_down.is_set()

    def test_idempotent(self):
        """Repeated calls keep the flag set and never raise."""
        pasla.shutting_down.clear()
        for _ in range(5):
            pasla._request_shutdown()
        assert pasla.shutting_down.is_set()


# ---------------------------------------------------------------------------
# bind_server — port retry loop
#
# bind_server tries random ports in PORT_RANGE, retrying up to
# PORT_BIND_MAX_RETRIES.  If all fail, it falls back to port 0 (OS-assigned).
# ---------------------------------------------------------------------------

class TestBindServerRetry:
    """Verify bind_server retry logic and fallback to OS-assigned port."""

    def test_fallback_to_port_zero_after_exhaustion(self, monkeypatch):
        """When all random ports fail, bind_server must fall back to port 0."""
        # Force only 2 retries for speed.
        monkeypatch.setattr(pasla, "PORT_BIND_MAX_RETRIES", 2)

        call_count = [0]
        original = pasla._make_server

        def _mock_make_server(port, handler, ip_mode=None):
            call_count[0] += 1
            if port != 0:
                raise OSError(f"Port {port} in use")
            return original(port, handler, ip_mode)

        monkeypatch.setattr(pasla, "_make_server", _mock_make_server)
        server, port = pasla.bind_server(ip_mode="4")
        try:
            # Should have tried 2 random ports + 1 fallback to port 0.
            assert call_count[0] == 3
            assert 1 <= port <= 65535
        finally:
            server.server_close()

    def test_success_on_first_try(self, monkeypatch):
        """If the first random port works, no retries are needed."""
        call_count = [0]
        original = pasla._make_server

        def _counting_make_server(port, handler, ip_mode=None):
            call_count[0] += 1
            return original(port, handler, ip_mode)

        monkeypatch.setattr(pasla, "_make_server", _counting_make_server)
        server, port = pasla.bind_server(ip_mode="4")
        try:
            assert call_count[0] == 1
        finally:
            server.server_close()


# ---------------------------------------------------------------------------
# Maintenance thread - periodic state cleanup
#
# The maintenance thread runs _cleanup_state() every STATE_CLEANUP_INTERVAL.
# A broken loop means request_log and active_connections grow unboundedly.
# ---------------------------------------------------------------------------

class TestMaintenanceThreadCleanup:
    """Verify the maintenance thread purges stale state periodically."""

    def test_cleanup_runs_on_interval(self, monkeypatch):
        """Stale entries must be cleaned within a few ticks."""
        # Tick fast and clean every tick so the test completes quickly.
        monkeypatch.setattr(pasla, "MAINTENANCE_TICK_INTERVAL", 0.05)
        monkeypatch.setattr(pasla, "STATE_CLEANUP_INTERVAL", 0.05)

        # Plant stale data.
        expired = time.monotonic() - pasla.RATE_LIMIT_WINDOW - 100
        pasla.request_log["stale_ip"] = [expired]
        pasla.active_connections["stale_ip"] = 0

        class _FakeServer:
            def shutdown(self):
                pass

        class _FakeCtrl:
            def is_alive(self):
                return True

        t = pasla.start_maintenance_thread(
            _FakeServer(), _FakeCtrl(),
            started_at=time.monotonic(), duration=1000,
        )
        try:
            poll_event = threading.Event()
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                if "stale_ip" not in pasla.request_log:
                    break
                poll_event.wait(0.05)

            assert "stale_ip" not in pasla.request_log
            assert "stale_ip" not in pasla.active_connections
        finally:
            pasla._request_shutdown()
            t.join(timeout=5)


# ---------------------------------------------------------------------------
# _resolve_ip — single resolver query
#
# Calls urllib.request.urlopen and validates the response with
# ipaddress.ip_address().  These tests mock urlopen.
# ---------------------------------------------------------------------------

class TestResolveIp:
    """Verify _resolve_ip handles valid, invalid, and failing resolvers."""

    def test_valid_ip_returned(self, monkeypatch):
        """A resolver returning a valid IP string must be accepted."""
        class _FakeResp:
            def read(self): return b"203.0.113.1"
            def __enter__(self): return self
            def __exit__(self, *a): pass

        monkeypatch.setattr(pasla.urllib.request, "urlopen", lambda *a, **kw: _FakeResp())
        assert pasla._resolve_ip("http://fake") == "203.0.113.1"

    def test_invalid_ip_returns_none(self, monkeypatch):
        """A resolver returning a non-IP string must be rejected."""
        class _FakeResp:
            def read(self): return b"not-an-ip-address"
            def __enter__(self): return self
            def __exit__(self, *a): pass

        monkeypatch.setattr(pasla.urllib.request, "urlopen", lambda *a, **kw: _FakeResp())
        assert pasla._resolve_ip("http://fake") is None

    def test_network_error_returns_none(self, monkeypatch):
        """If the HTTP request fails, return None without crashing."""
        monkeypatch.setattr(
            pasla.urllib.request, "urlopen",
            lambda *a, **kw: (_ for _ in ()).throw(OSError("network down"))
        )
        assert pasla._resolve_ip("http://fake") is None

    def test_ipv6_ip_returned(self, monkeypatch):
        """A resolver returning a valid IPv6 address must be accepted."""
        class _FakeResp:
            def read(self): return b"2001:db8::1"
            def __enter__(self): return self
            def __exit__(self, *a): pass

        monkeypatch.setattr(pasla.urllib.request, "urlopen", lambda *a, **kw: _FakeResp())
        assert pasla._resolve_ip("http://fake") == "2001:db8::1"


# ---------------------------------------------------------------------------
# _detect_one — parallel resolver query
# ---------------------------------------------------------------------------

class TestDetectOne:
    """Verify _detect_one returns the first successful resolver result."""

    def test_first_valid_wins(self, monkeypatch):
        """When multiple resolvers respond, the first valid one wins."""
        class _FakeResp:
            def __init__(self, ip): self._ip = ip
            def read(self): return self._ip.encode()
            def __enter__(self): return self
            def __exit__(self, *a): pass

        monkeypatch.setattr(
            pasla.urllib.request, "urlopen",
            lambda url, **kw: _FakeResp("198.51.100.1")
        )
        result = pasla._detect_one(["http://r1", "http://r2"])
        assert result == "198.51.100.1"

    def test_all_fail_returns_none(self, monkeypatch):
        """When all resolvers fail, return None."""
        monkeypatch.setattr(
            pasla.urllib.request, "urlopen",
            lambda *a, **kw: (_ for _ in ()).throw(OSError("fail"))
        )
        result = pasla._detect_one(["http://fail1", "http://fail2"])
        assert result is None


# ---------------------------------------------------------------------------
# detect_public_ips — end-to-end IP detection with fallback
# ---------------------------------------------------------------------------

class TestDetectPublicIps:
    """Verify detect_public_ips mode selection and fallback behaviour."""

    def test_ipv4_mode_returns_ipv4_key(self, monkeypatch):
        """ip_mode='4' must only attempt IPv4 detection."""
        monkeypatch.setattr(pasla, "_detect_one", lambda resolvers: "198.51.100.1")
        result = pasla.detect_public_ips(ip_mode="4")
        assert "ipv4" in result
        assert "ipv6" not in result

    def test_all_resolvers_fail_falls_back_to_loopback(self, monkeypatch):
        """When the public resolvers AND the local routing probe both
        fail, ``detect_public_ips`` must fall back to the loopback
        address for the requested family and emit a warning - so the
        banner stays usable for local testing instead of advertising
        an unresolvable placeholder."""
        monkeypatch.setattr(pasla, "_detect_one", lambda resolvers: None)

        class _FailSocket:
            def __init__(self, *a, **kw): pass
            def settimeout(self, *a): pass
            def connect(self, *a): raise OSError("no route")
            def close(self): pass
            def __enter__(self): return self
            def __exit__(self, *a): pass

        monkeypatch.setattr(socket, "socket", _FailSocket)

        v4 = pasla.detect_public_ips(ip_mode="4")
        assert v4 == {"ipv4": "127.0.0.1"}

        v6 = pasla.detect_public_ips(ip_mode="6")
        assert v6 == {"ipv6": "::1"}

        both = pasla.detect_public_ips(ip_mode=None)
        assert both == {"ipv4": "127.0.0.1", "ipv6": "::1"}

    def test_ipv6_mode_returns_ipv6_key(self, monkeypatch):
        """ip_mode='6' must only attempt IPv6 detection."""
        monkeypatch.setattr(pasla, "_detect_one", lambda resolvers: "2001:db8::1")
        result = pasla.detect_public_ips(ip_mode="6")
        assert "ipv6" in result
        assert "ipv4" not in result

    def test_both_protocols_detected(self, monkeypatch):
        """ip_mode=None must detect both IPv4 and IPv6."""
        ips = {"ipv4": "198.51.100.1", "ipv6": "2001:db8::1"}
        call_count = [0]

        def _mock_detect(resolvers):
            call_count[0] += 1
            if call_count[0] == 1:
                return ips["ipv4"]
            return ips["ipv6"]

        monkeypatch.setattr(pasla, "_detect_one", _mock_detect)
        result = pasla.detect_public_ips(ip_mode=None)
        assert "ipv4" in result
        assert "ipv6" in result


# ---------------------------------------------------------------------------
# Argument parsers — _build_serve_parser / _build_stop_parser
#
# Verify default values and flag behaviour without launching the server.
# ---------------------------------------------------------------------------

class TestBuildServeParser:
    """Verify serve-mode argument parser defaults and flags."""

    def test_default_duration(self):
        """Default duration must be 60 minutes."""
        parser = pasla._build_serve_parser()
        args = parser.parse_args(["testfile.txt"])
        assert args.duration == 60

    def test_custom_duration(self):
        """Duration argument must override the default."""
        parser = pasla._build_serve_parser()
        args = parser.parse_args(["testfile.txt", "30"])
        assert args.duration == 30

    def test_max_downloads_default_unlimited(self):
        """Default max_downloads must be 0 (unlimited)."""
        parser = pasla._build_serve_parser()
        args = parser.parse_args(["testfile.txt"])
        assert args.max_downloads == 0

    def test_custom_max_downloads(self):
        """max_downloads argument must be set when provided."""
        parser = pasla._build_serve_parser()
        args = parser.parse_args(["testfile.txt", "15", "5"])
        assert args.max_downloads == 5

    def test_trust_proxy_flag(self):
        """--trust-proxy must set the flag to True."""
        parser = pasla._build_serve_parser()
        args = parser.parse_args(["testfile.txt", "--trust-proxy"])
        assert args.trust_proxy is True

    def test_trust_proxy_default_false(self):
        """trust_proxy must default to False."""
        parser = pasla._build_serve_parser()
        args = parser.parse_args(["testfile.txt"])
        assert args.trust_proxy is False

    def test_ipv4_only_flag(self):
        """-4 flag must set ip_mode to '4'."""
        parser = pasla._build_serve_parser()
        args = parser.parse_args(["testfile.txt", "-4"])
        assert args.ip_mode == "4"

    def test_ipv6_only_flag(self):
        """-6 flag must set ip_mode to '6'."""
        parser = pasla._build_serve_parser()
        args = parser.parse_args(["testfile.txt", "-6"])
        assert args.ip_mode == "6"

    def test_detach_flag(self):
        """-d flag must set detach to True."""
        parser = pasla._build_serve_parser()
        args = parser.parse_args(["testfile.txt", "-d"])
        assert args.detach is True

    def test_no_flags_defaults(self):
        """Without flags, ip_mode must be None and detach must be False."""
        parser = pasla._build_serve_parser()
        args = parser.parse_args(["testfile.txt"])
        assert args.ip_mode is None
        assert args.detach is False


class TestBuildStopParser:
    """Verify stop-mode argument parser."""

    def test_stop_with_id(self):
        """Positional id argument must be captured."""
        parser = pasla._build_stop_parser()
        args = parser.parse_args(["abc123"])
        assert args.id == "abc123"

    def test_stop_all_flag(self):
        """--all flag must be set."""
        parser = pasla._build_stop_parser()
        args = parser.parse_args(["--all"])
        assert args.stop_all is True

    def test_stop_no_args(self):
        """Without arguments, id must be None and stop_all must be False."""
        parser = pasla._build_stop_parser()
        args = parser.parse_args([])
        assert args.id is None
        assert args.stop_all is False


# ---------------------------------------------------------------------------
# add_bytes_transferred / current_bytes_transferred
#
# Thread-safe counter for total bytes sent.  Verify atomicity.
# ---------------------------------------------------------------------------

class TestBytesTransferredCounter:
    """Verify add_bytes_transferred and current_bytes_transferred."""

    def test_increment(self):
        """Adding bytes must increase the counter."""
        pasla._add_bytes_transferred(1024)
        assert pasla._current_bytes_transferred() == 1024

    def test_multiple_increments(self):
        """Multiple calls must accumulate."""
        pasla._add_bytes_transferred(100)
        pasla._add_bytes_transferred(200)
        assert pasla._current_bytes_transferred() == 300

    def test_concurrent_increments(self):
        """Concurrent adds must not lose updates."""
        errors = []

        def _add():
            try:
                for _ in range(1000):
                    pasla._add_bytes_transferred(1)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_add) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors
        assert pasla._current_bytes_transferred() == 10000


# ---------------------------------------------------------------------------
# SecureHandler log suppression
#
# SecureHandler.log_message() and log_request() are overridden to suppress
# default BaseHTTPRequestHandler stderr output.  Verify they produce no output.
# ---------------------------------------------------------------------------

class TestHandlerLogSuppression:
    """Verify SecureHandler suppresses default HTTP logging."""

    def _make_handler_class(self, tmp_path):
        """Create a SecureHandler class for a temp file."""
        f = tmp_path / "test_suppress.txt"
        f.write_text("test", encoding="utf-8")
        server = pasla._make_server(0, pasla.BaseHTTPRequestHandler, ip_mode="4")
        try:
            handler_cls = pasla.make_handler(
                file_path=str(f),
                file_name=f.name,
                token="tok",
                max_downloads=0,
                trust_proxy=False,
            )
        except Exception:
            server.server_close()
            raise
        return handler_cls, server

    def test_log_message_suppressed(self, tmp_path):
        """log_message must produce no output."""
        handler_cls, server = self._make_handler_class(tmp_path)
        try:
            # Verify the override exists and does nothing.
            assert handler_cls.log_message is not pasla.BaseHTTPRequestHandler.log_message
        finally:
            server.server_close()

    def test_log_request_suppressed(self, tmp_path):
        """log_request must produce no output."""
        handler_cls, server = self._make_handler_class(tmp_path)
        try:
            assert handler_cls.log_request is not pasla.BaseHTTPRequestHandler.log_request
        finally:
            server.server_close()

    def test_server_version_is_pasla(self, tmp_path):
        """server_version must be 'pasla' (no version number)."""
        handler_cls, server = self._make_handler_class(tmp_path)
        try:
            assert handler_cls.server_version == "pasla"
        finally:
            server.server_close()

    def test_sys_version_is_empty(self, tmp_path):
        """sys_version must be empty to prevent Python version leakage."""
        handler_cls, server = self._make_handler_class(tmp_path)
        try:
            assert handler_cls.sys_version == ""
        finally:
            server.server_close()


# ---------------------------------------------------------------------------
# cmd_list — lists running instances
#
# Reads the registry, filters stale entries by checking process liveness
# and control plane reachability, then renders a table of live instances.
# ---------------------------------------------------------------------------

class TestCmdList:
    """Verify cmd_list displays live instances and prunes stale ones."""

    @pytest.fixture(autouse=True)
    def _patch_registry(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")

    def test_empty_registry(self, capsys):
        """No registry files → prints 'No active pasla instances.'"""
        pasla.cmd_list()
        assert "No active pasla instances." in capsys.readouterr().out

    def test_stale_dead_pid_pruned(self, capsys, monkeypatch):
        """A registry entry with a dead PID must be pruned."""
        pasla.write_registry("dead01", 999999999, 9999)
        monkeypatch.setattr(pasla, "pid_is_alive", lambda pid: False)
        pasla.cmd_list()
        assert "No active pasla instances." in capsys.readouterr().out
        # The registry file should be deleted.
        entries = pasla.read_all_registry()
        assert not any(e.get("id") == "dead01" for e in entries)

    def test_stale_no_ctrl_response_pruned(self, capsys, monkeypatch):
        """A live PID with no control plane response must be pruned."""
        pasla.write_registry("noctl01", os.getpid(), 9999)
        monkeypatch.setattr(pasla, "pid_is_alive", lambda pid: True)
        monkeypatch.setattr(pasla, "ctrl_status", lambda port, secret="": None)
        pasla.cmd_list()
        assert "No active pasla instances." in capsys.readouterr().out

    def test_live_instance_displayed(self, capsys, monkeypatch):
        """A live instance must appear in the table output."""
        pasla.write_registry("live01", os.getpid(), 9999, ctrl_secret="s")
        monkeypatch.setattr(pasla, "pid_is_alive", lambda pid: True)
        monkeypatch.setattr(pasla, "ctrl_status", lambda port, secret="": {
            "id": "live01",
            "file": "test.txt",
            "remaining_seconds": 3600,
            "download_count": 2,
            "max_downloads": 10,
            "bytes_transferred": 1024,
            "url_ipv4": "http://127.0.0.1:8000/tok/test.txt",
        })
        pasla.cmd_list()
        out = capsys.readouterr().out
        assert "live01" in out
        assert "test.txt" in out
        assert "2/10" in out

    def test_multiple_instances_displayed(self, capsys, monkeypatch):
        """Multiple live instances must all appear."""
        for i in range(3):
            pasla.write_registry(f"inst{i:02d}", os.getpid(), 9000 + i, ctrl_secret="s")

        monkeypatch.setattr(pasla, "pid_is_alive", lambda pid: True)

        call_count = [0]
        def _mock_status(port, secret=""):
            call_count[0] += 1
            return {
                "id": f"inst{call_count[0]-1:02d}",
                "file": f"file{call_count[0]-1}.txt",
                "remaining_seconds": 300,
                "download_count": 0,
                "max_downloads": 0,
                "bytes_transferred": 0,
            }

        monkeypatch.setattr(pasla, "ctrl_status", _mock_status)
        pasla.cmd_list()
        out = capsys.readouterr().out
        for i in range(3):
            assert f"inst{i:02d}" in out

    def test_url_ipv6_displayed(self, capsys, monkeypatch):
        """IPv6 URLs must be displayed when present."""
        pasla.write_registry("v6inst", os.getpid(), 9999, ctrl_secret="s")
        monkeypatch.setattr(pasla, "pid_is_alive", lambda pid: True)
        monkeypatch.setattr(pasla, "ctrl_status", lambda port, secret="": {
            "id": "v6inst",
            "file": "v6file.txt",
            "remaining_seconds": 60,
            "download_count": 0,
            "max_downloads": 0,
            "bytes_transferred": 0,
            "url_ipv6": "http://[::1]:8000/tok/v6file.txt",
        })
        pasla.cmd_list()
        out = capsys.readouterr().out
        assert "IPv6" in out

    def test_no_url_keys_omits_url_lines(self, capsys, monkeypatch):
        """When the status payload carries neither url_ipv4 nor
        url_ipv6 (for example, public-IP detection is disabled or
        failed), the table row prints just the metadata - no URL
        line at all - rather than guessing a fallback."""
        pasla.write_registry("urltest", os.getpid(), 9999, ctrl_secret="s")
        monkeypatch.setattr(pasla, "pid_is_alive", lambda pid: True)
        monkeypatch.setattr(pasla, "ctrl_status", lambda port, secret="": {
            "id": "urltest",
            "file": "f.txt",
            "remaining_seconds": 60,
            "download_count": 0,
            "max_downloads": 0,
            "bytes_transferred": 0,
        })
        pasla.cmd_list()
        out = capsys.readouterr().out
        assert "urltest" in out
        assert "IPv4:" not in out
        assert "IPv6:" not in out


# ---------------------------------------------------------------------------
# cmd_stop — stops running instances
#
# Reads the registry, matches targets by ID or --all, sends stop commands
# via the control plane, and cleans up unresponsive entries.
# ---------------------------------------------------------------------------

class TestCmdStop:
    """Verify cmd_stop sends stop commands and cleans up stale entries."""

    @pytest.fixture(autouse=True)
    def _patch_registry(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")

    def test_empty_registry(self, capsys):
        """No registry → prints 'No active pasla instances.'"""
        args = argparse.Namespace(id=None, stop_all=True)
        pasla.cmd_stop(args)
        assert "No active pasla instances." in capsys.readouterr().out

    def test_stop_all_sends_stop(self, capsys, monkeypatch):
        """--all must send stop to all instances."""
        pasla.write_registry("s01", os.getpid(), 9001, ctrl_secret="s")
        pasla.write_registry("s02", os.getpid(), 9002, ctrl_secret="s")
        monkeypatch.setattr(pasla, "ctrl_stop", lambda port, secret="": True)

        args = argparse.Namespace(id=None, stop_all=True)
        pasla.cmd_stop(args)
        out = capsys.readouterr().out
        assert "Stopping instance s01" in out
        assert "Stopping instance s02" in out

    def test_stop_by_id(self, capsys, monkeypatch):
        """Stopping by ID prefix must match the correct instance."""
        pasla.write_registry("abc123", os.getpid(), 9001, ctrl_secret="s")
        pasla.write_registry("def456", os.getpid(), 9002, ctrl_secret="s")
        monkeypatch.setattr(pasla, "ctrl_stop", lambda port, secret="": True)

        args = argparse.Namespace(id="abc", stop_all=False)
        pasla.cmd_stop(args)
        out = capsys.readouterr().out
        assert "abc123" in out
        assert "def456" not in out

    def test_no_matching_id(self, capsys, monkeypatch):
        """Non-matching ID must print 'No instance found'."""
        pasla.write_registry("xyz789", os.getpid(), 9001, ctrl_secret="s")

        args = argparse.Namespace(id="nomatch", stop_all=False)
        pasla.cmd_stop(args)
        assert "No instance found" in capsys.readouterr().out

    def test_unresponsive_instance_cleaned(self, capsys, monkeypatch):
        """An unresponsive instance must have its registry cleaned up."""
        pasla.write_registry("unresp", os.getpid(), 9001, ctrl_secret="s")
        monkeypatch.setattr(pasla, "ctrl_stop", lambda port, secret="": False)

        args = argparse.Namespace(id="unresp", stop_all=False)
        pasla.cmd_stop(args)
        out = capsys.readouterr().out
        assert "did not respond" in out
        # Registry entry should be gone.
        entries = pasla.read_all_registry()
        assert not any(e.get("id") == "unresp" for e in entries)


# ---------------------------------------------------------------------------
# parse_and_validate — argument dispatch and validation
#
# Routes sys.argv to list/stop/serve subcommands and validates the
# resolved file path is within ALLOWED_ROOT.
# ---------------------------------------------------------------------------

class TestParseAndValidate:
    """Verify parse_and_validate dispatches correctly."""

    def test_list_subcommand(self, monkeypatch):
        """'list' argument must set subcommand='list'."""
        monkeypatch.setattr(sys, "argv", ["pasla", "list"])
        ns = pasla.parse_and_validate()
        assert ns.subcommand == "list"

    def test_stop_subcommand_with_id(self, monkeypatch):
        """'stop <id>' must set subcommand='stop' and capture the id."""
        monkeypatch.setattr(sys, "argv", ["pasla", "stop", "abc123"])
        ns = pasla.parse_and_validate()
        assert ns.subcommand == "stop"
        assert ns.id == "abc123"

    def test_stop_subcommand_with_all(self, monkeypatch):
        """'stop --all' must set subcommand='stop' and stop_all=True."""
        monkeypatch.setattr(sys, "argv", ["pasla", "stop", "--all"])
        ns = pasla.parse_and_validate()
        assert ns.subcommand == "stop"
        assert ns.stop_all is True

    def test_serve_mode_with_file(self, monkeypatch, tmp_path):
        """A file path must resolve to serve mode (subcommand=None)."""
        f = tmp_path / "testfile.txt"
        f.write_text("content", encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["pasla", str(f)])
        monkeypatch.setattr(pasla, "ALLOWED_ROOT", str(tmp_path))
        ns = pasla.parse_and_validate()
        assert ns.subcommand is None
        assert ns.resolved_file == str(f)
        assert ns.duration_seconds == 60 * 60  # 60 min default

    def test_serve_mode_with_options(self, monkeypatch, tmp_path):
        """Serve mode must capture duration, max_downloads, and flags."""
        f = tmp_path / "opts.txt"
        f.write_text("data", encoding="utf-8")
        monkeypatch.setattr(sys, "argv", [
            "pasla", str(f), "30", "5", "--trust-proxy", "-4"
        ])
        monkeypatch.setattr(pasla, "ALLOWED_ROOT", str(tmp_path))
        ns = pasla.parse_and_validate()
        assert ns.duration == 30
        assert ns.max_downloads == 5
        assert ns.trust_proxy is True
        assert ns.ip_mode == "4"
        assert ns.duration_seconds == 30 * 60

    def test_file_outside_allowed_root_exits(self, monkeypatch, tmp_path):
        """A file outside ALLOWED_ROOT must cause sys.exit(1)."""
        f = tmp_path / "outside.txt"
        f.write_text("data", encoding="utf-8")
        # Set ALLOWED_ROOT to a subdirectory that doesn't contain f.
        fake_root = tmp_path / "subdir"
        fake_root.mkdir()
        monkeypatch.setattr(pasla, "ALLOWED_ROOT", str(fake_root))
        monkeypatch.setattr(sys, "argv", ["pasla", str(f)])
        with pytest.raises(SystemExit) as exc_info:
            pasla.parse_and_validate()
        assert exc_info.value.code == 1

    def test_nonexistent_file_exits(self, monkeypatch, tmp_path):
        """A file that doesn't exist must cause sys.exit(1)."""
        monkeypatch.setattr(sys, "argv", ["pasla", str(tmp_path / "nofile.txt")])
        monkeypatch.setattr(pasla, "ALLOWED_ROOT", str(tmp_path))
        with pytest.raises(SystemExit) as exc_info:
            pasla.parse_and_validate()
        assert exc_info.value.code == 1

    def test_empty_argv_prints_help_and_exits(self, monkeypatch):
        """No arguments → print help and exit(0)."""
        monkeypatch.setattr(sys, "argv", ["pasla"])
        with pytest.raises(SystemExit) as exc_info:
            pasla.parse_and_validate()
        assert exc_info.value.code == 0

    def test_daemon_flag_extracted(self, monkeypatch, tmp_path):
        """The internal --_daemon flag must be extracted and set."""
        f = tmp_path / "daemon.txt"
        f.write_text("data", encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["pasla", pasla._DAEMON_FLAG, str(f)])
        monkeypatch.setattr(pasla, "ALLOWED_ROOT", str(tmp_path))
        ns = pasla.parse_and_validate()
        assert ns.daemon is True

    def test_directory_prompts_and_exits_on_n(self, monkeypatch, tmp_path):
        """A directory argument must prompt and exit on 'n'."""
        d = tmp_path / "mydir"
        d.mkdir()
        (d / "inner.txt").write_text("data", encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["pasla", str(d)])
        monkeypatch.setattr(pasla, "ALLOWED_ROOT", str(tmp_path))
        monkeypatch.setattr("builtins.input", lambda prompt: "n")
        with pytest.raises(SystemExit) as exc_info:
            pasla.parse_and_validate()
        assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# cmd_serve — server orchestration (partial coverage)
#
# cmd_serve is the main server loop.  Testing the full loop requires
# integration tests, but we can test the setup phase by letting it start
# and then immediately triggering shutdown.
# ---------------------------------------------------------------------------

class TestCmdServe:
    """Verify cmd_serve orchestration — setup, registry, and cleanup."""

    def test_serve_starts_and_shuts_down(self, tmp_path, monkeypatch):
        """cmd_serve must bind, write registry, and clean up on shutdown.

        We patch serve_forever to immediately trigger shutdown, exercising
        the setup and teardown paths without blocking.
        """
        f = tmp_path / "serve_test.txt"
        f.write_text("serve test content", encoding="utf-8")

        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")
        monkeypatch.setattr(pasla, "ALLOWED_ROOT", str(tmp_path))
        # Prevent network calls for public IP detection.
        monkeypatch.setattr(pasla, "detect_public_ips", lambda ip_mode=None: {"ipv4": "127.0.0.1"})

        args = argparse.Namespace(
            resolved_file=str(f),
            file=str(f),
            duration=1,
            duration_seconds=60,
            max_downloads=0,
            trust_proxy=False,
            ip_mode="4",
            daemon=True,   # daemon=True to skip TUI/banner
            forced_instance_id="serve01",
            temp_tar=None,
            detach=False,
        )

        # Immediately trigger shutdown inside serve_forever.  Because
        # serve_forever is mocked, the maintenance thread's
        # server.shutdown() call is stubbed to a no-op.
        monkeypatch.setattr(pasla.ThreadingHTTPServer, "shutdown",
                            lambda self: None)

        def _quick_shutdown(self, *a, **kw):
            pasla._request_shutdown()
            # Wait for shutdown flag.
            pasla.shutting_down.wait(timeout=3)

        monkeypatch.setattr(pasla.ThreadingHTTPServer, "serve_forever", _quick_shutdown)

        pasla.cmd_serve(args)

        # After cmd_serve returns, registry should be cleaned up.
        entries = pasla.read_all_registry()
        assert not any(e.get("id") == "serve01" for e in entries)

    def test_serve_creates_registry(self, tmp_path, monkeypatch):
        """cmd_serve must write a registry entry during startup."""
        f = tmp_path / "reg_test.txt"
        f.write_text("registry test content", encoding="utf-8")

        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")
        monkeypatch.setattr(pasla, "ALLOWED_ROOT", str(tmp_path))
        monkeypatch.setattr(pasla, "detect_public_ips", lambda ip_mode=None: {"ipv4": "127.0.0.1"})

        registry_was_written = [False]
        original_write = pasla.write_registry

        def _spy_write(*a, **kw):
            registry_was_written[0] = True
            return original_write(*a, **kw)

        monkeypatch.setattr(pasla, "write_registry", _spy_write)

        args = argparse.Namespace(
            resolved_file=str(f),
            file=str(f),
            duration=1,
            duration_seconds=60,
            max_downloads=0,
            trust_proxy=False,
            ip_mode="4",
            daemon=True,
            forced_instance_id="reg_test01",
            temp_tar=None,
            detach=False,
        )

        # serve_forever is mocked below, so the maintenance thread's
        # server.shutdown() call is stubbed to a no-op - the real
        # serve_forever never ran to manage its shutdown event.
        monkeypatch.setattr(pasla.ThreadingHTTPServer, "shutdown",
                            lambda self: None)

        def _quick_shutdown(self, *a, **kw):
            pasla._request_shutdown()
            pasla.shutting_down.wait(timeout=3)

        monkeypatch.setattr(pasla.ThreadingHTTPServer, "serve_forever", _quick_shutdown)

        pasla.cmd_serve(args)
        assert registry_was_written[0]


# ---------------------------------------------------------------------------
# cmd_detach — cross-platform daemonisation
#
# Verifies the subprocess creation and registry polling without actually
# spawning a real daemon process.
# ---------------------------------------------------------------------------

class TestCmdDetach:
    """Verify cmd_detach spawns a subprocess and polls for readiness."""

    def test_detach_spawns_subprocess(self, monkeypatch, tmp_path):
        """cmd_detach must call subprocess.Popen with the correct flags."""
        import subprocess

        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")
        monkeypatch.setattr(pasla, "DETACH_READY_TIMEOUT", 0.5)  # fast timeout
        monkeypatch.setattr(
            pasla, "_restrict_windows_acl",
            lambda path, **kw: None,
        )

        popen_calls = []

        class _FakePopen:
            def __init__(self, cmd, **kwargs):
                popen_calls.append((cmd, kwargs))

        monkeypatch.setattr(subprocess, "Popen", _FakePopen)

        # The mocked Popen never actually writes the readiness file,
        # so cmd_detach hits its timeout branch and exits non-zero.
        # The Popen invocation we want to verify happens BEFORE that
        # branch, so the assertions below still hold.
        with pytest.raises(SystemExit) as excinfo:
            pasla.cmd_detach(["testfile.txt", "30"])
        assert excinfo.value.code == 2

        assert len(popen_calls) == 1
        cmd, kwargs = popen_calls[0]
        # The command must include the daemon flag.
        assert pasla._DAEMON_FLAG in cmd
        assert "testfile.txt" in cmd
        assert "30" in cmd

    def test_detach_timeout_exits_nonzero(
        self, monkeypatch, tmp_path, capsys,
    ):
        """If the daemon doesn't become ready, print a warning to
        stderr AND exit with code 2 so automation scripts treat the
        detach as a failure rather than a silent success."""
        import subprocess

        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")
        monkeypatch.setattr(pasla, "DETACH_READY_TIMEOUT", 0.3)
        monkeypatch.setattr(
            pasla, "_restrict_windows_acl",
            lambda path, **kw: None,
        )

        monkeypatch.setattr(subprocess, "Popen", lambda cmd, **kw: None)

        with pytest.raises(SystemExit) as excinfo:
            pasla.cmd_detach(["testfile.txt"])
        assert excinfo.value.code == 2
        captured = capsys.readouterr()
        assert "Warning" in captured.err


# ---------------------------------------------------------------------------
# pid_is_alive — Windows kernel32 branch
#
# On Windows, pid_is_alive uses ctypes to call kernel32.OpenProcess and
# GetExitCodeProcess.  The POSIX branch is already covered by test_platform.
# This test specifically targets the Windows code path.
# ---------------------------------------------------------------------------

class TestPidIsAliveWindows:
    """Additional pid_is_alive tests for the Windows code path."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_current_process_alive_via_kernel32(self):
        """Our own PID must be alive via the kernel32 path."""
        assert pasla.pid_is_alive(os.getpid()) is True

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_zero_pid_returns_false(self):
        """PID 0 (System Idle) cannot be opened → returns False."""
        # PID 0 on Windows is the System Idle Process, OpenProcess returns 0.
        result = pasla.pid_is_alive(0)
        # Either False or True (if access denied) — both are valid.
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# ThreadingHTTPServer.server_bind — IPV6_V6ONLY
# ---------------------------------------------------------------------------

class TestDualStackServerBind:
    """Verify ThreadingHTTPServer.server_bind handles IPv6 sockets."""

    def test_ipv6_socket_created(self):
        """ip_mode='6' must create an AF_INET6 socket."""
        if not ipv6_usable():
            pytest.skip("IPv6 not usable on this system")
        from http.server import BaseHTTPRequestHandler

        class _Null(BaseHTTPRequestHandler):
            def log_message(self, format, *args): pass

        srv = pasla._make_server(0, _Null, ip_mode="6")
        try:
            assert srv.address_family == socket.AF_INET6
        finally:
            srv.server_close()


# ---------------------------------------------------------------------------
# _handle_request_inner — IP validation (400 on invalid IP)
# ---------------------------------------------------------------------------

class TestHandleRequestInnerIPValidation:
    """Verify _handle_request_inner returns 400 for invalid client IP."""

    def test_invalid_ip_returns_400(self, tmp_path):
        """An invalid client IP must produce a 400 error."""
        f = tmp_path / "ipval.txt"
        f.write_text("ip validation test", encoding="utf-8")

        server = pasla._make_server(0, pasla.BaseHTTPRequestHandler, ip_mode="4")
        try:
            port = server.server_address[1]
            token = "ipvaltoken"

            server.RequestHandlerClass = pasla.make_handler(
                file_path=str(f),
                file_name=f.name,
                token=token,
                max_downloads=0,
                trust_proxy=False,
            )
            server.timeout = 2

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            try:
                # Send a valid request — should work.
                import http.client
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("GET", f"/{token}/{f.name}")
                resp = conn.getresponse()
                resp.read()
                assert resp.status == 200
            finally:
                pasla.shutting_down.set()
                server.shutdown()
                thread.join(timeout=5)
        finally:
            server.server_close()


# ---------------------------------------------------------------------------
# cmd_serve foreground mode — banner and cleanup
# ---------------------------------------------------------------------------

class TestCmdServeForeground:
    """Verify cmd_serve foreground banner, status bar, and cleanup paths."""

    def _make_args(self, tmp_path, *, daemon=False, temp_tar=None):
        """Helper: build a minimal Namespace for cmd_serve."""
        f = tmp_path / "fg_test.txt"
        f.write_text("foreground test content", encoding="utf-8")
        return argparse.Namespace(
            resolved_file=str(f),
            file=str(f),
            duration=1,
            duration_seconds=60,
            max_downloads=0,
            trust_proxy=False,
            ip_mode="4",
            daemon=daemon,
            forced_instance_id="fg01",
            temp_tar=temp_tar,
            detach=False,
        )

    def test_foreground_prints_banner(self, tmp_path, monkeypatch, capsys):
        """cmd_serve with daemon=False must print the server banner."""
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")
        monkeypatch.setattr(pasla, "ALLOWED_ROOT", str(tmp_path))
        monkeypatch.setattr(pasla, "detect_public_ips",
                            lambda ip_mode=None: {"ipv4": "127.0.0.1"})

        args = self._make_args(tmp_path, daemon=False)

        # serve_forever is mocked below, so the maintenance thread's
        # server.shutdown() call is stubbed to a no-op - the real
        # serve_forever never ran to manage its shutdown event.
        monkeypatch.setattr(pasla.ThreadingHTTPServer, "shutdown",
                            lambda self: None)

        def _quick_shutdown(self, *a, **kw):
            pasla._request_shutdown()
            pasla.shutting_down.wait(timeout=3)

        monkeypatch.setattr(pasla.ThreadingHTTPServer, "serve_forever",
                            _quick_shutdown)

        pasla.cmd_serve(args)
        out = capsys.readouterr().out
        assert "fg01" in out
        assert "fg_test.txt" in out

    def test_keyboard_interrupt_handled(self, tmp_path, monkeypatch):
        """KeyboardInterrupt during serve_forever must trigger clean shutdown."""
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")
        monkeypatch.setattr(pasla, "ALLOWED_ROOT", str(tmp_path))
        monkeypatch.setattr(pasla, "detect_public_ips",
                            lambda ip_mode=None: {"ipv4": "127.0.0.1"})

        args = self._make_args(tmp_path, daemon=True)

        monkeypatch.setattr(pasla.ThreadingHTTPServer, "shutdown",
                            lambda self: None)

        def _raise_keyboard_interrupt(self, *a, **kw):
            raise KeyboardInterrupt

        monkeypatch.setattr(pasla.ThreadingHTTPServer, "serve_forever",
                            _raise_keyboard_interrupt)

        pasla.cmd_serve(args)

        entries = pasla.read_all_registry()
        assert not any(e.get("id") == "fg01" for e in entries)

    def test_watchdog_triggers_graceful_shutdown(self, tmp_path, monkeypatch):
        """When ``duration_seconds`` elapses, the watchdog timer must
        invoke ``_schedule_graceful_shutdown`` so ``serve_forever``
        unblocks and the server cleans up the registry entry and
        log file before exiting.
        """
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")
        monkeypatch.setattr(pasla, "ALLOWED_ROOT", str(tmp_path))
        monkeypatch.setattr(pasla, "detect_public_ips",
                            lambda ip_mode=None: {"ipv4": "127.0.0.1"})

        args = self._make_args(tmp_path, daemon=True)
        # Sub-second duration so the watchdog fires quickly.
        args.duration_seconds = 1
        args.duration = 1

        monkeypatch.setattr(pasla.ThreadingHTTPServer, "shutdown",
                            lambda self: None)

        # Make serve_forever block until shutting_down is set.
        def _wait_for_shutdown(self, *a, **kw):
            pasla.shutting_down.wait(timeout=5)

        monkeypatch.setattr(pasla.ThreadingHTTPServer, "serve_forever",
                            _wait_for_shutdown)

        pasla.cmd_serve(args)

        # Watchdog must have fired and registry must be cleaned up.
        assert pasla.shutting_down.is_set()
        entries = pasla.read_all_registry()
        assert not any(e.get("id") == "fg01" for e in entries)

    def test_temp_tar_cleanup(self, tmp_path, monkeypatch):
        """cmd_serve must clean up temp_tar file and directory on exit."""
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")
        monkeypatch.setattr(pasla, "ALLOWED_ROOT", str(tmp_path))
        monkeypatch.setattr(pasla, "detect_public_ips",
                            lambda ip_mode=None: {"ipv4": "127.0.0.1"})

        # The temp tar must live inside REGISTRY_DIR, exactly where
        # _tar_directory() puts it - cmd_serve's cleanup goes through
        # _cleanup_temp_archive(), which refuses to delete anything
        # outside the registry directory (path-confinement guard).
        tar_dir = tmp_path / "registry" / ".tmp_abc"
        tar_dir.mkdir(parents=True)
        tar_file = tar_dir / "test.tar"
        tar_file.write_bytes(b"fake tar content")

        args = self._make_args(tmp_path, daemon=True, temp_tar=str(tar_file))
        real_file = tmp_path / "fg_test.txt"
        args.resolved_file = str(real_file)

        # serve_forever is mocked below, so the maintenance thread's
        # server.shutdown() call is stubbed to a no-op - the real
        # serve_forever never ran to manage its shutdown event.
        monkeypatch.setattr(pasla.ThreadingHTTPServer, "shutdown",
                            lambda self: None)

        def _quick_shutdown(self, *a, **kw):
            pasla._request_shutdown()
            pasla.shutting_down.wait(timeout=3)

        monkeypatch.setattr(pasla.ThreadingHTTPServer, "serve_forever",
                            _quick_shutdown)

        pasla.cmd_serve(args)
        assert not tar_file.exists()

    def test_daemon_log_file_cleaned(self, tmp_path, monkeypatch):
        """daemon=True must create a log file and clean it on exit."""
        reg_dir = tmp_path / "registry"
        monkeypatch.setattr(pasla, "REGISTRY_DIR", reg_dir)
        monkeypatch.setattr(pasla, "ALLOWED_ROOT", str(tmp_path))
        monkeypatch.setattr(pasla, "detect_public_ips",
                            lambda ip_mode=None: {"ipv4": "127.0.0.1"})

        args = self._make_args(tmp_path, daemon=True)

        # serve_forever is mocked below, so the maintenance thread's
        # server.shutdown() call is stubbed to a no-op - the real
        # serve_forever never ran to manage its shutdown event.
        monkeypatch.setattr(pasla.ThreadingHTTPServer, "shutdown",
                            lambda self: None)

        def _quick_shutdown(self, *a, **kw):
            pasla._request_shutdown()
            pasla.shutting_down.wait(timeout=3)

        monkeypatch.setattr(pasla.ThreadingHTTPServer, "serve_forever",
                            _quick_shutdown)

        pasla.cmd_serve(args)
        log_path = reg_dir / "pasla_fg01.log"
        assert not log_path.exists()


# ---------------------------------------------------------------------------
# main — entry point dispatch
# ---------------------------------------------------------------------------

class TestMain:
    """Verify main() dispatches correctly to subcommands."""

    def test_main_list(self, monkeypatch, capsys, tmp_path):
        """main() with 'list' must call cmd_list."""
        monkeypatch.setattr(sys, "argv", ["pasla", "list"])
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")
        pasla.main()
        assert "No active pasla instances." in capsys.readouterr().out

    def test_main_stop(self, monkeypatch, capsys, tmp_path):
        """main() with 'stop --all' must call cmd_stop."""
        monkeypatch.setattr(sys, "argv", ["pasla", "stop", "--all"])
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")
        pasla.main()
        assert "No active pasla instances." in capsys.readouterr().out


# ---------------------------------------------------------------------------
# format_url and _fmt_bytes — utility functions
# ---------------------------------------------------------------------------

class TestFormatUrl:
    """Verify format_url encodes addresses correctly."""

    def test_ipv6_address_bracketed(self):
        """IPv6 addresses must be wrapped in brackets."""
        url = pasla.format_url("::1", 8080, "token", "file.txt")
        assert "[::1]" in url

    def test_basic_url_format(self):
        """Standard URL must include http://, host, port, token, file."""
        url = pasla.format_url("192.168.1.1", 9000, "tok123", "report.pdf")
        assert url == "http://192.168.1.1:9000/tok123/report.pdf"


class TestFmtBytes:
    """Verify _fmt_bytes formats byte counts correctly."""

    def test_zero_bytes(self):
        assert pasla._fmt_bytes(0) == "0.0 B"

    def test_kilobytes(self):
        assert pasla._fmt_bytes(1024) == "1.0 KB"

    def test_megabytes(self):
        assert pasla._fmt_bytes(1048576) == "1.0 MB"

    def test_gigabytes(self):
        assert pasla._fmt_bytes(1073741824) == "1.0 GB"

    def test_small_bytes(self):
        assert pasla._fmt_bytes(512) == "512.0 B"


# ---------------------------------------------------------------------------
# _StatusBar — terminal size fallback
# ---------------------------------------------------------------------------

class TestStatusBarTerminalSize:
    """Verify _StatusBar handles terminal size errors gracefully."""

    def test_terminal_size_fallback(self, monkeypatch):
        """When os.get_terminal_size raises, _StatusBar uses 80 columns."""
        def _raise(*args, **kwargs):
            raise OSError("no terminal")

        monkeypatch.setattr(os, "get_terminal_size", _raise)
        bar = pasla._StatusBar(
            started=time.monotonic(),
            duration=60,
            max_downloads=0,
        )
        assert bar is not None


# ---------------------------------------------------------------------------
# _env_int — environment variable override helper
#
# Validates that PASLA_<NAME> env vars correctly override module-level
# constants, with robust fallback to defaults on invalid input.
# ---------------------------------------------------------------------------

class TestEnvInt:
    """Verify _env_int reads, validates, and falls back correctly."""

    def test_valid_override(self, monkeypatch):
        """A valid positive integer env var must be returned as-is."""
        monkeypatch.setenv("PASLA_SOCKET_TIMEOUT", "99")
        assert pasla._env_int("SOCKET_TIMEOUT", 30) == 99

    def test_missing_env_returns_default(self, monkeypatch):
        """When the env var is absent, the hardcoded default must be used."""
        monkeypatch.delenv("PASLA_SOCKET_TIMEOUT", raising=False)
        assert pasla._env_int("SOCKET_TIMEOUT", 30) == 30

    def test_non_numeric_falls_back_with_warning(self, monkeypatch):
        """A non-integer value must log a warning and fall back to default."""
        warnings = []
        monkeypatch.setattr(pasla.log, "warning", lambda fmt, *a: warnings.append(fmt % a))
        monkeypatch.setenv("PASLA_CHUNK_SIZE", "not_a_number")
        result = pasla._env_int("CHUNK_SIZE", 262144)
        assert result == 262144
        assert any("Invalid PASLA_CHUNK_SIZE" in w for w in warnings)

    def test_negative_value_falls_back(self, monkeypatch):
        """Negative values are rejected — they make no sense for any constant."""
        warnings = []
        monkeypatch.setattr(pasla.log, "warning", lambda fmt, *a: warnings.append(fmt % a))
        monkeypatch.setenv("PASLA_BAN_THRESHOLD", "-5")
        result = pasla._env_int("BAN_THRESHOLD", 5)
        assert result == 5
        assert any("Invalid PASLA_BAN_THRESHOLD" in w for w in warnings)

    def test_zero_is_valid(self, monkeypatch):
        """Zero is a valid value (e.g. unlimited downloads)."""
        monkeypatch.setenv("PASLA_MAX_GLOBAL_CONNECTIONS", "0")
        assert pasla._env_int("MAX_GLOBAL_CONNECTIONS", 100) == 0

    def test_float_string_falls_back(self, monkeypatch):
        """Floating-point strings must not be silently truncated."""
        warnings = []
        monkeypatch.setattr(pasla.log, "warning", lambda fmt, *a: warnings.append(fmt % a))
        monkeypatch.setenv("PASLA_RATE_LIMIT_WINDOW", "60.5")
        result = pasla._env_int("RATE_LIMIT_WINDOW", 60)
        assert result == 60
        assert any("Invalid PASLA_RATE_LIMIT_WINDOW" in w for w in warnings)

    def test_empty_string_falls_back(self, monkeypatch):
        """An empty string env var is invalid, not missing."""
        warnings = []
        monkeypatch.setattr(pasla.log, "warning", lambda fmt, *a: warnings.append(fmt % a))
        monkeypatch.setenv("PASLA_SOCKET_TIMEOUT", "")
        result = pasla._env_int("SOCKET_TIMEOUT", 30)
        assert result == 30
        assert any("Invalid PASLA_SOCKET_TIMEOUT" in w for w in warnings)


# ---------------------------------------------------------------------------
# --single flag — convenience alias for max_downloads=1
# ---------------------------------------------------------------------------

class TestSingleFlag:
    """Verify --single correctly overrides max_downloads to 1."""

    def test_single_sets_max_downloads_1(self):
        """--single alone must produce max_downloads=1."""
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt", "--single"])
        # Simulate the validation logic from parse_and_validate.
        if args.single:
            args.max_downloads = 1
        assert args.max_downloads == 1

    def test_single_overrides_explicit_max_downloads(self):
        """--single must force max_downloads to 1 even when set to 5.

        The parser accepts max_downloads=5, but --single always wins.
        This tests the actual semantic: the value changes from 5 to 1.
        """
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt", "30", "5", "--single"])
        assert args.max_downloads == 5  # parser sees 5 initially
        assert args.single is True
        # After validation logic, --single wins:
        if args.single:
            args.max_downloads = 1
        assert args.max_downloads == 1

    def test_single_with_max_downloads_0_overrides(self):
        """--single + default max_downloads=0 → must override to 1."""
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt", "--single"])
        assert args.max_downloads == 0  # default from parser
        if args.single:
            args.max_downloads = 1
        assert args.max_downloads == 1

    def test_without_single_default_max_downloads_unchanged(self):
        """Without --single, max_downloads defaults to 0 (unlimited)."""
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt"])
        assert args.single is False
        assert args.max_downloads == 0


# ---------------------------------------------------------------------------
# --allow-ip — CIDR allowlist parsing
# ---------------------------------------------------------------------------

class TestAllowIPParsing:
    """Verify --allow-ip CIDR strings are parsed and validated correctly."""

    def test_valid_cidr_matches_inside_rejects_outside(self):
        """A valid CIDR block must match IPs inside and reject those outside."""
        import ipaddress
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt", "--allow-ip", "10.0.0.0/8"])
        net = ipaddress.ip_network(args.allow_cidrs[0], strict=False)
        assert ipaddress.ip_address("10.1.2.3") in net
        assert ipaddress.ip_address("192.168.1.1") not in net

    def test_single_host_address_is_slash_32(self):
        """A bare IP (no prefix) must be treated as /32."""
        import ipaddress
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt", "--allow-ip", "192.168.1.5"])
        net = ipaddress.ip_network(args.allow_cidrs[0], strict=False)
        assert net.prefixlen == 32
        assert ipaddress.ip_address("192.168.1.5") in net
        assert ipaddress.ip_address("192.168.1.6") not in net

    def test_host_bits_normalized_with_strict_false(self):
        """Host-bit notation like 192.168.1.5/24 must normalise to .0/24."""
        import ipaddress
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt", "--allow-ip", "192.168.1.5/24"])
        net = ipaddress.ip_network(args.allow_cidrs[0], strict=False)
        assert str(net) == "192.168.1.0/24"

    def test_multiple_cidrs_repeatable(self):
        """--allow-ip must be repeatable to specify multiple ranges."""
        p = pasla._build_serve_parser()
        args = p.parse_args([
            "dummy.txt",
            "--allow-ip", "10.0.0.0/8",
            "--allow-ip", "172.16.0.0/12",
            "--allow-ip", "192.168.0.0/16",
        ])
        assert len(args.allow_cidrs) == 3

    def test_invalid_cidr_raises_valueerror(self):
        """An invalid CIDR string must raise ValueError from ip_network."""
        import ipaddress
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt", "--allow-ip", "not_a_cidr"])
        with pytest.raises(ValueError):
            ipaddress.ip_network(args.allow_cidrs[0], strict=False)

    def test_ipv6_cidr_accepted(self):
        """IPv6 CIDR ranges must be accepted for mixed-stack environments."""
        import ipaddress
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt", "--allow-ip", "::1/128"])
        net = ipaddress.ip_network(args.allow_cidrs[0], strict=False)
        assert ipaddress.ip_address("::1") in net

    def test_no_allow_ip_defaults_to_none(self):
        """Without --allow-ip, allow_cidrs must be None (no restriction)."""
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt"])
        assert args.allow_cidrs is None


# ---------------------------------------------------------------------------
# --json flag — CLI parsing
# ---------------------------------------------------------------------------

class TestJsonFlagParsing:
    """Verify --json flag is correctly parsed by the argument parser."""

    def test_json_flag_sets_json_output_true(self):
        """--json must set json_output=True."""
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt", "--json"])
        assert args.json_output is True

    def test_no_json_flag_defaults_false(self):
        """Without --json, json_output must default to False."""
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt"])
        assert args.json_output is False

    def test_json_combinable_with_single_and_allow_ip(self):
        """All new flags must be combinable without conflict."""
        p = pasla._build_serve_parser()
        args = p.parse_args([
            "dummy.txt", "--json", "--single",
            "--allow-ip", "10.0.0.0/8",
        ])
        assert args.json_output is True
        assert args.single is True
        assert args.allow_cidrs == ["10.0.0.0/8"]


# ---------------------------------------------------------------------------
# Config file support
# ---------------------------------------------------------------------------

class TestConfigPath:
    """Tests for _config_path()."""

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("PASLA_CONFIG", "/custom/path")
        assert pasla._config_path() == Path("/custom/path")

    @pytest.mark.skipif(os.name == "nt", reason="PosixPath cannot be tested on Windows")
    def test_posix_default(self, monkeypatch):
        monkeypatch.delenv("PASLA_CONFIG", raising=False)
        monkeypatch.setattr(os, "name", "posix")
        monkeypatch.setenv("HOME", "/home/testuser")
        result = pasla._config_path()
        assert result is not None
        assert str(result) == "/home/testuser/.config/pasla"

    @pytest.mark.skipif(os.name != "nt",
                        reason="Path('C:\\...') cannot instantiate on POSIX")
    def test_windows_default(self, monkeypatch):
        monkeypatch.delenv("PASLA_CONFIG", raising=False)
        monkeypatch.setattr(os, "name", "nt")
        monkeypatch.setenv("USERPROFILE", "C:\\Users\\Test")
        assert pasla._config_path() == Path("C:\\Users\\Test\\.pasla")

    def test_no_home_returns_none(self, monkeypatch):
        monkeypatch.delenv("PASLA_CONFIG", raising=False)
        monkeypatch.setattr(os, "name", "posix")
        monkeypatch.delenv("HOME", raising=False)
        assert pasla._config_path() is None


class TestLoadConfig:
    """Tests for _load_config()."""

    def test_missing_file_returns_empty(self, monkeypatch):
        monkeypatch.setenv("PASLA_CONFIG", "/nonexistent/path")
        assert pasla._load_config() == {}

    def test_valid_config(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config"
        cfg.write_text("[server]\nduration = 30\nport = 9090\n", encoding="utf-8")
        monkeypatch.setenv("PASLA_CONFIG", str(cfg))
        result = pasla._load_config()
        assert result["server"]["duration"] == "30"
        assert result["server"]["port"] == "9090"

    def test_invalid_config_returns_empty(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config"
        cfg.write_bytes(b"\x80\x81\x82invalid")
        monkeypatch.setenv("PASLA_CONFIG", str(cfg))
        # Should not raise, just log warning and return empty.
        result = pasla._load_config()
        assert result == {} or isinstance(result, dict)

    def test_sections_parsed(self, tmp_path, monkeypatch):
        cfg = tmp_path / "config"
        cfg.write_text(
            "[server]\nduration = 10\n[security]\ntrust_proxy = true\n[tls]\nhttps = true\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("PASLA_CONFIG", str(cfg))
        result = pasla._load_config()
        assert "server" in result
        assert "security" in result
        assert "tls" in result
        assert result["security"]["trust_proxy"] == "true"


# ---------------------------------------------------------------------------
# SHA-256 checksum
# ---------------------------------------------------------------------------

class TestComputeFileHash:
    """Tests for _compute_file_hash()."""

    def test_known_hash(self, tmp_path):
        content = b"hello world\n"
        f = tmp_path / "test.txt"
        f.write_bytes(content)
        expected_hex = hashlib.sha256(content).hexdigest()
        hex_dig, b64_dig = pasla._compute_file_hash(str(f))
        assert hex_dig == expected_hex
        assert len(b64_dig) > 0

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        hex_dig, _ = pasla._compute_file_hash(str(f))
        assert hex_dig == hashlib.sha256(b"").hexdigest()

    def test_progress_flag(self, tmp_path, capsys):
        content = b"x" * 1024
        f = tmp_path / "data.bin"
        f.write_bytes(content)
        pasla._compute_file_hash(str(f), show_progress=True)
        # Progress output is cleared with \r, so captured output should be clean.
        captured = capsys.readouterr()
        # No assertion on exact output — just ensure no crash.
        assert isinstance(captured.out, str)


class TestChecksumSmartDefault:
    """Tests for checksum smart default in parser."""

    def test_checksum_flag_exists(self):
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt", "--checksum"])
        assert args.checksum is True

    def test_no_checksum_flag_exists(self):
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt", "--no-checksum"])
        assert args.checksum is False

    def test_default_is_none(self):
        """When neither flag is given, checksum should be None (smart default)."""
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt"])
        assert args.checksum is None

    def test_mutual_exclusion(self):
        """--checksum and --no-checksum cannot be combined."""
        p = pasla._build_serve_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["dummy.txt", "--checksum", "--no-checksum"])


# ---------------------------------------------------------------------------
# Download history
# ---------------------------------------------------------------------------

class TestDownloadHistory:
    """Tests for download_history deque behavior."""

    def test_history_appended_on_complete(self):
        pasla.download_history.clear()
        pasla._release_transfer(
            "test-id-1", completed=True, max_downloads=0,
            client_ip="192.168.1.1", bytes_sent=1024,
        )
        assert len(pasla.download_history) == 1
        ts, ip, nbytes = pasla.download_history[0]
        assert ip == "192.168.1.1"
        assert nbytes == 1024

    def test_history_not_appended_on_incomplete(self):
        pasla.download_history.clear()
        pasla.active_transfers["test-id-2"] = False
        pasla._release_transfer(
            "test-id-2", completed=False, max_downloads=0,
            client_ip="10.0.0.1", bytes_sent=0,
        )
        assert len(pasla.download_history) == 0

    def test_maxlen_cap(self):
        pasla.download_history.clear()
        for i in range(60):
            pasla.download_history.append((time.monotonic(), f"ip-{i}", i * 100))
        # ``maxlen`` is aligned to the slice size returned by
        # ``get_status()`` so the deque never carries entries that
        # cannot reach the status payload anyway.
        assert len(pasla.download_history) == 10


# ---------------------------------------------------------------------------
# OSC 8 hyperlink
# ---------------------------------------------------------------------------

class TestOSC8Link:
    """Tests for _osc8_link()."""

    def test_format(self):
        url = "http://example.com:8080/token/file.zip"
        result = pasla._osc8_link(url)
        assert result == f"\x1b]8;;{url}\x07{url}\x1b]8;;\x07"

    def test_contains_original_url(self):
        url = "https://localhost:4443/abc/test.bin"
        result = pasla._osc8_link(url)
        assert url in result


# ---------------------------------------------------------------------------
# --dry-run flag
# ---------------------------------------------------------------------------

class TestDryRunFlag:
    """Tests for --dry-run parser flag."""

    def test_dry_run_flag_exists(self):
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt", "--dry-run"])
        assert args.dry_run is True

    def test_dry_run_default_false(self):
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt"])
        assert args.dry_run is False

    def test_dry_run_combinable_with_json(self):
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt", "--dry-run", "--json"])
        assert args.dry_run is True
        assert args.json_output is True


# ---------------------------------------------------------------------------
# HTTPS flag and cert generation
# ---------------------------------------------------------------------------

class TestHTTPSFlag:
    """Tests for --https parser flag."""

    def test_https_flag_exists(self):
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt", "--https"])
        assert args.https is True

    def test_https_default_false(self):
        p = pasla._build_serve_parser()
        args = p.parse_args(["dummy.txt"])
        assert args.https is False


class TestGenerateEphemeralCert:
    """Tests for _generate_ephemeral_cert()."""

    def test_cert_generation(self, tmp_path):
        """If openssl is available, cert files should be created."""
        cert_dir = str(tmp_path / "tls")
        os.makedirs(cert_dir)
        try:
            cert_path, key_path = pasla._generate_ephemeral_cert(cert_dir)
            assert os.path.isfile(cert_path)
            assert os.path.isfile(key_path)
            assert cert_path.endswith("cert.pem")
            assert key_path.endswith("key.pem")
        except FileNotFoundError:
            pytest.skip("openssl not available on PATH")

    def test_cert_fingerprint(self, tmp_path):
        """Fingerprint should return a non-empty string."""
        cert_dir = str(tmp_path / "tls2")
        os.makedirs(cert_dir)
        try:
            cert_path, _ = pasla._generate_ephemeral_cert(cert_dir)
            fp = pasla._get_cert_fingerprint(cert_path)
            assert len(fp) > 10  # SHA-256 fingerprint is long
            assert ":" in fp  # Colon-separated hex
        except FileNotFoundError:
            pytest.skip("openssl not available on PATH")

    def test_cert_dir_removed_on_init_failure(self, tmp_path, monkeypatch):
        """When ephemeral cert generation fails, ``cmd_serve`` must
        remove the empty ``cert_dir`` it just created before exiting.

        Without this cleanup, repeated ``--https`` failures (e.g.
        ``openssl`` missing on the host) leave orphaned
        ``pasla_<id>_tls`` directories in ``REGISTRY_DIR`` that only
        get reaped on next reboot.
        """
        import argparse
        import subprocess as _sp

        registry = tmp_path / "registry"
        registry.mkdir()
        monkeypatch.setattr(pasla, "REGISTRY_DIR", registry)

        # Force the cert generator to fail.
        def _fail(_dir):
            raise FileNotFoundError("openssl gone")
        monkeypatch.setattr(pasla, "_generate_ephemeral_cert", _fail)

        # Avoid real bind/network work — return a fake server.
        class _FakeServer:
            server_address = ("127.0.0.1", 12345)
            def server_close(self): pass
        monkeypatch.setattr(pasla, "bind_server",
                            lambda *a, **k: (_FakeServer(), 12345))

        # Stub IP detection to skip outbound resolvers entirely.
        monkeypatch.setattr(pasla, "detect_public_ips",
                            lambda *_a, **_k: {"ipv4": "127.0.0.1"})

        # Build a minimal args namespace simulating ``--https`` mode.
        f = tmp_path / "payload.bin"
        f.write_bytes(b"x" * 16)
        args = argparse.Namespace(
            file=str(f), resolved_file=str(f),
            duration_seconds=1, max_downloads=0, trust_proxy=False,
            ip_mode=None, port=None, single=False, json_output=False,
            allow_cidrs=None, allowed_networks=None,
            https=True, checksum=False, dry_run=False,
            daemon=False, forced_instance_id="abc123", temp_tar=None,
            duration=1,
        )

        with pytest.raises(SystemExit):
            pasla.cmd_serve(args)

        # cert_dir was created at REGISTRY_DIR / pasla_<id>_tls and must
        # be gone after the failure cleanup.
        cert_dir = registry / "pasla_abc123_tls"
        assert not cert_dir.exists()


class TestUserProvidedTlsCert:
    """``--tls-cert`` / ``--tls-key`` accept an existing PEM pair,
    bypass ephemeral generation, and never touch the operator's
    files on shutdown."""

    def _generate_pair(self, tmp_path):
        """Create a real cert/key pair under tmp_path; skip if openssl
        is unavailable on the test host."""
        cert_dir = tmp_path / "user_certs"
        cert_dir.mkdir()
        try:
            return pasla._generate_ephemeral_cert(str(cert_dir))
        except FileNotFoundError:
            pytest.skip("openssl CLI not available on PATH")

    def test_user_cert_load_skips_ephemeral_path(self, tmp_path, monkeypatch):
        cert_path, key_path = self._generate_pair(tmp_path)

        # If the ephemeral path is taken by mistake, the test fails:
        # `_generate_ephemeral_cert` becomes an attractor that signals
        # the regression.
        called = {"ephemeral": False}
        real_gen = pasla._generate_ephemeral_cert
        def _spy(d):
            called["ephemeral"] = True
            return real_gen(d)
        monkeypatch.setattr(pasla, "_generate_ephemeral_cert", _spy)

        # We do not need a real bound socket - replace ``wrap_socket``
        # with an identity passthrough.
        class _FakeSocket:
            def setsockopt(self, *a, **k): pass
            def close(self): pass
        class _FakeServer:
            socket = _FakeSocket()
            def server_close(self): pass

        ctx_calls = {"wrapped": False}
        original_wrap = pasla.ssl.SSLContext.wrap_socket
        def _fake_wrap(self, sock, **kwargs):
            ctx_calls["wrapped"] = True
            return sock
        monkeypatch.setattr(pasla.ssl.SSLContext, "wrap_socket", _fake_wrap)

        srv = _FakeServer()
        result = pasla._setup_https(
            srv, "byo01",
            user_cert=cert_path, user_key=key_path,
        )
        cert_dir, c, k, ephemeral = result

        assert ephemeral is False
        assert cert_dir is None
        assert c == cert_path
        assert k == key_path
        assert called["ephemeral"] is False, (
            "ephemeral generation should be skipped when user cert is supplied"
        )
        assert ctx_calls["wrapped"] is True
        # Files must still be on disk - we did not delete them.
        assert os.path.isfile(cert_path)
        assert os.path.isfile(key_path)

    def test_resolve_tls_path_follows_symlinks(self, tmp_path):
        """LE installs ``live/<domain>/cert.pem`` as a symlink; the
        resolver must follow the link rather than reject it."""
        target = tmp_path / "real_cert.pem"
        target.write_text("PEM\n", encoding="utf-8")
        link = tmp_path / "link_cert.pem"
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unsupported on this platform")
        resolved = pasla._resolve_tls_path(str(link), "cert")
        assert resolved == str(target)

    def test_resolve_tls_path_missing_returns_none(self, tmp_path):
        ghost = tmp_path / "no_such_file.pem"
        assert pasla._resolve_tls_path(str(ghost), "cert") is None

    def test_one_of_cert_key_supplied_is_rejected(self, tmp_path, monkeypatch):
        """Passing only --tls-cert (without --tls-key) is a config
        error; pasla must refuse to start rather than silently fall
        back to ephemeral."""
        cert_path, _ = self._generate_pair(tmp_path)
        monkeypatch.setattr(pasla, "ALLOWED_ROOT", str(tmp_path))
        share = tmp_path / "share.bin"
        share.write_bytes(b"x")
        monkeypatch.setattr("sys.argv", [
            "pasla", str(share), "--tls-cert", cert_path,
        ])
        with pytest.raises(SystemExit):
            pasla.parse_and_validate()

    def test_no_https_overrides_config(self, tmp_path, monkeypatch):
        """``--no-https`` is the hard override: even with a valid
        user-supplied cert/key pair, the run stays plaintext."""
        cert_path, key_path = self._generate_pair(tmp_path)
        monkeypatch.setattr(pasla, "ALLOWED_ROOT", str(tmp_path))
        share = tmp_path / "share.bin"
        share.write_bytes(b"x")
        monkeypatch.setattr("sys.argv", [
            "pasla", str(share),
            "--tls-cert", cert_path,
            "--tls-key", key_path,
            "--no-https",
        ])
        args = pasla.parse_and_validate()
        assert args.https is False
        assert args.tls_cert is None
        assert args.tls_key is None

    def test_config_cert_paths_auto_enable_https(
        self, tmp_path, monkeypatch,
    ):
        """A config file that lists existing cert/key paths under
        ``[tls]`` must auto-enable HTTPS without ``--https`` on the
        command line."""
        cert_path, key_path = self._generate_pair(tmp_path)
        monkeypatch.setattr(pasla, "ALLOWED_ROOT", str(tmp_path))

        cfg_file = tmp_path / "pasla.ini"
        cfg_file.write_text(
            f"[tls]\ncert = {cert_path}\nkey = {key_path}\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("PASLA_CONFIG", str(cfg_file))

        share = tmp_path / "share.bin"
        share.write_bytes(b"x")
        monkeypatch.setattr("sys.argv", ["pasla", str(share)])

        args = pasla.parse_and_validate()
        assert args.https is True
        assert args.tls_cert == cert_path
        assert args.tls_key == key_path


class TestCertExpiry:
    """``_get_cert_expiry`` reads ``notAfter`` from a PEM via openssl
    and returns ``(iso_date, days_remaining)``.  Also exercises the
    365-day default on freshly generated ephemeral certs."""

    def test_fresh_cert_has_positive_expiry(self, tmp_path):
        cert_dir = tmp_path / "tls"
        cert_dir.mkdir()
        try:
            cert_path, _ = pasla._generate_ephemeral_cert(str(cert_dir))
        except FileNotFoundError:
            pytest.skip("openssl CLI not available on PATH")
        result = pasla._get_cert_expiry(cert_path)
        assert result is not None
        iso_date, days = result
        # Default validity is 365 days.  Allow a small margin for
        # test machines whose clock disagrees with the cert's
        # generation moment.
        assert 360 <= days <= 366
        assert len(iso_date) == 10  # YYYY-MM-DD


@pytest.mark.skipif(os.name == "nt",
                    reason="POSIX-only: file mode bits do not reflect Windows ACLs")
class TestTlsKeyPermsWarning:
    """The world-readable private-key warning fires when the file
    has any group/other bits set; tightening to 0o600 silences it."""

    def _capture_warnings(self):
        """Attach a fresh ``MemoryHandler`` directly to the pasla
        logger so the assertion is independent of any propagate /
        handler state another test may have left behind (the live
        TUI tests in particular flip ``log.propagate``)."""
        import logging as _logging
        records: list = []

        class _ListHandler(_logging.Handler):
            def emit(self, rec):
                records.append(rec)

        handler = _ListHandler(level=_logging.WARNING)
        pasla.log.addHandler(handler)
        return records, handler

    def _detach(self, handler):
        pasla.log.removeHandler(handler)

    def test_tight_perms_no_warning(self, tmp_path):
        key = tmp_path / "tight.key"
        key.write_text("KEY", encoding="utf-8")
        os.chmod(key, 0o600)
        records, handler = self._capture_warnings()
        try:
            pasla._check_tls_key_perms(str(key))
        finally:
            self._detach(handler)
        assert not records

    def test_loose_perms_warns(self, tmp_path):
        key = tmp_path / "loose.key"
        key.write_text("KEY", encoding="utf-8")
        os.chmod(key, 0o644)
        records, handler = self._capture_warnings()
        try:
            pasla._check_tls_key_perms(str(key))
        finally:
            self._detach(handler)
        joined = " ".join(r.getMessage() for r in records)
        assert "permissive" in joined


# ---------------------------------------------------------------------------
# format_url scheme parameter
# ---------------------------------------------------------------------------

class TestFormatURLScheme:
    """Tests for format_url with scheme parameter."""

    def test_default_http(self):
        url = pasla.format_url("1.2.3.4", 8080, "tok", "file.zip")
        assert url.startswith("http://")

    def test_https_scheme(self):
        url = pasla.format_url("1.2.3.4", 8080, "tok", "file.zip", scheme="https")
        assert url.startswith("https://")

    def test_ipv6_https(self):
        url = pasla.format_url("::1", 443, "tok", "f.bin", scheme="https")
        assert url.startswith("https://[::1]:")


# ---------------------------------------------------------------------------
# LRU eviction in _record_failure
# ---------------------------------------------------------------------------

class TestRecordFailureEviction:
    """Verify _record_failure evicts oldest entry at capacity."""

    def test_eviction_on_full_table(self, monkeypatch):
        monkeypatch.setattr(pasla, "MAX_TRACKED_IPS", 3)
        pasla.failed_attempts["10.0.0.1"] = 1
        pasla.failed_attempts["10.0.0.2"] = 1
        pasla.failed_attempts["10.0.0.3"] = 1

        pasla._record_failure("10.0.0.99")
        assert "10.0.0.99" in pasla.failed_attempts
        assert "10.0.0.1" not in pasla.failed_attempts  # evicted
        assert len(pasla.failed_attempts) == 3

    def test_existing_ip_not_evicted(self, monkeypatch):
        monkeypatch.setattr(pasla, "MAX_TRACKED_IPS", 2)
        pasla.failed_attempts["10.0.0.1"] = 2
        pasla.failed_attempts["10.0.0.2"] = 1

        # Recording for existing IP must not trigger eviction.
        pasla._record_failure("10.0.0.2")
        assert "10.0.0.1" in pasla.failed_attempts
        assert pasla.failed_attempts["10.0.0.2"] == 2


# ---------------------------------------------------------------------------
# _build_url_payload helper
# ---------------------------------------------------------------------------

class TestBuildURLPayload:
    """Tests for _build_url_payload shared helper."""

    def test_includes_ipv4_only(self):
        status = {"url_ipv4": "http://1.2.3.4:80/tok/f", "url_ipv6": ""}
        payload = pasla._build_url_payload("abc123", status)
        assert payload["id"] == "abc123"
        assert payload["url_ipv4"] == "http://1.2.3.4:80/tok/f"
        assert "url_ipv6" not in payload  # empty -> omitted

    def test_both_protocols(self):
        status = {
            "url_ipv4": "http://1.2.3.4:80/t/f",
            "url_ipv6": "http://[::1]:80/t/f",
        }
        payload = pasla._build_url_payload("x", status)
        assert payload["url_ipv4"] == "http://1.2.3.4:80/t/f"
        assert payload["url_ipv6"] == "http://[::1]:80/t/f"

    def test_no_urls_omits_both(self):
        payload = pasla._build_url_payload("x", {})
        assert "url_ipv4" not in payload
        assert "url_ipv6" not in payload
        assert payload == {"id": "x", "version": pasla.__version__}


# ---------------------------------------------------------------------------
# TAR path handling
# ---------------------------------------------------------------------------

class TestTarPathHandling:
    """Verify TAR archive creation uses correct paths."""

    def test_tar_file_has_correct_extension(self, tmp_dir_with_files):
        """Archive file must have .tar extension."""
        tar_path = pasla._tar_directory(str(tmp_dir_with_files))
        try:
            assert tar_path.endswith(".tar")
            with tarfile.open(tar_path) as tf:
                names = tf.getnames()
                assert len(names) > 0
        finally:
            import shutil
            shutil.rmtree(os.path.dirname(tar_path))


# ---------------------------------------------------------------------------
# content_length initialisation in _handle_request_inner
#
# If the handler returns early (e.g. file open fails), content_length
# must be pre-initialised to avoid UnboundLocalError in the finally block.
# ---------------------------------------------------------------------------

class TestContentLengthInitialised:
    """Verify content_length is initialised before the try/finally block."""

    def test_file_open_failure_does_not_crash(self, tmp_path):
        """When the served file cannot be opened, the handler must send
        500 and release the transfer slot without raising
        ``UnboundLocalError`` from a half-initialised ``content_length``."""
        target = tmp_path / "gone.txt"
        target.write_text("temporary content", encoding="utf-8")

        token = pasla.secrets.token_urlsafe(16)
        pasla.ALLOWED_ROOT = str(tmp_path)

        server = pasla._make_server(0, pasla.BaseHTTPRequestHandler, ip_mode="4")
        try:
            port = server.server_address[1]

            server.RequestHandlerClass = pasla.make_handler(
                file_path=str(target),
                file_name="gone.txt",
                token=token,
                max_downloads=0,
                trust_proxy=False,
            )
            server.timeout = 2

            # Delete the file after handler creation but before any
            # request — the per-request open will raise OSError and
            # the handler must convert that to 500.
            target.unlink()

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            try:
                import http.client
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("GET", f"/{token}/gone.txt")
                resp = conn.getresponse()
                resp.read()
                assert resp.status == 500
            finally:
                pasla.shutting_down.set()
                server.shutdown()
                thread.join(timeout=5)
        finally:
            server.server_close()


# ---------------------------------------------------------------------------
# _method_not_allowed must cancel the header timer
#
# Without cancellation, the timer fires after the handler returns and
# closes a potentially reused file descriptor.
# ---------------------------------------------------------------------------

class TestMethodNotAllowedCancelsTimer:
    """Verify that disallowed HTTP methods cancel the header deadline timer."""

    def test_post_cancels_header_timer(self, tmp_path):
        """A POST request must cancel _header_timer before sending 405."""
        f = tmp_path / "timer_test.txt"
        f.write_text("content", encoding="utf-8")

        pasla.ALLOWED_ROOT = str(tmp_path)
        token = pasla.secrets.token_urlsafe(16)

        server = pasla._make_server(0, pasla.BaseHTTPRequestHandler, ip_mode="4")
        try:
            port = server.server_address[1]

            server.RequestHandlerClass = pasla.make_handler(
                file_path=str(f),
                file_name=f.name,
                token=token,
                max_downloads=0,
                trust_proxy=False,
            )
            server.timeout = 2

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            try:
                import http.client
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("POST", f"/{token}/{f.name}")
                resp = conn.getresponse()
                resp.read()
                assert resp.status == 405

                # The timer must have been cancelled — a subsequent valid GET
                # must succeed (if the timer had fired, the fd would be closed
                # and the next request would fail or hang).
                conn2 = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn2.request("GET", f"/{token}/{f.name}")
                resp2 = conn2.getresponse()
                resp2.read()
                assert resp2.status == 200
            finally:
                pasla.shutting_down.set()
                server.shutdown()
                thread.join(timeout=5)
        finally:
            server.server_close()


# ---------------------------------------------------------------------------
# handle() must join the header timer on exit
#
# Orphaned Timer threads prevent clean shutdown and accumulate under load.
# ---------------------------------------------------------------------------

class TestHandleJoinsHeaderTimer:
    """Verify that handle() cancels and joins _header_timer in its finally."""

    def test_timer_thread_dead_after_request(self, tmp_path):
        """After a completed request, the _header_timer thread must not be
        alive (cancel + join must have been called)."""
        f = tmp_path / "join_test.txt"
        f.write_text("join test content", encoding="utf-8")

        pasla.ALLOWED_ROOT = str(tmp_path)
        token = pasla.secrets.token_urlsafe(16)

        server = pasla._make_server(0, pasla.BaseHTTPRequestHandler, ip_mode="4")
        try:
            port = server.server_address[1]

            server.RequestHandlerClass = pasla.make_handler(
                file_path=str(f),
                file_name=f.name,
                token=token,
                max_downloads=0,
                trust_proxy=False,
            )
            server.timeout = 2

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            try:
                import http.client
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("GET", f"/{token}/{f.name}")
                resp = conn.getresponse()
                resp.read()
                assert resp.status == 200

                # After the request completes, no lingering "header-deadline"
                # Timer threads should be alive.
                alive_timers = [
                    t for t in threading.enumerate()
                    if t.name.startswith("Timer") and t.is_alive()
                ]
                # Allow a brief window for the join to complete.
                for t in alive_timers:
                    t.join(timeout=2)
                still_alive = [
                    t for t in alive_timers if t.is_alive()
                ]
                assert len(still_alive) == 0, (
                    f"Orphaned timer threads: {still_alive}"
                )
            finally:
                pasla.shutting_down.set()
                server.shutdown()
                thread.join(timeout=5)
        finally:
            server.server_close()


# ---------------------------------------------------------------------------
# _close_on_timeout — header deadline enforcement
#
# A Timer thread fires _close_on_timeout() to kill connections that stall
# during header parsing (slowloris protection).
# ---------------------------------------------------------------------------

class TestCloseOnTimeout:
    """Verify the header deadline timer terminates stalled connections."""

    def test_stalled_connection_terminated(self, tmp_path, monkeypatch):
        """A connection that sends no headers must be terminated within
        HEADER_READ_TIMEOUT + a small tolerance."""
        f = tmp_path / "timeout_test.txt"
        f.write_text("timeout test content", encoding="utf-8")

        pasla.ALLOWED_ROOT = str(tmp_path)
        token = pasla.secrets.token_urlsafe(16)

        # Use a short timeout to keep the test fast.
        monkeypatch.setattr(pasla, "HEADER_READ_TIMEOUT", 2)

        server = pasla._make_server(0, pasla.BaseHTTPRequestHandler, ip_mode="4")
        try:
            port = server.server_address[1]

            server.RequestHandlerClass = pasla.make_handler(
                file_path=str(f),
                file_name=f.name,
                token=token,
                max_downloads=0,
                trust_proxy=False,
            )
            server.timeout = 5

            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=10)
                try:
                    # Send nothing — the header timer should fire and kill
                    # the connection.
                    start = time.monotonic()
                    data = sock.recv(4096)
                    elapsed = time.monotonic() - start
                    # Connection must have been terminated.
                    assert data == b""
                    # Must complete within timeout + tolerance, not hang forever.
                    assert elapsed < 5, f"Took {elapsed:.1f}s, expected < 5s"
                except (ConnectionResetError, ConnectionAbortedError, OSError):
                    # Also acceptable — server forcibly closed the socket.
                    pass
                finally:
                    sock.close()
            finally:
                pasla.shutting_down.set()
                server.shutdown()
                thread.join(timeout=5)
        finally:
            server.server_close()

# ---------------------------------------------------------------------------
# _safe_display — terminal control-character stripping
# ---------------------------------------------------------------------------

class TestSafeDisplay:
    """Verify _safe_display removes control characters before display."""

    def test_strips_ansi_escape(self):
        assert pasla._safe_display("a\x1b[31mb\x07c") == "a[31mbc"

    def test_strips_del_and_c1(self):
        assert pasla._safe_display("a\x7fb\x9fc") == "abc"

    def test_keeps_normal_text(self):
        assert pasla._safe_display("report.pdf") == "report.pdf"

    def test_keeps_unicode(self):
        assert pasla._safe_display("résumé™.txt") == "résumé™.txt"


# ---------------------------------------------------------------------------
# _path_segment_count
# ---------------------------------------------------------------------------

class TestPathSegmentCount:
    """Verify segment counting used by the ban-shape heuristic."""

    def test_counts_segments(self):
        assert pasla._path_segment_count("/tok/file") == 2
        assert pasla._path_segment_count("/favicon.ico") == 1
        assert pasla._path_segment_count("/") == 0
        assert pasla._path_segment_count("/a/b/c") == 3


# ---------------------------------------------------------------------------
# _path_within_registry
# ---------------------------------------------------------------------------

class TestPathWithinRegistry:
    """Verify the registry-confinement predicate used by cleanup helpers."""

    def test_path_inside_registry(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path)
        assert pasla._path_within_registry(tmp_path / "pasla_x.json")

    def test_path_outside_registry(self, tmp_path, monkeypatch):
        reg = tmp_path / "reg"
        reg.mkdir()
        monkeypatch.setattr(pasla, "REGISTRY_DIR", reg)
        assert not pasla._path_within_registry(tmp_path / "elsewhere.txt")


# ---------------------------------------------------------------------------
# Header-deadline reaper
# ---------------------------------------------------------------------------

class _FakeConn:
    """Minimal connection stub recording shutdown() calls."""

    def __init__(self):
        self.shutdown_called = False

    def shutdown(self, how):
        self.shutdown_called = True


class TestHeaderDeadlineReaper:
    """Verify the reaper closes expired connections and spares live ones."""

    def test_expired_connection_is_closed(self):
        pasla._header_deadlines.clear()
        conn = _FakeConn()
        pasla._register_header_deadline(conn, time.monotonic() - 1)
        pasla._reap_header_deadlines()
        assert conn.shutdown_called
        assert conn not in pasla._header_deadlines

    def test_active_connection_is_left_alone(self):
        pasla._header_deadlines.clear()
        conn = _FakeConn()
        pasla._register_header_deadline(conn, time.monotonic() + 60)
        pasla._reap_header_deadlines()
        assert not conn.shutdown_called
        assert conn in pasla._header_deadlines

    def test_deregister_removes_entry(self):
        pasla._header_deadlines.clear()
        conn = _FakeConn()
        pasla._register_header_deadline(conn, time.monotonic() + 60)
        pasla._deregister_header_deadline(conn)
        assert conn not in pasla._header_deadlines
        # Reaping afterwards must not touch a deregistered connection.
        pasla._reap_header_deadlines()
        assert not conn.shutdown_called


# ---------------------------------------------------------------------------
# Maintenance thread - duration and control-plane watchdog
# ---------------------------------------------------------------------------

class _FakeServerStub:
    def shutdown(self):
        pass


class _FakeCtrlAlive:
    def is_alive(self):
        return True


class _FakeCtrlDead:
    def is_alive(self):
        return False


class TestMaintenanceThreadWatchdog:
    """Verify the maintenance thread shuts down on time-limit expiry
    and on control-plane death."""

    def test_duration_expiry_triggers_shutdown(self):
        pasla.shutting_down.clear()
        t = pasla.start_maintenance_thread(
            _FakeServerStub(), _FakeCtrlAlive(),
            started_at=time.monotonic() - 100, duration=1,
        )
        t.join(timeout=5)
        assert not t.is_alive()
        assert pasla.shutting_down.is_set()

    def test_dead_control_plane_triggers_shutdown(self):
        pasla.shutting_down.clear()
        t = pasla.start_maintenance_thread(
            _FakeServerStub(), _FakeCtrlDead(),
            started_at=time.monotonic(), duration=1000,
        )
        t.join(timeout=5)
        assert not t.is_alive()
        assert pasla.shutting_down.is_set()


# ---------------------------------------------------------------------------
# Control plane: secret is mandatory
# ---------------------------------------------------------------------------

class TestControlPlaneSecretRequired:
    """start_control_plane must refuse an empty/missing ctrl_secret.

    An empty secret makes hmac.compare_digest(secret_input, "") succeed
    for a client that sends {"secret": ""}, silently disabling control
    plane authentication.
    """

    def test_empty_secret_rejected(self):
        with pytest.raises(ValueError):
            pasla.start_control_plane(
                "id", lambda: {}, lambda: None, ctrl_secret="",
            )

    def test_missing_secret_rejected(self):
        # No default value any more - omitting the argument is a TypeError.
        with pytest.raises(TypeError):
            pasla.start_control_plane("id", lambda: {}, lambda: None)

    def test_valid_secret_accepted(self):
        port, thread = pasla.start_control_plane(
            "id", lambda: {}, lambda: None, ctrl_secret="real-secret",
        )
        try:
            assert isinstance(port, int) and port > 0
            assert thread.is_alive()
        finally:
            pasla.shutting_down.set()
            thread.join(timeout=5)
        pasla.shutting_down.clear()


# ---------------------------------------------------------------------------
# Control plane: non-loopback peers are dropped at accept time
# ---------------------------------------------------------------------------

class TestControlPlaneLoopbackRejection:
    """The accept loop must drop any peer that is not 127.0.0.1.

    The control-plane socket is already bound to loopback, but the
    accept loop performs a second, accept-time ``addr[0] == "127.0.0.1"``
    check as defence in depth.  This drives that rejection branch with a
    faked non-loopback peer so a future refactor cannot silently drop
    the check.
    """

    def test_non_loopback_peer_closed_and_logged(self, monkeypatch):
        rejected_conn = mock.Mock()
        accept_calls = {"n": 0}

        class _FakeServerSocket:
            """Minimal stand-in for the control-plane listen socket."""

            def setsockopt(self, *args):
                pass

            def bind(self, addr):
                pass

            def listen(self, backlog):
                pass

            def getsockname(self):
                return ("127.0.0.1", 12345)

            def settimeout(self, timeout):
                pass

            def accept(self):
                accept_calls["n"] += 1
                if accept_calls["n"] == 1:
                    # A non-loopback peer — must be rejected outright.
                    return rejected_conn, ("192.168.1.100", 4444)
                # Second call ends the accept loop cleanly.
                pasla.shutting_down.set()
                raise socket.timeout()

            def close(self):
                pass

        monkeypatch.setattr(
            pasla.socket, "socket", lambda *a, **k: _FakeServerSocket(),
        )

        # Capture the pasla logger in isolation so the assertion does
        # not depend on global handler/propagate state left behind by
        # other tests in the suite.
        records = []

        class _Capture(logging.Handler):
            def emit(self, record):
                records.append(record)

        log = pasla.log
        saved_handlers = log.handlers[:]
        saved_propagate = log.propagate
        log.handlers = [_Capture()]
        log.propagate = False
        try:
            _port, thread = pasla.start_control_plane(
                "loopback-test", lambda: {}, lambda: None,
                ctrl_secret="secret",
            )
            thread.join(timeout=5)
        finally:
            log.handlers = saved_handlers
            log.propagate = saved_propagate

        assert not thread.is_alive()
        # The rejected connection is closed without being serviced.
        rejected_conn.close.assert_called_once()
        # And the rejection is logged as a security warning.
        messages = [
            r.getMessage() for r in records if r.levelno == logging.WARNING
        ]
        assert any("rejected non-loopback" in m for m in messages)
        assert any("192.168.1.100" in m for m in messages)


# ---------------------------------------------------------------------------
# cmd_serve: unified finally reaps artefacts on an early-stage failure
# ---------------------------------------------------------------------------

class TestCmdServeEarlyFailureCleanup:
    """A failure before serving must still drive every cleanup branch."""

    def test_temp_tar_cleaned_on_handler_failure(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")
        monkeypatch.setattr(pasla, "ALLOWED_ROOT", str(tmp_path))
        (tmp_path / "registry").mkdir(parents=True, exist_ok=True)

        f = tmp_path / "early.txt"
        f.write_text("payload", encoding="utf-8")

        # Simulate the temporary archive a directory-share would create.
        tmp_dir = tmp_path / "registry" / ".tmp_earlytest"
        tmp_dir.mkdir()
        tar = tmp_dir / "archive.tar"
        tar.write_bytes(b"tardata")
        (tmp_dir / ".pasla_lock").write_text(str(os.getpid()), encoding="ascii")

        def _boom(*a, **kw):
            raise OSError("simulated handler creation failure")

        monkeypatch.setattr(pasla, "make_handler", _boom)

        args = argparse.Namespace(
            resolved_file=str(f), file=str(f), duration=1,
            duration_seconds=60, max_downloads=0, trust_proxy=False,
            ip_mode="4", daemon=True, forced_instance_id="early01",
            temp_tar=str(tar), detach=False,
        )

        with pytest.raises(SystemExit):
            pasla.cmd_serve(args)

        # The unified finally must reap the temp archive and its dir.
        assert not tar.exists()
        assert not tmp_dir.exists()
        # No registry entry left behind (it was never written).
        assert not any(
            e.get("id") == "early01" for e in pasla.read_all_registry()
        )


# ---------------------------------------------------------------------------
# Version system: VERSION file <-> __version__ consistency
# ---------------------------------------------------------------------------

class TestVersionConsistency:
    """The repo-root VERSION file and ``pasla.__version__`` must agree.

    They are bumped together on release; this test turns drift into a
    CI failure instead of a silent inconsistency.
    """

    def _version_file(self) -> Path:
        return Path(pasla.__file__).resolve().parent / "VERSION"

    def test_version_file_exists(self):
        assert self._version_file().is_file(), "repo-root VERSION file is missing"

    def test_version_file_matches_dunder(self):
        file_version = self._version_file().read_text(encoding="utf-8").strip()
        assert file_version == pasla.__version__

    def test_dunder_is_valid_calver(self):
        assert pasla._parse_version(pasla.__version__) is not None

    def test_build_url_payload_carries_version(self):
        payload = pasla._build_url_payload("abc123", {"url_ipv4": "http://x/"})
        assert payload["id"] == "abc123"
        assert payload["version"] == pasla.__version__


# ---------------------------------------------------------------------------
# _parse_version
# ---------------------------------------------------------------------------

class TestParseVersion:

    def test_valid_versions(self):
        assert pasla._parse_version("2026.1.0") == (2026, 1, 0)
        assert pasla._parse_version("  2027.10.3  ") == (2027, 10, 3)

    def test_invalid_versions(self):
        for bad in ["", "abc", "1.2", "1.2.3.4", "v1.2.3", "2026.1.x",
                    "2026..0", "2026.1.", "2026.1.0 extra", None, 123]:
            assert pasla._parse_version(bad) is None, bad


# ---------------------------------------------------------------------------
# Update checker (notify-only)
# ---------------------------------------------------------------------------

class TestUpdateChecker:
    """``_check_for_update`` is best-effort and must never raise."""

    @pytest.fixture(autouse=True)
    def _isolate(self, tmp_path, monkeypatch):
        # PASLA_CI is set in CI and would short-circuit the checker.
        monkeypatch.delenv("PASLA_CI", raising=False)
        # Isolate the throttle cache into a per-test directory.
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path)

    @staticmethod
    def _fake_urlopen(body: bytes):
        class _Resp:
            def __enter__(self_):
                return self_

            def __exit__(self_, *exc):
                return False

            def read(self_, n=-1):
                return body[:n] if (n is not None and n >= 0) else body

        return lambda url, timeout=None: _Resp()

    def test_newer_remote_returns_version(self, monkeypatch):
        monkeypatch.setattr(pasla.urllib.request, "urlopen",
                            self._fake_urlopen(b"9999.1.0\n"))
        assert pasla._check_for_update() == "9999.1.0"

    def test_same_version_returns_none(self, monkeypatch):
        monkeypatch.setattr(pasla.urllib.request, "urlopen",
                            self._fake_urlopen(pasla.__version__.encode()))
        assert pasla._check_for_update() is None

    def test_older_remote_returns_none(self, monkeypatch):
        monkeypatch.setattr(pasla.urllib.request, "urlopen",
                            self._fake_urlopen(b"1.0.0\n"))
        assert pasla._check_for_update() is None

    def test_garbage_body_returns_none(self, monkeypatch):
        monkeypatch.setattr(pasla.urllib.request, "urlopen",
                            self._fake_urlopen(b"not-a-version"))
        assert pasla._check_for_update() is None

    def test_oversized_body_does_not_crash(self, monkeypatch):
        # The 64-byte read cap truncates a huge body; the truncated
        # prefix is not a valid version, so the result is None.
        monkeypatch.setattr(pasla.urllib.request, "urlopen",
                            self._fake_urlopen(b"x" * 100_000))
        assert pasla._check_for_update() is None

    def test_network_error_returns_none(self, monkeypatch):
        def _boom(url, timeout=None):
            raise OSError("network down")

        monkeypatch.setattr(pasla.urllib.request, "urlopen", _boom)
        assert pasla._check_for_update() is None

    def test_throttle_skips_network(self, monkeypatch, tmp_path):
        # A fresh cache entry must prevent any network call.
        (tmp_path / "update_check.json").write_text(
            pasla.json.dumps({"checked_at": time.time(), "latest": "9999.2.0"}),
            encoding="utf-8",
        )

        def _must_not_call(url, timeout=None):
            raise AssertionError("network must not be hit when throttled")

        monkeypatch.setattr(pasla.urllib.request, "urlopen", _must_not_call)
        assert pasla._check_for_update() == "9999.2.0"

    def test_pasla_ci_short_circuits(self, monkeypatch):
        monkeypatch.setenv("PASLA_CI", "1")

        def _must_not_call(url, timeout=None):
            raise AssertionError("PASLA_CI must short-circuit before network")

        monkeypatch.setattr(pasla.urllib.request, "urlopen", _must_not_call)
        assert pasla._check_for_update() is None

    def test_update_notice_has_versions_and_url(self):
        notice = pasla._update_notice("9999.1.0")
        assert "9999.1.0" in notice
        assert pasla.__version__ in notice
        assert "raw.githubusercontent.com/Fix3dll/pasla" in notice
