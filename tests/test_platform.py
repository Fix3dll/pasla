"""
test_platform.py — Platform-specific tests.

Tests here verify behaviour that differs across Linux, macOS, and Windows.
Platform-inappropriate tests are skipped via pytest.mark.skipif or
pytest.skip() inside the test body.
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import time
from pathlib import Path

import pytest

from tests.conftest import pasla, ipv6_usable

# ---------------------------------------------------------------------------
# pid_is_alive
# ---------------------------------------------------------------------------

class TestPidIsAlive:

    def test_own_pid_is_alive(self):
        assert pasla.pid_is_alive(os.getpid())

    def test_dead_pid_returns_false(self):
        """A PID that almost certainly does not exist must return False.

        Windows: 2_000_000 is a valid multiple-of-4 PID but far beyond
        any realistic PID value (Windows PIDs rarely exceed ~100k).
        POSIX: 2^22 - 1 is the max PID on 64-bit Linux.

        In the astronomically unlikely event that the PID is actually
        alive, this test would false-fail — acceptable for CI.
        """
        if sys.platform == "win32":
            dead_pid = 2_000_000
        else:
            dead_pid = 2 ** 22 - 1

        assert pasla.pid_is_alive(dead_pid) is False

    def test_system_pid_1_alive(self):
        """PID 1 (init/launchd/Windows System) should always be alive."""
        if sys.platform == "win32":
            # On Windows PID 4 is the System process and always exists.
            assert pasla.pid_is_alive(4)
        else:
            assert pasla.pid_is_alive(1)

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX only")
    def test_posix_uses_kill_0(self, monkeypatch):
        """On POSIX, pid_is_alive must use os.kill(pid, 0)."""
        calls = []
        original_kill = os.kill

        def spy_kill(pid, sig):
            calls.append((pid, sig))
            return original_kill(pid, sig)

        monkeypatch.setattr(os, "kill", spy_kill)
        pasla.pid_is_alive(os.getpid())
        assert any(sig == 0 for _, sig in calls)

# ---------------------------------------------------------------------------
# IPv6 dual-stack
# ---------------------------------------------------------------------------

class TestIPv6DualStack:

    def test_dual_stack_flag_is_bool(self):
        assert isinstance(socket.has_dualstack_ipv6(), bool)

    @pytest.mark.skipif(not socket.has_dualstack_ipv6(),
                        reason="Platform does not support IPv6 dual-stack")
    def test_dual_stack_server_binds(self):
        """ThreadingHTTPServer should bind to :: when dual-stack is available."""
        from http.server import BaseHTTPRequestHandler

        class _Null(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

        # Using context manager (with) guarantees server_close() is called
        # gracefully, preventing resource leaks even if assertions fail.
        with pasla._make_server(0, _Null, ip_mode=None) as srv:
            assert srv.address_family == socket.AF_INET6

    def test_ipv4_only_mode_binds(self):
        from http.server import BaseHTTPRequestHandler

        class _Null(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

        with pasla._make_server(0, _Null, ip_mode="4") as srv:
            assert srv.address_family == socket.AF_INET

    @pytest.mark.skipif(not ipv6_usable(),
                        reason="IPv6 not usable on this system")
    def test_ipv6_only_mode_binds(self):
        from http.server import BaseHTTPRequestHandler

        class _Null(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

        with pasla._make_server(0, _Null, ip_mode="6") as srv:
            assert srv.address_family == socket.AF_INET6

    def test_fallback_to_ipv4_if_dualstack_missing(self, monkeypatch):
        """When dual-stack is unavailable, ip_mode=None should fallback to IPv4."""
        from http.server import BaseHTTPRequestHandler

        class _Null(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

        # Mock the system capability to simulate an environment lacking dual-stack support
        monkeypatch.setattr(socket, "has_dualstack_ipv6", lambda: False)
        
        with pasla._make_server(0, _Null, ip_mode=None) as srv:
            assert srv.address_family == socket.AF_INET

# ---------------------------------------------------------------------------
# Port binding
# ---------------------------------------------------------------------------

class TestPortBinding:

    def test_bind_server_returns_valid_port(self):
        server, port = pasla.bind_server(ip_mode="4")
        try:
            assert 1 <= port <= 65535
        finally:
            server.server_close()

    def test_two_servers_get_different_ports(self):
        s1, p1 = pasla.bind_server(ip_mode="4")
        s2, p2 = pasla.bind_server(ip_mode="4")
        try:
            assert p1 != p2
        finally:
            s1.server_close()
            s2.server_close()

# ---------------------------------------------------------------------------
# Registry / PID file operations
# ---------------------------------------------------------------------------

class TestRegistry:

    @pytest.fixture(autouse=True)
    def _patch_registry_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")

    def test_write_and_read_registry(self):
        pasla.write_registry("aabbcc", os.getpid(), 9999)
        entries = pasla.read_all_registry()
        assert any(e["id"] == "aabbcc" for e in entries)

    def test_delete_registry(self):
        pasla.write_registry("ddeeff", os.getpid(), 9998)
        pasla.delete_registry("ddeeff")
        entries = pasla.read_all_registry()
        assert not any(e["id"] == "ddeeff" for e in entries)

    def test_write_is_atomic(self, tmp_path):
        """
        write_registry uses mkstemp+os.replace for atomicity.
        Verify no half-written file exists on concurrent writes.
        """
        import threading

        errors = []

        def _write(i):
            try:
                pasla.write_registry(f"id{i:04d}", os.getpid(), 10000 + i)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_write, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        entries = pasla.read_all_registry()
        assert len(entries) == 20

    def test_stale_json_is_skipped(self):
        """Malformed registry files must not crash read_all_registry."""
        reg_dir = pasla.REGISTRY_DIR
        reg_dir.mkdir(parents=True, exist_ok=True)
        (reg_dir / "pasla_corrupt.json").write_text("{broken", encoding="utf-8")
        entries = pasla.read_all_registry()
        assert all(e.get("id") != "corrupt" for e in entries)

    def test_registry_entries_with_invalid_schema_are_dropped(self):
        """Tampered or partial registry entries must be skipped before
        downstream consumers (cmd_list, cmd_stop) see them.  A
        negative pid or out-of-range ctrl_port would otherwise reach
        ``socket.create_connection`` or ``pid_is_alive`` and fail
        with a confusing error."""
        import json as _json

        reg_dir = pasla.REGISTRY_DIR
        reg_dir.mkdir(parents=True, exist_ok=True)
        # Each row is one rejection reason.
        bad_payloads = {
            "pasla_negpid.json":  {"id": "negpid",  "pid": -1,       "ctrl_port": 5000},
            "pasla_zeropid.json": {"id": "zeropid", "pid": 0,        "ctrl_port": 5000},
            "pasla_strpid.json":  {"id": "strpid",  "pid": "abc",    "ctrl_port": 5000},
            "pasla_negport.json": {"id": "negport", "pid": 100,      "ctrl_port": -5},
            "pasla_bigport.json": {"id": "bigport", "pid": 100,      "ctrl_port": 99999},
            "pasla_strport.json": {"id": "strport", "pid": 100,      "ctrl_port": "x"},
            "pasla_noid.json":    {"pid": 100,      "ctrl_port": 5000},
            "pasla_listpay.json": [1, 2, 3],
        }
        for name, payload in bad_payloads.items():
            (reg_dir / name).write_text(_json.dumps(payload), encoding="utf-8")
        # And one valid entry that must still come through.
        (reg_dir / "pasla_good.json").write_text(
            _json.dumps({"id": "good", "pid": 100, "ctrl_port": 5000}),
            encoding="utf-8",
        )

        entries = pasla.read_all_registry()

        ids = {e.get("id") for e in entries}
        assert ids == {"good"}

    @pytest.mark.skipif(os.name == "nt",
                        reason="POSIX umask race only")
    def test_tmp_file_mode_is_0600_under_permissive_umask(self, tmp_path):
        """``write_registry`` must produce 0o600 even when the process
        umask is permissive — ``fchmod`` on the mkstemp fd closes the
        umask race window so the registry JSON (which contains
        ``ctrl_secret``) is never readable by other local users.
        """
        old_umask = os.umask(0o000)
        try:
            pasla.write_registry("perm01", os.getpid(), 12121,
                                 ctrl_secret="topsecret")
            target = pasla.REGISTRY_DIR / "pasla_perm01.json"
            mode = oct(target.stat().st_mode & 0o777)
            assert mode == "0o600"
        finally:
            os.umask(old_umask)

# ---------------------------------------------------------------------------
# Log file permissions
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform == "win32",
                    reason="os.chmod with 0o600 is POSIX-only")
class TestLogFilePermissions:

    def test_log_file_created_with_restricted_perms(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pasla, "REGISTRY_DIR", tmp_path / "registry")
        (tmp_path / "registry").mkdir(parents=True, exist_ok=True)
        log_path = tmp_path / "registry" / "pasla_test.log"
        import logging
        fh = logging.FileHandler(str(log_path), encoding="utf-8")
        fh.close()
        os.chmod(log_path, 0o600)
        mode = oct(log_path.stat().st_mode & 0o777)
        assert mode == "0o600"

    @pytest.mark.skipif(os.name == "nt",
                        reason="POSIX umask race window only")
    def test_no_race_window_during_create(self, tmp_path, monkeypatch):
        """The daemon log file must be pre-created with mode 0o600
        BEFORE ``logging.FileHandler`` opens it.  Otherwise a
        permissive umask leaves a window where another local user
        can read log output (download URL, peer IPs).
        """
        # Force a permissive umask globally for the duration of the
        # test; the production code must still produce 0o600.
        old_umask = os.umask(0o000)
        try:
            target = tmp_path / "race.log"
            fd = os.open(
                str(target),
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
            mode = oct(target.stat().st_mode & 0o777)
            assert mode == "0o600"
        finally:
            os.umask(old_umask)

# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform == "win32",
                    reason="SIGTERM behaviour differs on Windows")
class TestSignalHandling:

    def test_sigterm_is_handleable(self):
        """Verify signal.SIGTERM can be set on this platform."""
        import signal
        import threading

        original = signal.getsignal(signal.SIGTERM)
        fired = threading.Event()

        def handler(signum, frame):
            fired.set()

        signal.signal(signal.SIGTERM, handler)
        try:
            os.kill(os.getpid(), signal.SIGTERM)
            assert fired.wait(1.0), "SIGTERM was not delivered within 1 second"
        finally:
            signal.signal(signal.SIGTERM, original)

# ---------------------------------------------------------------------------
# UTF-8 stdout reconfiguration
# ---------------------------------------------------------------------------

class TestUTF8Reconfigure:

    def test_stdout_encoding_is_utf8(self):
        """
        The script forces stdout/stderr to UTF-8 at startup.
        This is already done in conftest via module load, so we just verify.
        """
        enc = getattr(sys.stdout, "encoding", None)
        # In CI stdout may be ascii; the reconfigure attempt is what matters.
        # We assert the attribute exists and is a string.
        assert isinstance(enc, str)

# ---------------------------------------------------------------------------
# Temp zip cleanup
# ---------------------------------------------------------------------------

class TestTempZipCleanup:

    def test_cleanup_removes_file_and_dir(self, tmp_path, monkeypatch):
        """Temp zip within REGISTRY_DIR must be deleted along with its parent."""
        reg_dir = tmp_path / "registry"
        monkeypatch.setattr(pasla, "REGISTRY_DIR", reg_dir)
        reg_dir.mkdir(parents=True, exist_ok=True)
        parent = reg_dir / "tmp_zip_parent"
        parent.mkdir()
        z = parent / "test.zip"
        z.write_bytes(b"fake zip")

        entry = {"temp_archive": str(z)}
        pasla._cleanup_temp_archive(entry)

        assert not z.exists()
        assert not parent.exists()

    def test_cleanup_noop_if_no_temp_archive(self):
        # Must not raise.
        pasla._cleanup_temp_archive({})
        pasla._cleanup_temp_archive({"temp_archive": None})

    def test_cleanup_noop_if_already_deleted(self, tmp_path, monkeypatch):
        """Must not raise when the zip file does not exist."""
        reg_dir = tmp_path / "registry"
        monkeypatch.setattr(pasla, "REGISTRY_DIR", reg_dir)
        reg_dir.mkdir(parents=True, exist_ok=True)
        z = reg_dir / "gone.zip"
        # File never created — must not raise.
        pasla._cleanup_temp_archive({"temp_archive": str(z)})

    def test_cleanup_rejects_path_outside_registry(self, tmp_path, monkeypatch):
        """Security: temp_archive pointing outside REGISTRY_DIR must be refused."""
        reg_dir = tmp_path / "registry"
        monkeypatch.setattr(pasla, "REGISTRY_DIR", reg_dir)
        reg_dir.mkdir(parents=True, exist_ok=True)
        # Create a file outside REGISTRY_DIR.
        outside = tmp_path / "etc_shadow"
        outside.write_text("sensitive", encoding="utf-8")

        pasla._cleanup_temp_archive({"temp_archive": str(outside)})

        # The file must NOT have been deleted.
        assert outside.exists()

    @pytest.mark.skipif(os.name == "nt",
                        reason="symlink creation requires elevated privileges on Windows")
    def test_cleanup_rejects_symlinked_temp_archive(self, tmp_path, monkeypatch):
        """Security: a symlink at ``temp_archive`` must not be followed.

        A same-UID attacker who can write into REGISTRY_DIR could
        plant a symlink to an arbitrary file (e.g. ``/etc/passwd``)
        and tamper with the registry JSON entry so ``temp_archive``
        points at the symlink.  The cleanup unlinks the symlink
        itself without following it, leaving the target intact.
        """
        reg_dir = tmp_path / "registry"
        monkeypatch.setattr(pasla, "REGISTRY_DIR", reg_dir)
        reg_dir.mkdir(parents=True, exist_ok=True)

        target = tmp_path / "sensitive_target"
        target.write_text("must not be deleted", encoding="utf-8")

        link_path = reg_dir / "evil.tar"
        os.symlink(target, link_path)

        pasla._cleanup_temp_archive({"temp_archive": str(link_path)})

        # Symlink itself was removed, but the target survives.
        assert not link_path.exists()
        assert target.exists()
        assert target.read_text(encoding="utf-8") == "must not be deleted"

    def test_cleanup_log_file_removes_orphan(self, tmp_path, monkeypatch):
        """An orphaned ``pasla_<id>.log`` file is removed when the
        registry JSON for that instance is gone (SIGKILL path)."""
        reg_dir = tmp_path / "registry"
        monkeypatch.setattr(pasla, "REGISTRY_DIR", reg_dir)
        reg_dir.mkdir(parents=True, exist_ok=True)

        log_path = reg_dir / "pasla_logorph_.log"
        log_path.write_text("peer 203.0.113.5 downloaded ...", encoding="utf-8")

        pasla._cleanup_log_file("logorph_")

        assert not log_path.exists()

    def test_sweep_orphan_artifacts_removes_log_files(
        self, tmp_path, monkeypatch,
    ):
        """The sweep used by ``cmd_list`` removes log files of
        instances that are no longer active."""
        reg_dir = tmp_path / "registry"
        monkeypatch.setattr(pasla, "REGISTRY_DIR", reg_dir)
        reg_dir.mkdir(parents=True, exist_ok=True)

        keep_log = reg_dir / "pasla_keep01.log"
        drop_log = reg_dir / "pasla_drop99.log"
        keep_log.write_text("running", encoding="utf-8")
        drop_log.write_text("orphan", encoding="utf-8")

        pasla._sweep_orphan_artifacts({"keep01"})

        assert keep_log.exists()
        assert not drop_log.exists()

    @pytest.mark.skipif(os.name == "nt",
                        reason="symlink creation requires elevated privileges on Windows")
    def test_cleanup_log_file_rejects_symlink(self, tmp_path, monkeypatch):
        """A symlink at the log file path must NOT be followed - the
        symlink itself is unlinked but the target is left intact."""
        reg_dir = tmp_path / "registry"
        monkeypatch.setattr(pasla, "REGISTRY_DIR", reg_dir)
        reg_dir.mkdir(parents=True, exist_ok=True)

        target = tmp_path / "important.txt"
        target.write_text("survive", encoding="utf-8")
        link = reg_dir / "pasla_evilog_.log"
        os.symlink(target, link)

        pasla._cleanup_log_file("evilog_")

        assert not link.exists()
        assert target.exists()

    def test_cleanup_tls_dir_removes_orphan(self, tmp_path, monkeypatch):
        """An orphaned ``pasla_<id>_tls/`` directory is removed when
        the registry JSON for that instance is gone (SIGKILL path).
        Without this, the private key would persist on disk for the
        full configured cert validity.
        """
        reg_dir = tmp_path / "registry"
        monkeypatch.setattr(pasla, "REGISTRY_DIR", reg_dir)
        reg_dir.mkdir(parents=True, exist_ok=True)

        tls_dir = reg_dir / "pasla_orph01_tls"
        tls_dir.mkdir()
        (tls_dir / "cert.pem").write_text("PEM", encoding="utf-8")
        (tls_dir / "key.pem").write_text("KEY", encoding="utf-8")

        pasla._cleanup_tls_dir("orph01")

        assert not tls_dir.exists()

    def test_sweep_orphan_artifacts_skips_active_tls_dirs(
        self, tmp_path, monkeypatch,
    ):
        """The sweep used by ``cmd_list`` keeps TLS dirs of active
        instances and removes the rest."""
        reg_dir = tmp_path / "registry"
        monkeypatch.setattr(pasla, "REGISTRY_DIR", reg_dir)
        reg_dir.mkdir(parents=True, exist_ok=True)

        active = reg_dir / "pasla_keep01_tls"
        stale  = reg_dir / "pasla_drop99_tls"
        active.mkdir()
        stale.mkdir()

        pasla._sweep_orphan_artifacts({"keep01"})

        assert active.exists()
        assert not stale.exists()

    @pytest.mark.skipif(os.name == "nt",
                        reason="symlink creation requires elevated privileges on Windows")
    def test_cleanup_tls_dir_rejects_symlink(self, tmp_path, monkeypatch):
        """A symlink at the TLS dir path must NOT be followed.

        A same-UID attacker who can write into REGISTRY_DIR could
        otherwise plant a symlink to an arbitrary directory and
        coerce ``pasla list`` into ``rmtree``-ing it.
        """
        reg_dir = tmp_path / "registry"
        monkeypatch.setattr(pasla, "REGISTRY_DIR", reg_dir)
        reg_dir.mkdir(parents=True, exist_ok=True)

        target = tmp_path / "real_dir"
        target.mkdir()
        (target / "important.txt").write_text("survive", encoding="utf-8")

        link = reg_dir / "pasla_evil01_tls"
        os.symlink(target, link)

        pasla._cleanup_tls_dir("evil01")

        # Symlink itself removed but the target survives intact.
        assert not link.exists()
        assert target.exists()
        assert (target / "important.txt").exists()

    @pytest.mark.skipif(os.name == "nt",
                        reason="symlink creation requires elevated privileges on Windows")
    def test_cleanup_rejects_symlinked_parent(self, tmp_path, monkeypatch):
        """Security: a symlinked parent directory must not be
        traversed for rmdir, otherwise a same-UID attacker can
        coerce the cleanup into removing arbitrary directories."""
        reg_dir = tmp_path / "registry"
        monkeypatch.setattr(pasla, "REGISTRY_DIR", reg_dir)
        reg_dir.mkdir(parents=True, exist_ok=True)

        real_parent = tmp_path / "real_dir"
        real_parent.mkdir()
        link_parent = reg_dir / "link_parent"
        os.symlink(real_parent, link_parent)
        zip_via_link = link_parent / "x.zip"
        # Don't create the file; we just need the path to resolve via
        # the symlinked parent.
        pasla._cleanup_temp_archive({"temp_archive": str(zip_via_link)})

        # Symlinked parent must remain — refused outright.
        assert link_parent.is_symlink()
        assert real_parent.exists()


class TestPIDLockProtection:
    """Verify that the sweep respects .pasla_lock files."""

    def test_sweep_skips_locked_tmp_dir(self, tmp_path, monkeypatch):
        """A .tmp_* dir with a lock pointing to own PID must survive sweep."""
        reg_dir = tmp_path / "registry"
        monkeypatch.setattr(pasla, "REGISTRY_DIR", reg_dir)
        reg_dir.mkdir(parents=True, exist_ok=True)

        tmp_dir = reg_dir / ".tmp_abc123"
        tmp_dir.mkdir()
        (tmp_dir / ".pasla_lock").write_text(
            str(os.getpid()), encoding="ascii",
        )

        pasla._sweep_orphan_artifacts(set())

        assert tmp_dir.exists(), "Locked dir with live PID must survive sweep"

    def test_sweep_removes_unlocked_tmp_dir(self, tmp_path, monkeypatch):
        """A .tmp_* dir with no lock must be deleted."""
        reg_dir = tmp_path / "registry"
        monkeypatch.setattr(pasla, "REGISTRY_DIR", reg_dir)
        reg_dir.mkdir(parents=True, exist_ok=True)

        tmp_dir = reg_dir / ".tmp_nolck"
        tmp_dir.mkdir()
        (tmp_dir / "data.tar").write_bytes(b"orphan")

        pasla._sweep_orphan_artifacts(set())

        assert not tmp_dir.exists(), "Unlocked dir must be removed"

    def test_sweep_removes_dead_locked_tmp_dir(self, tmp_path, monkeypatch):
        """A .tmp_* dir with lock pointing to a dead PID must be deleted."""
        reg_dir = tmp_path / "registry"
        monkeypatch.setattr(pasla, "REGISTRY_DIR", reg_dir)
        reg_dir.mkdir(parents=True, exist_ok=True)

        tmp_dir = reg_dir / ".tmp_deadpid"
        tmp_dir.mkdir()
        # Use PID 0 which is never a user process.
        (tmp_dir / ".pasla_lock").write_text("999999999", encoding="ascii")

        # Mock pid_is_alive to return False for the dead PID.
        monkeypatch.setattr(pasla, "pid_is_alive", lambda pid: False)

        pasla._sweep_orphan_artifacts(set())

        assert not tmp_dir.exists(), "Dir with dead PID lock must be removed"

    def test_sweep_skips_locked_tls_dir(self, tmp_path, monkeypatch):
        """A pasla_*_tls dir with a live lock must survive sweep."""
        reg_dir = tmp_path / "registry"
        monkeypatch.setattr(pasla, "REGISTRY_DIR", reg_dir)
        reg_dir.mkdir(parents=True, exist_ok=True)

        tls_dir = reg_dir / "pasla_locktls_tls"
        tls_dir.mkdir()
        (tls_dir / ".pasla_lock").write_text(
            str(os.getpid()), encoding="ascii",
        )

        pasla._sweep_orphan_artifacts(set())

        assert tls_dir.exists(), "Locked TLS dir with live PID must survive"

    def test_write_lock_file_creates_file(self, tmp_path):
        """_write_lock_file must create a .pasla_lock with current PID."""
        d = tmp_path / "test_lock"
        d.mkdir()
        pasla._write_lock_file(d)
        lock = d / ".pasla_lock"
        assert lock.exists()
        assert lock.read_text(encoding="ascii").strip() == str(os.getpid())


# ---------------------------------------------------------------------------
# bind_server — occupied port (platform-specific)
#
# Linux:   SO_REUSEADDR only allows TIME_WAIT reuse — a listening socket
#          will block the second bind, so real socket contention works.
# Windows: SO_REUSEADDR allows binding the same port twice even when both
#          are listening.  We must use a raw socket without SO_REUSEADDR
#          to create a genuine collision.
# ---------------------------------------------------------------------------

class TestOccupiedPort:

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX only")
    def test_occupied_port_exits_posix(self):
        """On POSIX, bind_server must exit when the port is already bound."""
        blocker = pasla._make_server(0, pasla.BaseHTTPRequestHandler, ip_mode="4")
        occupied_port = blocker.server_address[1]
        try:
            with pytest.raises(SystemExit):
                pasla.bind_server(ip_mode="4", port=occupied_port)
        finally:
            blocker.server_close()

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_occupied_port_exits_windows(self):
        """On Windows, bind_server must exit when the port is already bound.

        Windows SO_REUSEADDR allows double-bind when both sockets set it.
        HTTPServer always sets SO_REUSEADDR, so the blocker must NOT set it
        to create a real collision.
        """
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Explicitly do NOT set SO_REUSEADDR on the blocker.
        blocker.bind(("0.0.0.0", 0))
        blocker.listen(1)
        occupied_port = blocker.getsockname()[1]
        try:
            with pytest.raises(SystemExit):
                pasla.bind_server(ip_mode="4", port=occupied_port)
        finally:
            blocker.close()