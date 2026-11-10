# Copyright (C) 2007 Giampaolo Rodola' <g.rodola@gmail.com>.
# Use of this source code is governed by a MIT license that can be
# found in the LICENSE file.

"""Security tests for the two-phased RNFR/RNTO (rename) command pair.

A rename is split in two commands: RNFR marks the source path and RNTO
provides the destination. The pending source is session state, so these
tests make sure that:

* a RNFR which fails (missing path, home directory, denied permission)
  does not leave a stale source a later RNTO could still act on;
* a RNTO which fails clears the pending source, so it cannot be retried
  against a different destination;
* USER (account switch) and REIN invalidate the pending rename, so the
  source path can never survive a cross-account login;
* the "f" (rename) permission is checked on *both* the source and the
  destination, never on just one end.

Every test asserts both the protocol reply code and the final state of
the filesystem, so that a reply rejecting the command while the file was
actually moved (or vice versa) is caught.

The FTP command channel is driven directly in-process over a
``socket.socketpair()`` instead of binding a listening port, so the
whole suite runs locally without opening any network socket.
"""

import os
import shutil
import socket
import tempfile
from unittest.mock import patch

import pytest

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.filesystems import AbstractedFS
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.ioloop import IOLoop

from . import POSIX
from . import PyftpdlibTestCase


class RecordingAuthorizer(DummyAuthorizer):
    """DummyAuthorizer recording every has_perm() query.

    Each recorded entry is a ``(permission, real_path)`` tuple, allowing
    tests to prove which end of a rename (source vs. destination) was
    authorized instead of only observing the final reply.
    """

    def __init__(self):
        super().__init__()
        self.perm_calls = []

    def has_perm(self, username, perm, path=None):
        self.perm_calls.append((perm, path))
        return super().has_perm(username, perm, path)


class _FakeServer:
    """Minimal stand-in for FTPServer: only ip_map is touched when the
    command channel is closed (see FTPHandler.close())."""

    def __init__(self):
        self.ip_map = []


class TestRenameSecurity(PyftpdlibTestCase):
    """In-process command-dispatch tests for RNFR/RNTO state handling."""

    # Full permissions; individual tests narrow them through the
    # recording authorizer / override_perm().
    base_perm = "elradfmwMT"

    def setUp(self):
        super().setUp()
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="pyftpd-rnfr-"))
        self.addCleanup(self._cleanup_root)
        self._loops = []
        self._sockets = []
        self._handlers = []

    def _cleanup_root(self):
        for handler in self._handlers:
            if not getattr(handler, "_closed", False):
                handler.close()
        for loop in self._loops:
            loop.close()
        for sock in self._sockets:
            sock.close()
        shutil.rmtree(self.root, ignore_errors=True)

    def make_homes(self, *names):
        """Create independent home directories and return their paths."""
        homes = {}
        for name in names:
            path = os.path.join(self.root, name)
            os.mkdir(path)
            homes[name] = path
        return homes

    def make_authorizer(self, users):
        """Build a RecordingAuthorizer.

        ``users`` maps username -> (password, home, permission string).
        """
        authorizer = RecordingAuthorizer()
        for username, (password, home, perm) in users.items():
            authorizer.add_user(username, password, home, perm=perm)
        return authorizer

    def connect(self, authorizer, home, username="user", password="pwd"):
        """Create a handler bound to a socketpair and log the user in.

        Returns the handler; the handler is closed automatically during
        tearDown().
        """
        class Handler(FTPHandler):
            pass

        Handler.authorizer = authorizer
        # Make the deferred 530 callback of a failed login fire as soon
        # as the scheduler is pumped.
        Handler.auth_failed_timeout = 0.0

        client_sock, server_sock = socket.socketpair()
        self._sockets.extend((client_sock, server_sock))
        with patch.object(
            socket.socket,
            "getpeername",
            return_value=("127.0.0.1", 12345),
        ):
            loop = IOLoop.factory()
            handler = Handler(
                server_sock, _FakeServer(), ioloop=loop
            )
        self._loops.append(loop)
        self._handlers.append(handler)

        self.dispatch(handler, "USER", username)
        self.dispatch(handler, "PASS", password)
        loop.sched.poll()
        assert handler.authenticated
        # PASS built the FS from the authorizer home; make sure it is
        # the directory this test expects.
        assert os.path.realpath(handler.fs.root) == os.path.realpath(home)
        return handler

    def dispatch(self, handler, cmd, arg=""):
        """Dispatch one FTP command and return the raw protocol reply."""
        line = f"{cmd} {arg}".strip()
        handler.pre_process_command(line, cmd, arg)
        return handler._last_response

    def touch(self, home, *parts):
        """Create an empty file under home and return its real path."""
        path = os.path.join(home, *parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w"):
            pass
        return path

    # -- normal, successful rename -----------------------------------

    def test_rename_ok_moves_file_and_clears_state(self):
        home = self.make_homes("home")["home"]
        authorizer = self.make_authorizer(
            {"user": ("pwd", home, self.base_perm)}
        )
        handler = self.connect(authorizer, home)
        source = self.touch(home, "src.txt")
        destination = os.path.join(home, "dst.txt")

        reply = self.dispatch(handler, "RNFR", "src.txt")
        assert reply.startswith("350"), reply
        assert handler._rnfr is not None

        reply = self.dispatch(handler, "RNTO", "dst.txt")
        assert reply.startswith("250"), reply
        # Pending rename is consumed once the sequence completes.
        assert handler._rnfr is None
        # Filesystem really reflects the move.
        assert not os.path.exists(source)
        assert os.path.exists(destination)
        # Both ends were authorized with the rename permission.
        f_checks = [
            path for perm, path in authorizer.perm_calls if perm == "f"
        ]
        assert any(path == source for path in f_checks)
        assert any(path == destination for path in f_checks)

    # -- RNFR followed by USER / REIN --------------------------------

    def test_rnfr_then_rein_invalidates_pending_rename(self):
        home = self.make_homes("home")["home"]
        authorizer = self.make_authorizer(
            {"user": ("pwd", home, self.base_perm)}
        )
        handler = self.connect(authorizer, home)
        source = self.touch(home, "src.txt")

        assert self.dispatch(handler, "RNFR", "src.txt").startswith("350")
        assert handler._rnfr is not None

        reply = self.dispatch(handler, "REIN")
        assert reply.startswith("230"), reply
        # REIN flushes the account and, with it, the pending source.
        assert not handler.authenticated
        assert handler._rnfr is None

        # RNTO is now rejected at the authentication stage; the source
        # file must be untouched.
        reply = self.dispatch(handler, "RNTO", "dst.txt")
        assert reply.startswith("530"), reply
        assert os.path.exists(source)
        assert not os.path.exists(os.path.join(home, "dst.txt"))

    def test_rnfr_then_user_switch_invalidates_pending_rename(self):
        homes = self.make_homes("home1", "home2")
        authorizer = self.make_authorizer(
            {
                "user1": ("pwd1", homes["home1"], self.base_perm),
                "user2": ("pwd2", homes["home2"], self.base_perm),
            }
        )
        handler = self.connect(
            authorizer, homes["home1"], username="user1", password="pwd1"
        )
        source = self.touch(homes["home1"], "src.txt")

        assert self.dispatch(handler, "RNFR", "src.txt").startswith("350")
        # A new USER while authenticated flushes the old account.
        reply = self.dispatch(handler, "USER", "user2")
        assert "flushed" in reply.lower(), reply
        assert not handler.authenticated
        assert handler._rnfr is None

        # Complete the cross-account login.
        self.dispatch(handler, "PASS", "pwd2")
        handler.ioloop.sched.poll()
        assert handler.authenticated
        assert os.path.realpath(handler.fs.root) == os.path.realpath(
            homes["home2"]
        )

        # The old source path from user1 must not be reusable by user2.
        reply = self.dispatch(handler, "RNTO", "dst.txt")
        assert reply.startswith("503"), reply
        # user1's file stayed put and nothing appeared in user2's home.
        assert os.path.exists(source)
        assert os.listdir(homes["home2"]) == []

    def test_rnfr_then_failed_login_does_not_reuse_source(self):
        home = self.make_homes("home")["home"]
        authorizer = self.make_authorizer(
            {"user": ("pwd", home, self.base_perm)}
        )
        handler = self.connect(authorizer, home)
        source = self.touch(home, "src.txt")

        assert self.dispatch(handler, "RNFR", "src.txt").startswith("350")
        # Re-authentication attempt with a wrong password.
        self.dispatch(handler, "USER", "user")
        self.dispatch(handler, "PASS", "wrong-password")
        handler.ioloop.sched.poll()
        assert not handler.authenticated
        # The pending source was flushed together with the account.
        assert handler._rnfr is None

        reply = self.dispatch(handler, "RNTO", "dst.txt")
        assert reply.startswith("530"), reply
        assert os.path.exists(source)

    # -- second RNFR failing -----------------------------------------

    def test_failed_second_rnfr_discards_previous_source(self):
        home = self.make_homes("home")["home"]
        authorizer = self.make_authorizer(
            {"user": ("pwd", home, self.base_perm)}
        )
        handler = self.connect(authorizer, home)
        source = self.touch(home, "src.txt")

        assert self.dispatch(handler, "RNFR", "src.txt").startswith("350")
        # A second RNFR pointing at a missing path must fail and reset
        # the pending source instead of keeping the first one.
        reply = self.dispatch(handler, "RNFR", "missing.txt")
        assert reply.startswith("550"), reply
        assert handler._rnfr is None

        # RNTO must now report the bad sequence and never move the file.
        reply = self.dispatch(handler, "RNTO", "dst.txt")
        assert reply.startswith("503"), reply
        assert os.path.exists(source)
        assert not os.path.exists(os.path.join(home, "dst.txt"))

    def test_rnfr_on_home_directory_clears_pending_source(self):
        home = self.make_homes("home")["home"]
        authorizer = self.make_authorizer(
            {"user": ("pwd", home, self.base_perm)}
        )
        handler = self.connect(authorizer, home)
        source = self.touch(home, "src.txt")

        assert self.dispatch(handler, "RNFR", "src.txt").startswith("350")
        reply = self.dispatch(handler, "RNFR", "/")
        assert "home directory" in reply.lower(), reply
        assert handler._rnfr is None

        reply = self.dispatch(handler, "RNTO", "dst.txt")
        assert reply.startswith("503"), reply
        assert os.path.exists(source)

    def test_permission_denied_rnfr_clears_pending_source(self):
        home = self.make_homes("home")["home"]
        authorizer = self.make_authorizer(
            {"user": ("pwd", home, self.base_perm)}
        )
        handler = self.connect(authorizer, home)
        source = self.touch(home, "src.txt")
        assert self.dispatch(handler, "RNFR", "src.txt").startswith("350")

        # Drop the rename permission; the next RNFR is rejected before
        # ftp_RNFR() even runs.
        authorizer.user_table["user"]["perm"] = "elradwmMT"
        reply = self.dispatch(handler, "RNFR", "src.txt")
        assert reply.startswith("550"), reply
        assert handler._rnfr is None
        authorizer.user_table["user"]["perm"] = self.base_perm

        # With permissions restored the standalone RNTO still fails
        # because no source is pending, proving the state (not the
        # permission) is what got cleared.
        reply = self.dispatch(handler, "RNTO", "dst.txt")
        assert reply.startswith("503"), reply
        assert os.path.exists(source)

    # -- RNTO failing -------------------------------------------------

    def test_failed_rnto_clears_pending_source(self):
        home = self.make_homes("home")["home"]
        authorizer = self.make_authorizer(
            {"user": ("pwd", home, self.base_perm)}
        )
        handler = self.connect(authorizer, home)
        source = self.touch(home, "src.txt")

        assert self.dispatch(handler, "RNFR", "src.txt").startswith("350")
        # Destination lives in a non-existing directory -> os.rename
        # fails, and the pending source must be consumed by the failure.
        reply = self.dispatch(handler, "RNTO", "no-such-dir/dst.txt")
        assert reply.startswith("550"), reply
        assert handler._rnfr is None

        # Re-issuing RNTO must not resurrect the old source.
        reply = self.dispatch(handler, "RNTO", "dst.txt")
        assert reply.startswith("503"), reply
        assert os.path.exists(source)
        assert not os.path.exists(os.path.join(home, "dst.txt"))

    @pytest.mark.skipif(not POSIX, reason="POSIX symlink semantics only")
    def test_rnto_escaping_root_clears_pending_source(self):
        home = self.make_homes("home")["home"]
        outside = os.path.join(self.root, "outside")
        os.mkdir(outside)
        # A symlink inside the home pointing outside of it.
        os.symlink(outside, os.path.join(home, "link"))
        authorizer = self.make_authorizer(
            {"user": ("pwd", home, self.base_perm)}
        )
        handler = self.connect(authorizer, home)
        source = self.touch(home, "src.txt")

        assert self.dispatch(handler, "RNFR", "src.txt").startswith("350")
        # validpath() resolves the symlink and rejects the destination
        # before the rename filesystem call is attempted.
        reply = self.dispatch(handler, "RNTO", "link/escape.txt")
        assert reply.startswith("550"), reply
        assert "outside" in reply.lower() or "root directory" in reply.lower()
        assert handler._rnfr is None

        reply = self.dispatch(handler, "RNTO", "dst.txt")
        assert reply.startswith("503"), reply
        assert os.path.exists(source)
        assert os.listdir(outside) == []

    def test_permission_denied_rnto_clears_pending_source(self):
        home = self.make_homes("home")["home"]
        source_dir = os.path.join(home, "src")
        dest_dir = os.path.join(home, "dst")
        os.mkdir(source_dir)
        os.mkdir(dest_dir)
        authorizer = self.make_authorizer(
            {"user": ("pwd", home, self.base_perm)}
        )
        # Destination directory denies the rename permission.
        authorizer.override_perm("user", dest_dir, perm="elradwmMT")
        handler = self.connect(authorizer, home)
        source = self.touch(home, "src", "file.txt")

        assert self.dispatch(
            handler, "RNFR", "src/file.txt"
        ).startswith("350")
        reply = self.dispatch(handler, "RNTO", "dst/file.txt")
        assert reply.startswith("550"), reply
        # The pre-dispatch denial still invalidates the pending source.
        assert handler._rnfr is None

        reply = self.dispatch(handler, "RNTO", "other.txt")
        assert reply.startswith("503"), reply
        assert os.path.exists(source)
        assert os.listdir(dest_dir) == []

    # -- source vs. destination permission checks --------------------

    def test_rename_checked_on_both_source_and_destination(self):
        home = self.make_homes("home")["home"]
        source_dir = os.path.join(home, "src")
        dest_dir = os.path.join(home, "dst")
        os.mkdir(source_dir)
        os.mkdir(dest_dir)
        authorizer = self.make_authorizer(
            {"user": ("pwd", home, self.base_perm)}
        )
        # Only the destination loses the rename permission.
        authorizer.override_perm("user", dest_dir, perm="elradwmMT")
        handler = self.connect(authorizer, home)
        source = self.touch(home, "src", "file.txt")
        destination = os.path.join(dest_dir, "file.txt")

        assert self.dispatch(
            handler, "RNFR", "src/file.txt"
        ).startswith("350")
        reply = self.dispatch(handler, "RNTO", "dst/file.txt")
        assert reply.startswith("550"), reply

        # The recording authorizer proves the "f" permission was queried
        # for both ends, each against its own real path.
        f_checks = [
            path for perm, path in authorizer.perm_calls if perm == "f"
        ]
        assert source in f_checks
        assert destination in f_checks
        # Reply rejected the move, so the filesystem must be unchanged.
        assert os.path.exists(source)
        assert not os.path.exists(destination)

    def test_rename_denied_when_source_lacks_permission(self):
        home = self.make_homes("home")["home"]
        source_dir = os.path.join(home, "src")
        os.mkdir(source_dir)
        authorizer = self.make_authorizer(
            {"user": ("pwd", home, self.base_perm)}
        )
        # Source directory denies the rename permission.
        authorizer.override_perm("user", source_dir, perm="elradwmMT")
        handler = self.connect(authorizer, home)
        source = self.touch(home, "src", "file.txt")

        reply = self.dispatch(handler, "RNFR", "src/file.txt")
        assert reply.startswith("550"), reply
        assert handler._rnfr is None
        # No pending source means a standalone RNTO cannot move anything.
        reply = self.dispatch(handler, "RNTO", "file.txt")
        assert reply.startswith("503"), reply
        assert os.path.exists(source)
        assert not os.path.exists(os.path.join(home, "file.txt"))
