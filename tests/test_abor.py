# Copyright (C) 2007 Giampaolo Rodola' <g.rodola@gmail.com>.
# Use of this source code is governed by MIT license that can be
# found in the LICENSE file.

"""Deterministic tests for ABOR interleaved with STOR/RETR transfers.

The event orderings around transfer start, partial send/receive, EOF
and ABOR are exercised without relying on network timing: client and
server share the two ends of a socketpair() and the server IOLoop is
stepped manually, so each test decides precisely which event (command,
data chunk, EOF, disconnect) is processed next. Files are a few KB at
most; no test waits for a "big" transfer to complete in order to create
a race window.

Every scenario checks the full control-channel reply sequence, the
exact number/order of on_file_* / on_incomplete_file_* callbacks and
the ownership of file handles (an aborted transfer must neither leak
its own handle nor close or hijack the handle of the next transfer) --
not just that "the connection ends up closed".

Leftover-file convention pinned down here (pre-existing pyftpdlib
behavior): when an upload (STOR) is aborted, the partially received
file is left on disk; the server never deletes it. The
on_incomplete_file_received() callback is the application hook for
cleaning it up. When the control connection is dropped instead of
using ABOR, pending files are closed silently (no callback).
"""

import os
import socket

import pytest

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.filesystems import AbstractedFS
from pyftpdlib.handlers import DTPHandler
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.ioloop import Select

from . import HOME
from . import PASSWD
from . import USER
from . import PyftpdlibTestCase

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "socketpair"), reason="socketpair() not available"
)

PASV_REPLY = "227 Entering passive mode (127,0,0,1,192,1)."
QUEUED_REPLY = "150 File status okay. About to open data connection."
REUSE_REPLY = "125 Data connection already open. Transfer starting."
ABOR_IDLE_REPLY = "225 No transfer to abort."
NOOP_REPLY = "200 I successfully did nothing'."
ABOR_OK_REPLY = "225 ABOR command successful; data channel closed."
ABOR_426_REPLY = "426 Transfer aborted via ABOR."
ABOR_226_REPLY = "226 ABOR command successful."
COMPLETE_REPLY = "226 Transfer complete."


class FakeTCPSocket:
    """Wraps one end of a socketpair() pretending it is a TCP socket,
    so that the FTP handlers can be driven without binding real ports.
    """

    def __init__(
        self, sock, peer=("127.0.0.1", 5000), local=("127.0.0.1", 21)
    ):
        self._sock = sock
        self._peer = peer
        self._local = local

    def getpeername(self):
        return self._peer

    def getsockname(self):
        return self._local

    def __getattr__(self, name):
        return getattr(self._sock, name)


class FakePassiveDTP:
    """Stand-in for PassiveDTP which does not bind() a real socket.

    It sends the 227 reply immediately; the test then "connects" the
    data channel by hand via FtpSession.data_connect().
    """

    def __init__(self, cmd_channel, extmode=False):
        self.cmd_channel = cmd_channel
        self.closed = False
        cmd_channel.respond(PASV_REPLY)

    def close(self):
        self.closed = True


class DummyFTPServer:
    """The minimal subset of the FTPServer API used by FTPHandler."""

    def __init__(self):
        self.ip_map = []

    def _accept_new_data_cons(self):
        return True


class FtpSession:
    """A logged-in FTP session driven by manually stepping the IOLoop.

    - (list) events: (callback-name, file-basename) tuples, in order.
    - (dict) handles: {absolute-path: [file objects opened by the server]}.
    """

    def __init__(self, homedir):
        self.events = []
        self.handles = {}
        self.ioloop = Select()
        session = self

        class RecordingFS(AbstractedFS):
            def open(self, filename, mode):
                fd = super().open(filename, mode)
                key = os.path.abspath(filename)
                session.handles.setdefault(key, []).append(fd)
                return fd

        class TestDTPHandler(DTPHandler):
            timeout = 0
            # small buffer => fine-grained, controlled send scheduling
            ac_out_buffer_size = 1024

        class TestFTPHandler(FTPHandler):
            abstracted_fs = RecordingFS
            dtp_handler = TestDTPHandler
            passive_dtp = FakePassiveDTP
            timeout = 0
            use_sendfile = False

            def on_disconnect(self):
                session.events.append(("disconnect",))

            def on_file_received(self, file):
                session.events.append(
                    ("file_received", os.path.basename(file))
                )

            def on_incomplete_file_received(self, file):
                session.events.append(
                    ("incomplete_received", os.path.basename(file))
                )

            def on_file_sent(self, file):
                session.events.append(("file_sent", os.path.basename(file)))

            def on_incomplete_file_sent(self, file):
                session.events.append(
                    ("incomplete_sent", os.path.basename(file))
                )

        authorizer = DummyAuthorizer()
        authorizer.add_user(USER, PASSWD, homedir, perm="elradfmwMT")
        TestFTPHandler.authorizer = authorizer

        self.server = DummyFTPServer()
        ctrl_srv, self.ctrl = socket.socketpair()
        self.handler = TestFTPHandler(
            FakeTCPSocket(ctrl_srv), self.server, ioloop=self.ioloop
        )
        self.handler.handle()  # sends the 220 greeting
        self.data_cli = None
        self._rbuf = b""

    # --- I/O scheduling

    def step(self, times=2):
        """Let the server process pending I/O events."""
        for _ in range(times):
            self.ioloop.loop(0, blocking=False)

    def send_raw(self, data):
        """Send bytes on the control channel without stepping the loop."""
        self.ctrl.sendall(data)

    def cmd(self, line):
        """Send a command and let the server process it."""
        self.send_raw(line.encode("utf-8") + b"\r\n")
        self.step()

    def read_replies(self):
        """Drain the control socket, returning the reply lines so far."""
        self.ctrl.setblocking(False)
        try:
            while True:
                try:
                    chunk = self.ctrl.recv(65536)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                self._rbuf += chunk
        finally:
            self.ctrl.setblocking(True)
        lines = self._rbuf.split(b"\r\n")
        self._rbuf = lines.pop()
        return [line.decode("utf-8") for line in lines]

    # --- data channel

    def data_connect(self):
        """Simulate the client connecting to the passive data port."""
        srv, self.data_cli = socket.socketpair()
        dtp = self.handler.dtp_handler(FakeTCPSocket(srv), self.handler)
        assert dtp.connected
        self.handler.data_channel = dtp
        self.handler._on_dtp_connection()
        return self.data_cli

    def data_send(self, data):
        self.data_cli.sendall(data)
        self.step()

    def data_eof(self):
        self.data_cli.close()
        self.data_cli = None
        self.step()

    def data_recv_all(self):
        """Read until the server closes the data connection."""
        self.data_cli.setblocking(False)
        chunks = []
        try:
            for _ in range(1000):
                self.step()
                try:
                    chunk = self.data_cli.recv(65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
        finally:
            self.data_cli.setblocking(True)
        raise AssertionError("server did not close the data connection")

    def close(self):
        for sock in (self.ctrl, self.data_cli):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        if not self.handler._closed:
            self.handler.close()
        self.step()
        self.ioloop.close()


class TestAborRaceConditions(PyftpdlibTestCase):
    """ABOR interleaved with STOR/RETR at every stage of a transfer."""

    def setUp(self):
        super().setUp()
        self.session = FtpSession(HOME)
        self.addCleanup(self.session.close)
        greeting = self.session.read_replies()
        assert len(greeting) == 1
        assert greeting[0].startswith("220")
        self.login()

    # --- helpers

    def login(self):
        self.session.cmd(f"USER {USER}")
        self.session.cmd(f"PASS {PASSWD}")
        self.session.cmd("TYPE I")
        assert self.session.read_replies() == [
            "331 Username ok, send password.",
            "230 Login successful.",
            "200 Type set to: Binary.",
        ]

    def pasv(self):
        self.session.cmd("PASV")
        assert self.session.read_replies() == [PASV_REPLY]

    def stor(self, name):
        self.session.cmd("STOR " + name)
        assert self.session.read_replies() == [QUEUED_REPLY]

    def retr(self, name):
        self.session.cmd("RETR " + name)
        assert self.session.read_replies() == [QUEUED_REPLY]

    def abor(self):
        self.session.cmd("ABOR")
        return self.session.read_replies()

    def make_file(self, content):
        testfn = self.get_testfn()
        with open(testfn, "wb") as f:
            f.write(content)
        return testfn

    def read_file(self, testfn):
        with open(testfn, "rb") as f:
            return f.read()

    def assert_handles_closed(self, testfn):
        handles = self.session.handles[os.path.abspath(testfn)]
        assert handles, "no handle recorded for %r" % testfn
        for fd in handles:
            assert fd.closed, "leaked handle for %r" % testfn

    # --- ABOR while idle

    def test_abor_idle(self):
        # No PASV/PORT, no transfer command: 225, no callbacks, and the
        # session stays usable.
        assert self.abor() == [ABOR_IDLE_REPLY]
        assert self.session.events == []
        self.session.cmd("NOOP")
        assert self.session.read_replies() == [NOOP_REPLY]

    def test_abor_after_pasv_without_transfer(self):
        # PASV received but no transfer command and no connection yet:
        # the listening data socket is closed, 225 is returned.
        self.pasv()
        acceptor = self.session.handler._dtp_acceptor
        assert self.abor() == [ABOR_OK_REPLY]
        assert acceptor.closed
        assert self.session.handler._dtp_acceptor is None
        assert self.session.events == []
        # the session is still fully usable
        testfn = self.get_testfn()
        self.pasv()
        self.stor(testfn)
        self.session.data_connect()
        self.session.data_send(b"x" * 100)
        self.session.data_eof()
        assert self.session.read_replies() == [COMPLETE_REPLY]
        assert self.session.events == [("file_received", testfn)]

    # --- abort A, then complete B (the regression scenario)

    def test_abor_queued_stor_then_complete_b(self):
        # STOR A was accepted (150) but its data connection was never
        # established when ABOR arrives.
        testfn_a = self.get_testfn()
        testfn_b = self.get_testfn()
        payload_b = b"B" * 3000
        self.pasv()
        self.stor(testfn_a)
        assert self.abor() == [ABOR_OK_REPLY]
        # A was aborted: its handle is closed, the incomplete callback
        # fired exactly once, and the (empty) leftover file is left on
        # disk as per repo convention (the server never deletes it).
        assert self.session.events == [("incomplete_received", testfn_a)]
        self.assert_handles_closed(testfn_a)
        assert self.read_file(testfn_a) == b""
        # B starts right away and must be fully independent.
        self.pasv()
        self.stor(testfn_b)
        self.session.data_connect()
        dtp_b = self.session.handler.data_channel
        assert os.path.abspath(dtp_b.file_obj.name) == os.path.abspath(
            testfn_b
        )
        self.session.data_send(payload_b)
        self.session.data_eof()
        assert self.session.read_replies() == [COMPLETE_REPLY]
        assert self.session.events == [
            ("incomplete_received", testfn_a),
            ("file_received", testfn_b),
        ]
        assert self.read_file(testfn_b) == payload_b
        self.assert_handles_closed(testfn_b)
        assert self.session.handler.data_channel is None

    def test_abor_queued_stor_then_reused_data_connection(self):
        # Same as above, but the client connects the data channel for B
        # *before* issuing STOR B (ftplib transfercmd() order). The
        # aborted A must not be resurrected on the new connection.
        testfn_a = self.get_testfn()
        testfn_b = self.get_testfn()
        payload_b = b"B" * 3000
        self.pasv()
        self.stor(testfn_a)
        assert self.abor() == [ABOR_OK_REPLY]
        assert self.session.events == [("incomplete_received", testfn_a)]
        self.pasv()
        self.session.data_connect()
        # no stale transfer may be attached to the new connection
        assert self.session.handler.data_channel.file_obj is None
        self.session.cmd("STOR " + testfn_b)
        assert self.session.read_replies() == [REUSE_REPLY]
        dtp_b = self.session.handler.data_channel
        assert os.path.abspath(dtp_b.file_obj.name) == os.path.abspath(
            testfn_b
        )
        self.session.data_send(payload_b)
        self.session.data_eof()
        assert self.session.read_replies() == [COMPLETE_REPLY]
        assert self.session.events == [
            ("incomplete_received", testfn_a),
            ("file_received", testfn_b),
        ]
        assert self.read_file(testfn_b) == payload_b
        self.assert_handles_closed(testfn_a)
        self.assert_handles_closed(testfn_b)

    def test_abor_queued_retr_then_complete_b(self):
        # RETR A was accepted (150) but the client aborted before
        # connecting the data channel.
        content_a = b"A" * 3000
        content_b = b"B" * 3000
        testfn_a = self.make_file(content_a)
        testfn_b = self.make_file(content_b)
        self.pasv()
        self.retr(testfn_a)
        assert self.abor() == [ABOR_OK_REPLY]
        assert self.session.events == [("incomplete_sent", testfn_a)]
        self.assert_handles_closed(testfn_a)
        # B starts right away and must be fully independent.
        self.pasv()
        self.retr(testfn_b)
        self.session.data_connect()
        data = self.session.data_recv_all()
        assert self.session.read_replies() == [COMPLETE_REPLY]
        assert data == content_b
        assert self.session.events == [
            ("incomplete_sent", testfn_a),
            ("file_sent", testfn_b),
        ]
        self.assert_handles_closed(testfn_b)

    def test_abor_active_stor_then_complete_b(self):
        # STOR A is in progress (partial data received) when ABOR
        # arrives: 426 then 226, then B runs to completion.
        testfn_a = self.get_testfn()
        testfn_b = self.get_testfn()
        payload_a = b"A" * 1000
        payload_b = b"B" * 3000
        self.pasv()
        self.stor(testfn_a)
        self.session.data_connect()
        dtp_a = self.session.handler.data_channel
        self.session.data_send(payload_a)
        assert self.abor() == [ABOR_426_REPLY, ABOR_226_REPLY]
        assert self.session.events == [("incomplete_received", testfn_a)]
        self.assert_handles_closed(testfn_a)
        # A's leftover partial file is left on disk (repo convention).
        assert self.read_file(testfn_a) == payload_a
        # B starts right away on a brand new data channel.
        self.pasv()
        self.stor(testfn_b)
        self.session.data_connect()
        dtp_b = self.session.handler.data_channel
        assert dtp_b is not dtp_a
        assert os.path.abspath(dtp_b.file_obj.name) == os.path.abspath(
            testfn_b
        )
        self.session.data_send(payload_b)
        self.session.data_eof()
        assert self.session.read_replies() == [COMPLETE_REPLY]
        assert self.session.events == [
            ("incomplete_received", testfn_a),
            ("file_received", testfn_b),
        ]
        assert self.read_file(testfn_b) == payload_b
        self.assert_handles_closed(testfn_b)

    def test_abor_active_retr_then_complete_b(self):
        # RETR A is in progress (partial data sent) when ABOR arrives.
        content_a = b"A" * 3000
        content_b = b"B" * 3000
        testfn_a = self.make_file(content_a)
        testfn_b = self.make_file(content_b)
        self.pasv()
        self.retr(testfn_a)
        self.session.data_connect()
        self.session.step()  # first chunk(s) go out
        assert self.abor() == [ABOR_426_REPLY, ABOR_226_REPLY]
        assert self.session.events == [("incomplete_sent", testfn_a)]
        self.assert_handles_closed(testfn_a)
        # B starts right away and must be fully independent.
        self.pasv()
        self.retr(testfn_b)
        self.session.data_connect()
        data = self.session.data_recv_all()
        assert self.session.read_replies() == [COMPLETE_REPLY]
        assert data == content_b
        assert self.session.events == [
            ("incomplete_sent", testfn_a),
            ("file_sent", testfn_b),
        ]
        self.assert_handles_closed(testfn_b)

    def test_abor_twice(self):
        # The second ABOR finds nothing to abort and must not produce
        # duplicate callbacks.
        testfn_a = self.get_testfn()
        self.pasv()
        self.stor(testfn_a)
        self.session.data_connect()
        self.session.data_send(b"A" * 1000)
        assert self.abor() == [ABOR_426_REPLY, ABOR_226_REPLY]
        assert self.abor() == [ABOR_IDLE_REPLY]
        assert self.session.events == [("incomplete_received", testfn_a)]
        self.assert_handles_closed(testfn_a)

    # --- transfer completion interleaved with ABOR

    def test_stor_eof_then_abor(self):
        # EOF is processed first: the transfer completed (226), so the
        # late ABOR finds nothing to abort.
        testfn_a = self.get_testfn()
        payload_a = b"A" * 3000
        self.pasv()
        self.stor(testfn_a)
        self.session.data_connect()
        self.session.data_send(payload_a)
        self.session.data_eof()
        assert self.session.read_replies() == [COMPLETE_REPLY]
        assert self.abor() == [ABOR_IDLE_REPLY]
        assert self.session.events == [("file_received", testfn_a)]
        assert self.read_file(testfn_a) == payload_a
        self.assert_handles_closed(testfn_a)

    def test_stor_abor_then_late_eof(self):
        # ABOR is processed first (426 + 226); the client then closes
        # the data connection, which the server already closed: no
        # further replies and no further callbacks.
        testfn_a = self.get_testfn()
        self.pasv()
        self.stor(testfn_a)
        self.session.data_connect()
        self.session.data_send(b"A" * 1000)
        assert self.abor() == [ABOR_426_REPLY, ABOR_226_REPLY]
        self.session.data_eof()
        assert self.session.read_replies() == []
        assert self.session.events == [("incomplete_received", testfn_a)]
        self.assert_handles_closed(testfn_a)

    def test_stor_abor_and_eof_in_same_poll(self):
        # ABOR and the data-channel EOF are both pending when the
        # IOLoop polls once. The control channel (registered first) is
        # served first, so the abort wins: 426 + 226, one incomplete
        # callback, and no late 226 from the aborted channel.
        testfn_a = self.get_testfn()
        self.pasv()
        self.stor(testfn_a)
        self.session.data_connect()
        self.session.data_send(b"A" * 1000)
        # stage both events without stepping the loop
        self.session.send_raw(b"ABOR\r\n")
        self.session.data_cli.close()
        self.session.data_cli = None
        self.session.step(1)
        assert self.session.read_replies() == [ABOR_426_REPLY, ABOR_226_REPLY]
        assert self.session.events == [("incomplete_received", testfn_a)]
        self.assert_handles_closed(testfn_a)
        # the session is still usable afterwards
        self.session.cmd("NOOP")
        assert self.session.read_replies() == [NOOP_REPLY]

    # --- data connection dropped (no ABOR)

    def test_retr_data_conn_drop(self):
        # The client drops the data connection while RETR A is in
        # progress: the server detects it on send, replies 426 and
        # fires the incomplete callback; B then completes normally.
        content_a = b"A" * 3000
        content_b = b"B" * 3000
        testfn_a = self.make_file(content_a)
        testfn_b = self.make_file(content_b)
        self.pasv()
        self.retr(testfn_a)
        self.session.data_connect()
        # one 1024-byte chunk (ac_out_buffer_size) went out eagerly
        self.session.data_cli.close()
        self.session.data_cli = None
        self.session.step()
        assert self.session.read_replies() == [
            "426 Transfer aborted; 1024 bytes transmitted."
        ]
        assert self.session.events == [("incomplete_sent", testfn_a)]
        self.assert_handles_closed(testfn_a)
        # B is unaffected
        self.pasv()
        self.retr(testfn_b)
        self.session.data_connect()
        data = self.session.data_recv_all()
        assert self.session.read_replies() == [COMPLETE_REPLY]
        assert data == content_b
        assert self.session.events == [
            ("incomplete_sent", testfn_a),
            ("file_sent", testfn_b),
        ]

    def test_stor_data_conn_drop_is_complete(self):
        # For STOR, closing the data connection *is* the end of the
        # file (FTP semantics): the transfer is complete, not aborted.
        testfn_a = self.get_testfn()
        payload_a = b"A" * 3000
        self.pasv()
        self.stor(testfn_a)
        self.session.data_connect()
        self.session.data_send(payload_a)
        self.session.data_eof()
        assert self.session.read_replies() == [COMPLETE_REPLY]
        assert self.session.events == [("file_received", testfn_a)]
        assert self.read_file(testfn_a) == payload_a

    # --- control connection exit

    def test_control_conn_exit_during_stor(self):
        # The client drops the control connection while STOR A is in
        # progress: the data channel is torn down, the incomplete
        # callback fires once, the handle is closed.
        testfn_a = self.get_testfn()
        payload_a = b"A" * 1000
        self.pasv()
        self.stor(testfn_a)
        self.session.data_connect()
        self.session.data_send(payload_a)
        self.session.ctrl.close()
        self.session.step(3)
        assert self.session.events == [
            ("incomplete_received", testfn_a),
            ("disconnect",),
        ]
        self.assert_handles_closed(testfn_a)
        assert self.read_file(testfn_a) == payload_a
        assert self.session.handler._closed
        assert self.session.ioloop.socket_map == {}

    def test_control_conn_exit_with_queued_stor(self):
        # The client drops the control connection after STOR A was
        # accepted but before the data connection was made. Existing
        # convention: the pending file is closed silently (no
        # callback), the empty leftover file stays on disk.
        testfn_a = self.get_testfn()
        self.pasv()
        self.stor(testfn_a)
        self.session.ctrl.close()
        self.session.step(3)
        assert self.session.events == [("disconnect",)]
        self.assert_handles_closed(testfn_a)
        assert self.read_file(testfn_a) == b""
        assert self.session.handler._closed
        assert self.session.ioloop.socket_map == {}

    def test_quit_during_stor_completes_transfer(self):
        # QUIT while STOR A is in progress: 221 immediately, but the
        # connection stays open until the transfer result (226), then
        # the server closes it (RFC-959).
        testfn_a = self.get_testfn()
        payload_a = b"A" * 3000
        self.pasv()
        self.stor(testfn_a)
        self.session.data_connect()
        self.session.data_send(payload_a[:1000])
        self.session.cmd("QUIT")
        assert self.session.read_replies() == ["221 Goodbye."]
        assert not self.session.handler._closed
        self.session.data_send(payload_a[1000:])
        self.session.data_eof()
        assert self.session.read_replies() == [COMPLETE_REPLY]
        self.session.step()
        assert self.session.events == [
            ("file_received", testfn_a),
            ("disconnect",),
        ]
        assert self.session.handler._closed
        assert self.read_file(testfn_a) == payload_a
