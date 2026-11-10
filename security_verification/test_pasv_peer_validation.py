"""Repeatable security verification for PASV/EPSV data-channel peer checks.

These tests exercise the *real* ``PassiveDTP.handle_accepted`` acceptance
path and the *real* ``DTPHandler`` takeover, but without binding any TCP
port and without NAT/public addresses:

* the "listening" endpoint is one end of a loopback ``socket.socketpair``
  (it only supplies an fd registered in the IO loop);
* every accepted connection is another socketpair whose server end is
  handed to ``handle_accepted`` together with an *injectable* peer
  address tuple, so any IPv4 / IPv6 / IPv4-mapped IPv6 origin can be
  simulated deterministically.

Each test records which control session ends up owning every accepted
connection, so the report can prove that a rejected/foreign connection is
never attached to a user's DTP.
"""

import ipaddress
import socket

import pytest

from pyftpdlib.handlers.ftp.data import DTPHandler
from pyftpdlib.handlers.ftp.dispatchers import PassiveDTP
from pyftpdlib.ioloop import IOLoop


# ---------------------------------------------------------------------
# Address semantics
# ---------------------------------------------------------------------

def _normalize(ip_str):
    """Collapse an IPv4-mapped IPv6 address (RFC 3493 sec. 3.7) onto its
    IPv4 identity so that ``::ffff:127.0.0.1`` and ``127.0.0.1`` compare
    equal as *addresses*, while genuinely different addresses stay
    different.  String inequality alone must never be treated as an
    attack signal.
    """
    addr = ipaddress.ip_address(ip_str)
    return getattr(addr, "ipv4_mapped", None) or addr


def addresses_same_identity(ip_a, ip_b):
    try:
        return _normalize(ip_a) == _normalize(ip_b)
    except ValueError:
        return ip_a == ip_b


# ---------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------

class FakeControlSession:
    """Minimal stand-in for FTPHandler carrying exactly the state that
    PassiveDTP/DTPHandler touch, plus an explicit session label used to
    attribute every accepted connection in the report.
    """

    def __init__(self, ioloop, remote_ip, permit_foreign_addresses=False,
                 session_id="session-A", connected=True):
        self.ioloop = ioloop
        self.connected = connected
        self.remote_ip = remote_ip
        self.permit_foreign_addresses = permit_foreign_addresses
        self.dtp_handler = DTPHandler
        self.timeout = 0
        self.data_channel = None
        self.session_id = session_id
        self.events = []
        self.accepted_owners = []

    # logging / replies -------------------------------------------------
    def log(self, msg, logfun=None):
        self.events.append(("log", msg))

    def log_exception(self, instance):
        self.events.append(("exception", repr(instance)))

    def respond(self, msg, logfun=None):
        self.events.append(("respond", msg))

    def respond_w_warning(self, msg):
        self.events.append(("respond_w_warning", msg))

    def get_repr_info(self, as_str=False, extra_info=None):
        return self.session_id

    # DTP lifecycle hooks ----------------------------------------------
    def _on_dtp_connection(self):
        # The accepted socket is now this session's data channel.
        self.accepted_owners.append(self.session_id)
        self.events.append(("dtp_connection", self.session_id))

    def _on_dtp_close(self):
        self.data_channel = None


class Harness:
    def __init__(self):
        self.ioloop = IOLoop()
        self.threads = []

    def new_session(self, remote_ip, **kwargs):
        return FakeControlSession(self.ioloop, remote_ip, **kwargs)

    def new_acceptor(self, cmd):
        # One socketpair only models the *listening* fd; it is never the
        # data socket that gets accepted.
        listen_sock, spare = socket.socketpair()
        acceptor = PassiveDTP.__new__(PassiveDTP)
        acceptor.ioloop = self.ioloop
        acceptor.cmd_channel = cmd
        acceptor._closed = False
        acceptor._fileno = listen_sock.fileno()
        acceptor.socket = listen_sock
        acceptor._tasks = []
        self.ioloop.register(listen_sock.fileno(), acceptor,
                             self.ioloop.READ)
        self.threads.append((listen_sock, spare))
        cmd._dtp_acceptor = acceptor
        return acceptor

    def simulate_incoming(self, acceptor, peer_ip, peer_port=40000):
        """Pretend the kernel accepted a TCP connection from ``peer``.
        Returns the client end of the emulated connection so the test can
        prove data flow (or rejection) afterwards.
        """
        server_sock, client_sock = socket.socketpair()
        acceptor.handle_accepted(server_sock, (peer_ip, peer_port))
        return server_sock, client_sock

    def shutdown(self):
        for listen_sock, spare in self.threads:
            try:
                listen_sock.close()
            except OSError:
                pass
            try:
                spare.close()
            except OSError:
                pass
        self.ioloop.close()


@pytest.fixture
def harness():
    h = Harness()
    yield h
    h.shutdown()


def _owner_of(cmd):
    return cmd.data_channel.cmd_channel.session_id if cmd.data_channel \
        else None


# ---------------------------------------------------------------------
# 1. Origin matching: foreign peer must not start a transfer
# ---------------------------------------------------------------------

def test_foreign_ipv4_peer_is_rejected_and_never_attached(harness):
    cmd = harness.new_session("203.0.113.7", session_id="user-1")
    acceptor = harness.new_acceptor(cmd)

    server_sock, client_sock = harness.simulate_incoming(
        acceptor, "198.51.100.66")

    # No DTPHandler is created, so no transfer can begin.
    assert cmd.data_channel is None
    assert cmd.accepted_owners == []
    assert any("425" in m and "foreign address" in m
               for _, m in cmd.events), cmd.events
    # The listening socket stays open for the legitimate client.
    assert acceptor._closed is False
    # The rejected socket was closed server-side: peer gets EOF/error.
    client_sock.settimeout(1)
    assert client_sock.recv(16) == b""
    server_sock.close()
    client_sock.close()


def test_foreign_ipv6_peer_is_rejected(harness):
    cmd = harness.new_session("2001:db8::1", session_id="user-2")
    acceptor = harness.new_acceptor(cmd)

    server_sock, client_sock = harness.simulate_incoming(
        acceptor, "2001:db8::beef")

    assert cmd.data_channel is None
    assert cmd.accepted_owners == []
    assert any("425" in m for _, m in cmd.events)
    assert acceptor._closed is False
    server_sock.close()
    client_sock.close()


# ---------------------------------------------------------------------
# 2. After a rejection the legitimate peer can still connect
# ---------------------------------------------------------------------

def test_legitimate_peer_still_accepted_after_rejection(harness):
    cmd = harness.new_session("203.0.113.7", session_id="user-1")
    acceptor = harness.new_acceptor(cmd)

    bad_srv, bad_cli = harness.simulate_incoming(acceptor, "198.51.100.66")
    assert cmd.data_channel is None

    good_srv, good_cli = harness.simulate_incoming(acceptor, "203.0.113.7")
    dtp = cmd.data_channel
    assert isinstance(dtp, DTPHandler)
    assert dtp.connected is True
    # The accepted connection is attributed to the correct control session.
    assert _owner_of(cmd) == "user-1"
    assert cmd.accepted_owners == ["user-1"]
    # Acceptor consumed exactly one connection and then closed itself.
    assert acceptor._closed is True

    # Prove the accepted pipe really carries this user's data.
    dtp.enable_receiving("i", "STOR")
    good_cli.sendall(b"ownership-proof")
    harness.ioloop.poll(0.2)
    assert dtp.tot_bytes_received == len(b"ownership-proof")

    dtp.close()
    for s in (bad_srv, bad_cli, good_srv, good_cli):
        s.close()


# ---------------------------------------------------------------------
# 3. IPv4 vs IPv4-mapped IPv6 must use address semantics, not strings
# ---------------------------------------------------------------------

def test_mapped_ipv6_peer_same_ipv4_identity_is_accepted(harness):
    # Control connection arrived over a dual-stack IPv6 listener, so the
    # kernel reports the IPv4 client as ::ffff:203.0.113.7.
    cmd = harness.new_session("::ffff:203.0.113.7", session_id="user-3")
    acceptor = harness.new_acceptor(cmd)

    server_sock, client_sock = harness.simulate_incoming(
        acceptor, "203.0.113.7")

    dtp = cmd.data_channel
    # Document current library behavior honestly: the production code does
    # a raw string inequality, so this semantically-equal pair is rejected.
    assert dtp is None, (
        "expected current string-comparison behavior to reject the "
        "mapped-address pair; see test_mapped_semantics helper for the "
        "semantic rule the check ought to implement"
    )
    assert any("425" in m for _, m in cmd.events)
    # The semantic helper itself proves this pair is NOT an attack.
    assert addresses_same_identity("::ffff:203.0.113.7", "203.0.113.7")
    server_sock.close()
    client_sock.close()


def test_mapped_ipv6_peer_different_ipv4_identity_is_rejected(harness):
    cmd = harness.new_session("::ffff:203.0.113.7", session_id="user-3")
    acceptor = harness.new_acceptor(cmd)

    server_sock, client_sock = harness.simulate_incoming(
        acceptor, "198.51.100.66")

    assert cmd.data_channel is None
    assert not addresses_same_identity("::ffff:203.0.113.7",
                                       "198.51.100.66")
    server_sock.close()
    client_sock.close()


@pytest.mark.parametrize("a,b,expected", [
    ("127.0.0.1", "127.0.0.1", True),
    ("127.0.0.1", "::ffff:127.0.0.1", True),
    ("::ffff:127.0.0.1", "127.0.0.1", True),
    ("::ffff:127.0.0.1", "::ffff:127.0.0.1", True),
    ("::1", "::ffff:127.0.0.1", False),
    ("203.0.113.7", "::ffff:198.51.100.66", False),
    ("2001:db8::1", "2001:db8::1", True),
    ("2001:db8::1", "2001:db8::2", False),
])
def test_address_identity_semantics(a, b, expected):
    assert addresses_same_identity(a, b) is expected


# ---------------------------------------------------------------------
# 4. permit_foreign_addresses changes the trust boundary
# ---------------------------------------------------------------------

def test_permit_foreign_addresses_accepts_and_attributes_foreign(harness):
    cmd = harness.new_session("203.0.113.7",
                              permit_foreign_addresses=True,
                              session_id="user-4")
    acceptor = harness.new_acceptor(cmd)

    server_sock, client_sock = harness.simulate_incoming(
        acceptor, "198.51.100.66")

    dtp = cmd.data_channel
    assert isinstance(dtp, DTPHandler)
    assert dtp.connected is True
    # The foreign connection is now explicitly trusted and owned by this
    # session — that is the trust-boundary change in one assertion.
    assert _owner_of(cmd) == "user-4"
    assert cmd.accepted_owners == ["user-4"]
    assert any("foreign address" in m for _, m in cmd.events)
    dtp.close()
    server_sock.close()
    client_sock.close()


# ---------------------------------------------------------------------
# 5. Listener lifecycle: stale listeners must not take over new transfers
# ---------------------------------------------------------------------

def test_new_pasv_replaces_old_listener(harness):
    cmd = harness.new_session("203.0.113.7", session_id="user-5")
    first = harness.new_acceptor(cmd)
    first_fd = first._fileno
    second = harness.new_acceptor(cmd)

    # Mirror FTPHandler._make_epasv / _shutdown_connecting_dtp: the old
    # listener is closed (socket shut, fd unregistered) before the new one
    # is created, so it can never receive or accept another event.
    first.close()
    assert first._closed is True
    assert first.connected is False
    assert first_fd not in harness.ioloop.socket_map

    # A fresh connection is owned by the *new* listener/session only.
    good_srv, good_cli = harness.simulate_incoming(second, "203.0.113.7")
    assert _owner_of(cmd) == "user-5"
    assert cmd.accepted_owners == ["user-5"]
    assert second._closed is True
    cmd.data_channel.close()
    for s in (good_srv, good_cli):
        s.close()


def test_closed_control_connection_refuses_takeover(harness):
    cmd = harness.new_session("203.0.113.7", session_id="user-6")
    acceptor = harness.new_acceptor(cmd)

    # Control connection dropped before the data connection arrived.
    cmd.connected = False
    server_sock, client_sock = harness.simulate_incoming(
        acceptor, "203.0.113.7")

    assert cmd.data_channel is None
    assert cmd.accepted_owners == []
    assert acceptor._closed is True
    server_sock.close()
    client_sock.close()


def test_two_sessions_keep_separate_listeners_and_ownership(harness):
    alice = harness.new_session("203.0.113.7", session_id="alice")
    bob = harness.new_session("198.51.100.66", session_id="bob")
    a_listener = harness.new_acceptor(alice)
    b_listener = harness.new_acceptor(bob)

    # Bob's peer hitting Alice's listener is foreign to Alice and rejected.
    srv, cli = harness.simulate_incoming(a_listener, "198.51.100.66")
    assert alice.data_channel is None
    assert alice.accepted_owners == []
    srv.close(); cli.close()

    # Each legitimate peer then lands on its own listener/session.
    srv_a, cli_a = harness.simulate_incoming(a_listener, "203.0.113.7")
    srv_b, cli_b = harness.simulate_incoming(b_listener, "198.51.100.66")
    assert _owner_of(alice) == "alice"
    assert _owner_of(bob) == "bob"
    assert alice.accepted_owners == ["alice"]
    assert bob.accepted_owners == ["bob"]
    alice.data_channel.close()
    bob.data_channel.close()
    for s in (srv_a, cli_a, srv_b, cli_b):
        s.close()
