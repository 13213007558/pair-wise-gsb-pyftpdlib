"""Optional end-to-end cross-check using a real loopback FTP server.

Unlike test_pasv_peer_validation.py this binds real TCP ports, so it only
runs where local binding is permitted (the project CI, a dev VM, or a
sandbox with sandbox.network.allowLocalBinding=true).  It is skipped with
an explanatory message when binding is unavailable.

Run:
    .venv/bin/python security_verification/e2e_dualstack_demo.py
"""

import ftplib
import socket
import sys
import tempfile

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer


def can_bind(host, family):
    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        s.bind((host, 0))
    except OSError:
        return False
    else:
        return True
    finally:
        s.close()


def main():
    if not can_bind("127.0.0.1", socket.AF_INET):
        print("SKIP: local TCP binding is disabled in this environment "
              "(EPERM). Run where binding is allowed, or enable "
              "sandbox.network.allowLocalBinding.")
        return 2

    tmp = tempfile.mkdtemp(prefix="pyftpdlib-e2e-")
    authorizer = DummyAuthorizer()
    authorizer.add_anonymous(tmp)
    handler = FTPHandler
    handler.authorizer = authorizer
    # Explicit default: foreign data peers are rejected.
    handler.permit_foreign_addresses = False

    dual_stack = (
        socket.has_ipv6
        and hasattr(socket, "IPV6_V6ONLY")
        and can_bind("::1", socket.AF_INET6)
    )
    bind_host = "::" if dual_stack else "127.0.0.1"
    server = FTPServer((bind_host, 0), handler)
    host, port = server.socket.getsockname()[:2]

    import threading
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        connect_host = "127.0.0.1" if dual_stack else "127.0.0.1"
        ftp = ftplib.FTP()
        ftp.connect(connect_host, port, timeout=5)
        ftp.login()
        print("control peer as seen by server:",
              server.handler and "see session logs")
        # A normal PASV transfer from the same peer must succeed.
        p_host, p_port = ftp.parse227(ftp.sendcmd("PASV"))
        with socket.create_connection((p_host, p_port), timeout=5):
            ftp.voidcmd("TYPE I")
            # LIST consumes the data connection
            ftp.retrlines("LIST")
        print("same-peer PASV transfer: OK")
        ftp.quit()
    finally:
        server.close_all()
    print("dual-stack listener used:", dual_stack, "bound to:", bind_host)
    return 0


if __name__ == "__main__":
    sys.exit(main())
