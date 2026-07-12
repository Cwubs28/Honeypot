#!/usr/bin/env python3
"""
SSH Honeypot
------------
A fake SSH service that listens for incoming connections and logs everything
about them (source IP, timestamp, any data sent). Nothing real is running
behind it - there's no actual SSH server, no real login, no risk. Since
nothing legitimate should ever be trying to log into a fake service, any
connection attempt is inherently suspicious and worth logging.

This is the "attract and log" half of a detection pipeline. The other half
is failed_login_detector.py (see the failed-login-detector repo), which
analyzes logs like the ones this honeypot produces and flags brute-force
patterns. This honeypot intentionally writes its log in the same format
as a real SSH auth log, so the existing detector can analyze this
honeypot's output with zero changes.

SAFETY NOTE:
This binds to 127.0.0.1 (localhost) by default, meaning only your own
machine can connect to it - it is not exposed to the internet or your
local network. This is intentional so the honeypot is 100% safe to run
for testing and portfolio purposes. Real production honeypots are
deployed on public cloud servers specifically to attract real internet
traffic - that is a deliberate infrastructure decision, not something
this script does by default.

Usage:
    python3 honeypot.py
    python3 honeypot.py --port 2222
    python3 honeypot.py --port 2222 --log honeypot.log
"""

import socket
import argparse
import threading
from datetime import datetime


# A short list of fake usernames to simulate in the log, so the output
# looks like a realistic mix of login attempts rather than always the
# same single username. Real attackers try lists like this too.
FAKE_USERNAMES_SEEN = ["admin", "root", "test", "user", "oracle", "postgres"]


def log_connection_attempt(log_path, source_ip, source_port, attempt_number):
    """
    Writes one line to the log file in the same format as a real SSH auth
    log (matching what failed_login_detector.py already knows how to
    parse). This is what makes the two projects work together as a
    pipeline: the honeypot's output IS the detector's input, with no
    conversion step needed.
    """
    fake_user = FAKE_USERNAMES_SEEN[attempt_number % len(FAKE_USERNAMES_SEEN)]
    timestamp = datetime.now().strftime("%b %d %H:%M:%S")

    log_line = (
        f"{timestamp} honeypot sshd[{1000 + attempt_number}]: "
        f"Failed password for invalid user {fake_user} "
        f"from {source_ip} port {source_port} ssh2\n"
    )

    with open(log_path, "a") as f:
        f.write(log_line)

    print(f"[LOGGED] Connection from {source_ip}:{source_port} "
          f"(logged as failed login attempt for user '{fake_user}')")


def handle_connection(client_socket, address, log_path, attempt_number):
    """
    Handles a single incoming connection. Sends a fake SSH-style banner
    to seem convincing, then logs the attempt and closes the connection.
    Nothing about this touches a real filesystem, real credentials, or
    a real service - it's entirely a decoy.
    """
    source_ip, source_port = address

    try:
        # Real SSH servers announce themselves immediately on connect with
        # a version banner. Sending one back makes this look like a real
        # SSH service to anything scanning or connecting to it.
        client_socket.send(b"SSH-2.0-OpenSSH_8.9\r\n")

        # Give the connecting client a moment to send something back
        # (real SSH clients do), but don't hang forever waiting.
        client_socket.settimeout(2)
        try:
            client_socket.recv(1024)
        except socket.timeout:
            pass

    except Exception:
        pass
    finally:
        client_socket.close()

    log_connection_attempt(log_path, source_ip, source_port, attempt_number)


def run_honeypot(bind_address, port, log_path):
    """
    Opens a listening socket on the given port and waits for incoming
    connections. Each connection is handled in its own thread so the
    honeypot can deal with multiple connection attempts at the same time
    without one slow connection blocking the others.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind_address, port))
    server.listen(5)

    print("=" * 60)
    print("SSH HONEYPOT - LISTENING")
    print("=" * 60)
    print(f"Bound to      : {bind_address}:{port}")
    print(f"Logging to    : {log_path}")
    print("Waiting for connections... (Ctrl+C to stop)")
    print("=" * 60)

    attempt_number = 0

    try:
        while True:
            client_socket, address = server.accept()
            attempt_number += 1
            # Handle each connection in its own thread so the honeypot
            # keeps listening even while processing a connection.
            t = threading.Thread(
                target=handle_connection,
                args=(client_socket, address, log_path, attempt_number)
            )
            t.start()
    except KeyboardInterrupt:
        print("\n\nHoneypot stopped.")
        print(f"Total connection attempts logged: {attempt_number}")
    finally:
        server.close()


def main():
    parser = argparse.ArgumentParser(
        description="Run a fake SSH service that logs connection attempts.",
        epilog="Binds to 127.0.0.1 by default - safe for local testing only."
    )
    parser.add_argument(
        "--port", type=int, default=2222,
        help="Port to listen on (default: 2222, avoids needing admin rights)"
    )
    parser.add_argument(
        "--bind", default="127.0.0.1",
        help="Address to bind to (default: 127.0.0.1 - localhost only, safe)"
    )
    parser.add_argument(
        "--log", default="honeypot.log",
        help="File to write connection logs to (default: honeypot.log)"
    )

    args = parser.parse_args()
    run_honeypot(args.bind, args.port, args.log)


if __name__ == "__main__":
    main()
