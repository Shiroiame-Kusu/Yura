#!/usr/bin/env python3
"""Controlled destination server for the routing spike.

Serves a fixed marker payload over TCP (as a minimal HTTP response) and over UDP.
It binds only to loopback and is reachable *only* through the spike's SOCKS5 proxy,
because the address the clients actually target is routed into a dead-end dummy
interface. Receiving the marker is therefore proof that the flow was proxied.

Every request is written to a JSONL log so the destination side can be cross-checked
against the proxy side independently.

Runs unprivileged. Never needs root.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
import time


class AuditLog:
    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        with open(self._path, "w", encoding="utf-8"):
            pass

    def record(self, **fields: object) -> None:
        fields["ts"] = time.time()
        line = json.dumps(fields, sort_keys=True)
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()


def serve_tcp(host: str, port: int, marker: str, audit: AuditLog) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(64)
    print(f"marker tcp on {host}:{port}", flush=True)

    while True:
        conn, peer = listener.accept()
        threading.Thread(
            target=handle_tcp, args=(conn, peer, marker, audit), daemon=True
        ).start()


def handle_tcp(conn: socket.socket, peer: tuple[str, int], marker: str, audit: AuditLog) -> None:
    try:
        conn.settimeout(5)
        try:
            request = conn.recv(4096).decode("latin-1", "replace")
        except OSError:
            request = ""
        first_line = request.split("\r\n", 1)[0] if request else ""
        audit.record(event="tcp_request", client=f"{peer[0]}:{peer[1]}", request=first_line)

        body = marker.encode()
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Connection: close\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )
        conn.sendall(response)
    except OSError:
        pass
    finally:
        conn.close()


def serve_hold(host: str, port: int, audit: AuditLog) -> None:
    """Accepts connections and holds them open indefinitely.

    This is what the "existing connections" checks connect to before a rule is applied:
    the socket must survive the rule and keep using the route it was created on.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(64)
    print(f"marker hold on {host}:{port}", flush=True)

    held: list[socket.socket] = []
    while True:
        conn, peer = listener.accept()
        audit.record(event="hold_accepted", client=f"{peer[0]}:{peer[1]}")
        held.append(conn)  # deliberately never closed


def serve_udp(host: str, port: int, marker: str, audit: AuditLog) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    print(f"marker udp on {host}:{port}", flush=True)

    while True:
        try:
            data, peer = sock.recvfrom(65535)
        except OSError:
            return
        audit.record(
            event="udp_request",
            client=f"{peer[0]}:{peer[1]}",
            payload=data[:64].decode("latin-1", "replace"),
        )
        try:
            sock.sendto(marker.encode(), peer)
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--tcp-port", type=int, default=18080)
    parser.add_argument("--udp-port", type=int, default=19090)
    parser.add_argument("--hold-port", type=int, default=18081)
    parser.add_argument("--tcp-marker", default="YURA-TCP-PROXIED-OK")
    parser.add_argument("--udp-marker", default="YURA-UDP-PROXIED-OK")
    parser.add_argument("--log", required=True)
    args = parser.parse_args()

    audit = AuditLog(args.log)
    threading.Thread(
        target=serve_udp, args=(args.listen, args.udp_port, args.udp_marker, audit), daemon=True
    ).start()
    threading.Thread(
        target=serve_hold, args=(args.listen, args.hold_port, audit), daemon=True
    ).start()
    serve_tcp(args.listen, args.tcp_port, args.tcp_marker, audit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
