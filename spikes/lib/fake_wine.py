#!/usr/bin/env python3
"""Stands in for Wine where it matters to routing: which process creates a program's sockets.

Wine opens every socket a Windows program asks for inside the wineserver of the program's
prefix, and hands the program a copy over a unix socket. The socket belongs to the wineserver,
and so does its cgroup, which the kernel fixes when the socket is created. A rule that places
only the program therefore routes none of what it sends.

Run through private copies of the interpreter named wineserver and wine64-preloader, with
WINEPREFIX set, the two roles here look to Yura exactly like a prefix's server and a Windows
program in it, and their sockets are made the way Wine makes them.

  server:  fake_wine.py server --socket PATH
  client:  fake_wine.py client --socket PATH --tcp-target HOST:PORT --out FILE [--wine-target X.exe]

The client records each attempt as spike_client.py does, so logquery.py reads both alike.
Runs unprivileged.
"""

from __future__ import annotations

import argparse
import array
import collections
import json
import os
import socket
import sys
import time


def serve(path: str) -> int:
    if os.path.exists(path):
        os.unlink(path)

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(16)
    print(f"fake wineserver pid {os.getpid()} on {path}, prefix {os.environ.get('WINEPREFIX')}", flush=True)
    # Wine keeps its own copy of a socket for as long as the program's handle to it is open, so a
    # flow is as likely to be found in the server as in the program. The last few stand in for that;
    # one pushed out of the backlog is closed.
    held: collections.deque[socket.socket] = collections.deque(maxlen=64)
    while True:
        conn, _ = listener.accept()
        with conn:
            if not conn.recv(64):
                continue
            # Created here, in the server: this is the line that decides the socket's cgroup.
            made = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.sendmsg([b"ok"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [made.fileno()]))])
            held.append(made)


def ask_for_socket(path: str) -> socket.socket:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.connect(path)
        conn.sendall(b"tcp\n")
        fds = array.array("i")
        _, ancillary, _, _ = conn.recvmsg(16, socket.CMSG_SPACE(fds.itemsize))
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds.frombytes(data[: len(data) - (len(data) % fds.itemsize)])
        if not fds:
            raise OSError("the server sent no socket")
        return socket.socket(fileno=fds[0])


def attempt(path: str, target: tuple[str, int], timeout: float) -> tuple[bool, str]:
    try:
        with ask_for_socket(path) as sock:
            sock.settimeout(timeout)
            sock.connect(target)
            sock.sendall(f"GET / HTTP/1.1\r\nHost: {target[0]}\r\nConnection: close\r\n\r\n".encode())
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            _, _, payload = b"".join(chunks).decode("latin-1", "replace").partition("\r\n\r\n")
            return True, payload.strip()
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"


def run_client(args: argparse.Namespace) -> int:
    host, _, port = args.tcp_target.rpartition(":")
    target = (host, int(port))
    with open(args.out, "w", encoding="utf-8", buffering=1) as out:
        def record(**fields: object) -> None:
            fields["ts"] = time.time()
            out.write(json.dumps(fields, sort_keys=True) + "\n")

        record(event="start", pid=os.getpid())
        record(event="label", label=args.label, wine_target=args.wine_target)
        while True:
            ok, detail = attempt(args.socket, target, args.timeout)
            record(event="tcp", ok=ok, detail=detail, target=args.tcp_target)
            time.sleep(args.interval)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("role", choices=["server", "client"])
    parser.add_argument("--socket", required=True)
    parser.add_argument("--tcp-target")
    parser.add_argument("--out")
    parser.add_argument("--label", default="wine")
    parser.add_argument("--wine-target", help="A Windows executable to carry in argv, as a Wine process does.")
    parser.add_argument("--interval", type=float, default=0.4)
    parser.add_argument("--timeout", type=float, default=1.5)
    args = parser.parse_args()

    if args.role == "server":
        return serve(args.socket)
    if not args.tcp_target or not args.out:
        parser.error("a client needs --tcp-target and --out")
    return run_client(args)


if __name__ == "__main__":
    sys.exit(main())
