#!/usr/bin/env python3
"""An ordinary network application, used as the subject of the routing spike.

Nothing here knows about Yura. It is started normally, as the desktop user, with no
wrapper, no special cgroup and no environment variables — which is the whole point: the
spike must prove that an *already-running, unmodified* process can be re-routed.

Behaviour, once per interval:
  * open a NEW TCP connection to --tcp-target and issue a minimal HTTP GET
  * send a UDP datagram to --udp-target and wait briefly for a reply

Additionally, at startup it opens ONE long-lived TCP connection to --preexisting-target
and keeps it open, re-reading it each interval. That connection exists before any routing
rule is applied and is what the "existing connections" requirement is checked against.

Every attempt is written to a JSONL file with a timestamp, so the harness can correlate
outcomes against the exact moment a rule was applied.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time


def parse_endpoint(text: str) -> tuple[str, int]:
    host, _, port = text.rpartition(":")
    return host, int(port)


class Recorder:
    def __init__(self, path: str) -> None:
        self._handle = open(path, "w", encoding="utf-8", buffering=1)
        self.record(event="start", pid=os.getpid())

    def record(self, **fields: object) -> None:
        fields["ts"] = time.time()
        self._handle.write(json.dumps(fields, sort_keys=True) + "\n")
        self._handle.flush()


def try_tcp(target: tuple[str, int], timeout: float) -> tuple[bool, str]:
    try:
        with socket.create_connection(target, timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(
                f"GET / HTTP/1.1\r\nHost: {target[0]}\r\nConnection: close\r\n\r\n".encode()
            )
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            body = b"".join(chunks).decode("latin-1", "replace")
            _, _, payload = body.partition("\r\n\r\n")
            return True, payload.strip()
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"


def try_udp(target: tuple[str, int], timeout: float) -> tuple[bool, str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(b"YURA-PING", target)
        data, _peer = sock.recvfrom(4096)
        return True, data.decode("latin-1", "replace").strip()
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True, help="Identifies this instance in the log")
    parser.add_argument("--tcp-target", required=True)
    parser.add_argument("--udp-target")
    parser.add_argument("--preexisting-target")
    parser.add_argument("--out", required=True)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--timeout", type=float, default=2.0)
    args = parser.parse_args()

    rec = Recorder(args.out)
    rec.record(event="label", label=args.label)

    # Open the long-lived connection before anything can possibly be routed.
    preexisting: socket.socket | None = None
    if args.preexisting_target:
        target = parse_endpoint(args.preexisting_target)
        try:
            preexisting = socket.create_connection(target, timeout=args.timeout)
            preexisting.settimeout(0.2)
            rec.record(
                event="preexisting_open",
                target=f"{target[0]}:{target[1]}",
                local=":".join(str(p) for p in preexisting.getsockname()),
            )
        except OSError as exc:
            rec.record(event="preexisting_failed", error=str(exc))

    tcp_target = parse_endpoint(args.tcp_target)
    udp_target = parse_endpoint(args.udp_target) if args.udp_target else None

    while True:
        ok, detail = try_tcp(tcp_target, args.timeout)
        rec.record(event="tcp", ok=ok, detail=detail, target=args.tcp_target)

        if udp_target is not None:
            ok, detail = try_udp(udp_target, args.timeout)
            rec.record(event="udp", ok=ok, detail=detail, target=args.udp_target)

        if preexisting is not None:
            try:
                # The marker server holds the connection open; a live socket simply has
                # nothing to read, which is what we assert on.
                preexisting.recv(1)
                alive = False  # peer closed
            except TimeoutError:
                alive = True
            except OSError:
                alive = False
            rec.record(event="preexisting_state", alive=alive)

        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
