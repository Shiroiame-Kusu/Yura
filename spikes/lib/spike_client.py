#!/usr/bin/env python3
"""An ordinary network application, used as the subject of the routing spike.

Nothing here knows about Yura. It is started normally, as the desktop user, with no
wrapper, no special cgroup and no environment variables — which is the whole point: the
spike must prove that an *already-running, unmodified* process can be re-routed.

Behaviour, once per interval:
  * open a NEW TCP connection to --tcp-target and issue a minimal HTTP GET
  * send a UDP datagram to --udp-target and wait briefly for a reply
  * resolve --dns-query, if given, by speaking DNS to a named resolver

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
import random
import socket
import struct
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


def try_tcp(target: tuple[str, int], timeout: float, host_header: str | None) -> tuple[bool, str]:
    try:
        with socket.create_connection(target, timeout=timeout) as sock:
            sock.settimeout(timeout)
            # The Host header is what a host-name rule matches on when there is no TLS
            # handshake to read an SNI from.
            host = host_header or target[0]
            sock.sendall(
                f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
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


def build_dns_query(name: str) -> bytes:
    """A minimal A query. Written by hand so the socket, and therefore the route, is ours."""
    header = struct.pack("!HHHHHH", random.randint(0, 0xFFFF), 0x0100, 1, 0, 0, 0)
    question = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.split(".")
    ) + b"\x00" + struct.pack("!HH", 1, 1)
    return header + question


def parse_dns_answer(message: bytes) -> str | None:
    """Returns the first A record's address, or None if the answer has none."""
    if len(message) < 12:
        return None
    ancount = struct.unpack("!H", message[6:8])[0]
    if ancount < 1:
        return None

    offset = 12
    # Skip the question name, then qtype and qclass.
    while offset < len(message) and message[offset] != 0:
        if message[offset] & 0xC0 == 0xC0:
            offset += 2
            break
        offset += message[offset] + 1
    else:
        offset += 1
    offset += 4

    for _ in range(ancount):
        if offset >= len(message):
            return None
        if message[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while offset < len(message) and message[offset] != 0:
                offset += message[offset] + 1
            offset += 1
        if offset + 10 > len(message):
            return None
        rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", message[offset:offset + 10])
        offset += 10
        if rtype == 1 and rdlength == 4:
            return socket.inet_ntoa(message[offset:offset + 4])
        offset += rdlength
    return None


def try_dns(name: str, resolver: tuple[str, int], timeout: float) -> tuple[bool, str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(build_dns_query(name), resolver)
        data, _peer = sock.recvfrom(4096)
        address = parse_dns_answer(data)
        return (True, address) if address else (False, "answer carried no A record")
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
    parser.add_argument(
        "--http-host",
        help="Host header to send, so a destination-name rule has a name to match.",
    )
    parser.add_argument(
        "--dns-query",
        metavar="NAME@HOST:PORT",
        help="Resolve NAME against a resolver each interval.",
    )
    parser.add_argument(
        "--wine-target",
        help=(
            "A Windows executable path to carry in argv. Makes /proc look to Yura exactly "
            "like a Wine process running that executable, which is what distinguishes two "
            "games sharing one runtime. Otherwise unused."
        ),
    )
    args = parser.parse_args()

    rec = Recorder(args.out)
    rec.record(event="label", label=args.label, wine_target=args.wine_target)

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

    dns_name: str | None = None
    dns_resolver: tuple[str, int] | None = None
    if args.dns_query:
        dns_name, _, resolver = args.dns_query.partition("@")
        dns_resolver = parse_endpoint(resolver)

    while True:
        ok, detail = try_tcp(tcp_target, args.timeout, args.http_host)
        rec.record(event="tcp", ok=ok, detail=detail, target=args.tcp_target)

        if udp_target is not None:
            ok, detail = try_udp(udp_target, args.timeout)
            rec.record(event="udp", ok=ok, detail=detail, target=args.udp_target)

        if dns_name is not None and dns_resolver is not None:
            ok, detail = try_dns(dns_name, dns_resolver, args.timeout)
            rec.record(event="dns", ok=ok, detail=detail, name=dns_name)

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
            # Reported as "ok" because that is the field assertions read, and a
            # still-open pre-rule connection is precisely the success condition.
            rec.record(event="preexisting_state", ok=alive, alive=alive)

        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
