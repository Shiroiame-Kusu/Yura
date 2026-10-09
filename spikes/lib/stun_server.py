#!/usr/bin/env python3
"""A minimal STUN server (RFC 5389) for the acceptance network.

Answers binding requests with XOR-MAPPED-ADDRESS — the address it saw the request come
from — and records every query. That is what lets the harness prove *which* path a NAT test
measured: a server reachable only inside a network namespace can only be answering the
traffic that went through the exit into it, and the address it reports is the address that
exit gives a game.

Optionally advertises a second address with --other, which is what a client needs before it
can ask to be answered from somewhere else, and then ignores the asking: a server that names a
second address and never answers from it, which a client must not take for a NAT filtering.

With --alternate it is the server RFC 5780 describes instead. It listens on its two addresses
and two ports, names the other in OTHER-ADDRESS, and honours CHANGE-REQUEST by answering from
the socket asked for. That is what tells a NAT2 from a NAT3, so the harness puts a firewall
that filters like one or the other in front of the client and checks which it is called.

Runs unprivileged. Never needs root.
"""

from __future__ import annotations

import argparse
import json
import select
import socket
import struct
import sys
import threading
import time

MAGIC = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
ATTR_MAPPED = 0x0001
ATTR_CHANGE_REQUEST = 0x0003
ATTR_XOR_MAPPED = 0x0020
ATTR_SOFTWARE = 0x8022
ATTR_RESPONSE_ORIGIN = 0x802B
ATTR_OTHER_ADDRESS = 0x802C


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


def attribute(kind: int, value: bytes) -> bytes:
    padding = (-len(value)) % 4
    return struct.pack("!HH", kind, len(value)) + value + bytes(padding)


def address_value(host: str, port: int) -> bytes:
    return struct.pack("!BBH", 0, 0x01, port) + socket.inet_aton(host)


def xor_address_value(host: str, port: int) -> bytes:
    raw = socket.inet_aton(host)
    xored = bytes(b ^ m for b, m in zip(raw, struct.pack("!I", MAGIC)))
    return struct.pack("!BBH", 0, 0x01, port ^ (MAGIC >> 16)) + xored


def parse_change_request(body: bytes) -> int:
    offset = 0
    change = 0
    while offset + 4 <= len(body):
        kind, length = struct.unpack("!HH", body[offset:offset + 4])
        value = body[offset + 4:offset + 4 + length]
        if kind == ATTR_CHANGE_REQUEST and length == 4:
            change = struct.unpack("!I", value)[0]
        offset += 4 + length + ((-length) % 4)
    return change


def endpoint(text: str) -> tuple[str, int]:
    host, _, port = text.rpartition(":")
    return host, int(port)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", required=True)
    parser.add_argument("--port", type=int, default=3478)
    parser.add_argument(
        "--other",
        metavar="ADDR:PORT",
        help="Advertise this as the server's second address (OTHER-ADDRESS), and never answer from it.",
    )
    parser.add_argument(
        "--alternate",
        metavar="ADDR:PORT",
        help="Listen on this second address and port too, advertise it, and honour CHANGE-REQUEST.",
    )
    parser.add_argument("--software", default="yura-acceptance-stun")
    parser.add_argument("--log", required=True)
    args = parser.parse_args()

    audit = AuditLog(args.log)
    primary = (args.listen, args.port)
    alternate = endpoint(args.alternate) if args.alternate else None
    advertised = alternate or (endpoint(args.other) if args.other else None)

    # The primary socket always; with --alternate, the other three combinations of the two
    # addresses and two ports, which is where CHANGE-REQUEST answers come from.
    wanted = [primary]
    if alternate is not None:
        wanted += [(args.listen, alternate[1]), (alternate[0], args.port), alternate]
    sockets = {}
    for address in wanted:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(address)
        sockets[address] = sock
    print("stun on " + ", ".join(f"{h}:{p}" for h, p in sockets), flush=True)

    while True:
        readable, _, _ = select.select(list(sockets.values()), [], [])
        for sock in readable:
            local = sock.getsockname()
            try:
                data, client = sock.recvfrom(2048)
            except OSError as exc:
                audit.record(event="receive_failed", error=str(exc))
                continue

            if len(data) < 20:
                continue

            kind, length, magic = struct.unpack("!HHI", data[:8])
            transaction = data[8:20]
            if magic != MAGIC or kind != BINDING_REQUEST or 20 + length > len(data):
                audit.record(event="not_stun", client=f"{client[0]}:{client[1]}", bytes=len(data))
                continue

            change = parse_change_request(data[20:20 + length])
            audit.record(
                event="binding",
                client=f"{client[0]}:{client[1]}",
                change=change,
                listen=f"{local[0]}:{local[1]}",
            )

            # Without --alternate, a request to be answered from elsewhere is acknowledged in the
            # log and then ignored, which is what a server without a working second address does.
            if change and alternate is None:
                audit.record(event="change_ignored", client=f"{client[0]}:{client[1]}", change=change)
                continue

            source = local
            if change:
                host, port = local
                if change & 0x04:
                    host = alternate[0] if host == args.listen else args.listen
                if change & 0x02:
                    port = alternate[1] if port == args.port else args.port
                source = (host, port)

            body = attribute(ATTR_XOR_MAPPED, xor_address_value(client[0], client[1]))
            body += attribute(ATTR_MAPPED, address_value(client[0], client[1]))
            body += attribute(ATTR_SOFTWARE, args.software.encode("utf-8"))
            if advertised is not None:
                body += attribute(ATTR_OTHER_ADDRESS, address_value(advertised[0], advertised[1]))
            if alternate is not None:
                body += attribute(ATTR_RESPONSE_ORIGIN, address_value(source[0], source[1]))

            reply = struct.pack("!HHI", BINDING_SUCCESS, len(body), MAGIC) + transaction + body
            try:
                sockets[source].sendto(reply, client)
            except OSError as exc:
                audit.record(event="send_failed", client=f"{client[0]}:{client[1]}", error=str(exc))
                continue

            if source != local:
                audit.record(
                    event="answered_from",
                    client=f"{client[0]}:{client[1]}",
                    change=change,
                    source=f"{source[0]}:{source[1]}",
                )

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
