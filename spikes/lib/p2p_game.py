#!/usr/bin/env python3
"""Both ends of a peer-to-peer game's networking, for the acceptance network.

``game`` does what a game does to be reachable: it opens one UDP socket, asks a STUN server
which address its peers will see, and then answers whoever sends to that socket, including
peers it has never sent anything to. ``peer`` is one of those peers. It sends to the address
the game learned and waits for the answer.

Together they answer the question a NAT test against these fixtures cannot: whether a route
lets a stranger in. The STUN server here ignores CHANGE-REQUEST, so filtering is never
measured; a peer at an address the game never contacted getting an answer measures it end to
end, the way a game's own peers would.

Every datagram either side receives is written to a JSONL file. Runs unprivileged. Never needs
root.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import sys
import time

MAGIC = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
ATTR_MAPPED = 0x0001
ATTR_XOR_MAPPED = 0x0020


def parse_endpoint(text: str) -> tuple[str, int]:
    host, _, port = text.rpartition(":")
    return host, int(port)


def show(endpoint: tuple[str, int]) -> str:
    return f"{endpoint[0]}:{endpoint[1]}"


class Recorder:
    def __init__(self, path: str) -> None:
        self._handle = open(path, "w", encoding="utf-8", buffering=1)
        self.record(event="start", pid=os.getpid())

    def record(self, **fields: object) -> None:
        fields["ts"] = time.time()
        self._handle.write(json.dumps(fields, sort_keys=True) + "\n")
        self._handle.flush()


def mapped_address(message: bytes, transaction: bytes) -> tuple[str, int] | None:
    """The address a binding response reports, or None if this is not the answer awaited."""
    if len(message) < 20:
        return None
    kind, length, magic = struct.unpack("!HHI", message[:8])
    if kind != BINDING_SUCCESS or magic != MAGIC or message[8:20] != transaction:
        return None

    found = None
    offset = 20
    end = min(len(message), 20 + length)
    while offset + 4 <= end:
        attr, size = struct.unpack("!HH", message[offset:offset + 4])
        value = message[offset + 4:offset + 4 + size]
        if attr in (ATTR_XOR_MAPPED, ATTR_MAPPED) and size >= 8 and value[1] == 0x01:
            port = struct.unpack("!H", value[2:4])[0]
            raw = value[4:8]
            if attr == ATTR_XOR_MAPPED:
                port ^= MAGIC >> 16
                raw = bytes(b ^ m for b, m in zip(raw, struct.pack("!I", MAGIC)))
            found = (socket.inet_ntoa(raw), port)
            if attr == ATTR_XOR_MAPPED:
                return found
        offset += 4 + size + ((-size) % 4)
    return found


def run_game(args: argparse.Namespace) -> int:
    rec = Recorder(args.log)
    rendezvous = parse_endpoint(args.rendezvous)

    # A socket's cgroup is fixed when it is created, and one created before the rule reached
    # this process is never routed. So each attempt opens a new socket, and the game keeps the
    # first one that gets an answer.
    sock: socket.socket | None = None
    mapped: tuple[str, int] | None = None
    for attempt in range(1, args.attempts + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", 0))
        sock.settimeout(args.timeout)
        transaction = os.urandom(12)
        request = struct.pack("!HHI", BINDING_REQUEST, 0, MAGIC) + transaction
        try:
            sock.sendto(request, rendezvous)
            deadline = time.monotonic() + args.timeout
            while mapped is None and time.monotonic() < deadline:
                sock.settimeout(max(0.01, deadline - time.monotonic()))
                data, sender = sock.recvfrom(2048)
                if sender == rendezvous:
                    mapped = mapped_address(data, transaction)
        except OSError as exc:
            rec.record(event="rendezvous_silent", attempt=attempt, local=show(sock.getsockname()),
                       detail=f"{type(exc).__name__}: {exc}")
        if mapped is not None:
            rec.record(event="mapped", ok=True, mapped=show(mapped), local=show(sock.getsockname()),
                       attempt=attempt)
            print(f"peers are to send to {show(mapped)}", flush=True)
            break
        sock.close()
        sock = None

    if sock is None:
        rec.record(event="rendezvous_failed", ok=False, attempts=args.attempts)
        print(f"no answer from {args.rendezvous} in {args.attempts} attempts", flush=True)
        return 1

    # From here on the game only answers. Whoever sends, it replies to, from the same socket.
    sock.settimeout(None)
    while True:
        data, sender = sock.recvfrom(4096)
        if sender == rendezvous:
            continue  # A late answer to an earlier binding request.
        rec.record(event="peer", ok=True, sender=show(sender), detail=data.decode("latin-1", "replace"))
        try:
            sock.sendto(b"YURA-P2P-ANSWER " + data, sender)
        except OSError as exc:
            rec.record(event="answer_failed", ok=False, sender=show(sender),
                       detail=f"{type(exc).__name__}: {exc}")


def run_peer(args: argparse.Namespace) -> int:
    rec = Recorder(args.log)
    target = parse_endpoint(args.to)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(parse_endpoint(args.bind))
    sock.settimeout(args.interval)
    for attempt in range(1, args.attempts + 1):
        try:
            sock.sendto(args.payload.encode(), target)
            rec.record(event="sent", attempt=attempt, to=args.to)
            data, sender = sock.recvfrom(4096)
        except TimeoutError:
            continue
        except OSError as exc:
            rec.record(event="send_failed", attempt=attempt, detail=f"{type(exc).__name__}: {exc}")
            time.sleep(args.interval)
            continue

        # Recorded whoever it came from: an answer from the wrong address is the failure the
        # harness is looking for, and has to be visible as one.
        rec.record(event="answer", ok=True, sender=show(sender), detail=data.decode("latin-1", "replace"))
        print(f"answered from {show(sender)}", flush=True)
        return 0

    rec.record(event="silence", ok=False, attempts=args.attempts)
    print(f"no answer from {args.to} in {args.attempts} attempts", flush=True)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="role", required=True)

    game = sub.add_parser("game", help="Learn the address peers will see, then answer them")
    game.add_argument("--rendezvous", required=True, metavar="HOST:PORT", help="A STUN server")
    game.add_argument("--log", required=True)
    game.add_argument("--attempts", type=int, default=20)
    game.add_argument("--timeout", type=float, default=1.0)
    game.set_defaults(func=run_game)

    peer = sub.add_parser("peer", help="Send to the game's address and wait for its answer")
    peer.add_argument("--bind", required=True, metavar="ADDR:PORT")
    peer.add_argument("--to", required=True, metavar="HOST:PORT")
    peer.add_argument("--log", required=True)
    peer.add_argument("--payload", default="YURA-P2P-HELLO")
    peer.add_argument("--attempts", type=int, default=10)
    peer.add_argument("--interval", type=float, default=0.5)
    peer.set_defaults(func=run_peer)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
