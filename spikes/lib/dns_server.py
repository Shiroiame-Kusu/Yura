#!/usr/bin/env python3
"""Minimal DNS responder used to prove name learning end to end.

Answers every A query with one fixed address and logs what was asked. It exists so the
acceptance suite can show that a proxied process's DNS goes through the proxy AND that the
daemon learns the name from the answer, which is what makes host-name rules matchable.

Needs root only because DNS lives on port 53. The processes being routed stay unprivileged.
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import threading
import time


def parse_question(message: bytes) -> tuple[str, int] | None:
    if len(message) < 12:
        return None
    qdcount = struct.unpack("!H", message[4:6])[0]
    if qdcount < 1:
        return None
    offset = 12
    labels = []
    while offset < len(message):
        length = message[offset]
        offset += 1
        if length == 0:
            break
        if offset + length > len(message):
            return None
        labels.append(message[offset:offset + length].decode("ascii", "replace"))
        offset += length
    if offset + 4 > len(message):
        return None
    qtype = struct.unpack("!H", message[offset:offset + 2])[0]
    return ".".join(labels), qtype


def build_answer(query: bytes, question_end: int, address: str, ttl: int) -> bytes:
    header = bytearray(query[:12])
    header[2] = 0x81  # QR=1, RD=1
    header[3] = 0x80  # RA=1
    header[6:8] = struct.pack("!H", 1)  # ancount
    header[8:12] = b"\x00\x00\x00\x00"  # nscount, arcount
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + socket.inet_aton(address)
    return bytes(header) + query[12:question_end] + answer


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--answer", required=True, help="A record returned for every query")
    parser.add_argument("--ttl", type=int, default=300)
    parser.add_argument("--log", required=True)
    args = parser.parse_args()

    with open(args.log, "w", encoding="utf-8"):
        pass
    lock = threading.Lock()

    def record(**fields: object) -> None:
        fields["ts"] = time.time()
        with lock, open(args.log, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(fields, sort_keys=True) + "\n")
            handle.flush()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.listen, args.port))
    print(f"dns on {args.listen}:{args.port} -> {args.answer}", flush=True)

    while True:
        try:
            data, peer = sock.recvfrom(4096)
        except OSError:
            return 0
        question = parse_question(data)
        if question is None:
            continue
        name, qtype = question
        record(event="query", name=name, qtype=qtype, client=f"{peer[0]}:{peer[1]}")
        # The question section ends 4 bytes after the final label.
        end = 12 + sum(len(label) + 1 for label in name.split(".")) + 1 + 4
        try:
            sock.sendto(build_answer(data, end, args.answer, args.ttl), peer)
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
