#!/usr/bin/env python3
"""Instrumented SOCKS5 server used as the controlled proxy in the routing spike.

This stands in for the user-supplied proxy. It is deliberately not a general purpose
proxy: it exists so the spike can prove, from the proxy's own side, that a particular
flow really traversed it.

Two independent pieces of evidence come out of this process:

  1. A JSONL audit log of every CONNECT and UDP ASSOCIATE, with the requested target
     and the client source port.
  2. A destination rewrite: requests for the unroutable spike target are answered by
     dialling a local marker server instead. Traffic that did not go through this proxy
     therefore cannot possibly receive the marker payload.

Runs unprivileged. Never needs root.
"""

from __future__ import annotations

import argparse
import json
import selectors
import socket
import struct
import sys
import threading
import time
from typing import Optional

AUTH_NONE = 0x00
AUTH_USERPASS = 0x02
AUTH_UNACCEPTABLE = 0xFF

CMD_CONNECT = 0x01
CMD_UDP_ASSOCIATE = 0x03

ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_CONNECTION_REFUSED = 0x05
REP_CMD_NOT_SUPPORTED = 0x07


class AuditLog:
    """Append-only JSONL log. Flushed on every record so the shell can tail it."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()
        # Truncate on start: each spike run gets a clean log.
        with open(self._path, "w", encoding="utf-8"):
            pass

    def record(self, **fields: object) -> None:
        fields["ts"] = time.time()
        line = json.dumps(fields, sort_keys=True)
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()


def read_exactly(sock: socket.socket, count: int) -> bytes:
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ConnectionError(f"peer closed after {len(buf)} of {count} bytes")
        buf += chunk
    return buf


def read_address(sock: socket.socket) -> tuple[str, int]:
    atyp = read_exactly(sock, 1)[0]
    if atyp == ATYP_IPV4:
        host = socket.inet_ntop(socket.AF_INET, read_exactly(sock, 4))
    elif atyp == ATYP_IPV6:
        host = socket.inet_ntop(socket.AF_INET6, read_exactly(sock, 16))
    elif atyp == ATYP_DOMAIN:
        length = read_exactly(sock, 1)[0]
        host = read_exactly(sock, length).decode("idna")
    else:
        raise ValueError(f"unsupported address type {atyp:#x}")
    port = struct.unpack("!H", read_exactly(sock, 2))[0]
    return host, port


def encode_address(host: str, port: int) -> bytes:
    try:
        packed = socket.inet_pton(socket.AF_INET, host)
        return bytes([ATYP_IPV4]) + packed + struct.pack("!H", port)
    except OSError:
        pass
    try:
        packed = socket.inet_pton(socket.AF_INET6, host)
        return bytes([ATYP_IPV6]) + packed + struct.pack("!H", port)
    except OSError:
        pass
    raw = host.encode("idna")
    return bytes([ATYP_DOMAIN, len(raw)]) + raw + struct.pack("!H", port)


class Socks5Server:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.audit = AuditLog(args.log)
        self.rewrites: dict[tuple[str, int], tuple[str, int]] = {}
        for spec in args.rewrite or []:
            # Format: from_host:from_port=to_host:to_port
            src, _, dst = spec.partition("=")
            sh, _, sp = src.rpartition(":")
            dh, _, dp = dst.rpartition(":")
            self.rewrites[(sh, int(sp))] = (dh, int(dp))

    def resolve_target(self, host: str, port: int) -> tuple[str, int]:
        return self.rewrites.get((host, port), (host, port))

    # -- handshake ---------------------------------------------------------

    def handshake(self, sock: socket.socket) -> bool:
        version, nmethods = struct.unpack("!BB", read_exactly(sock, 2))
        if version != 0x05:
            return False
        methods = set(read_exactly(sock, nmethods))

        if self.args.username:
            if AUTH_USERPASS not in methods:
                sock.sendall(struct.pack("!BB", 0x05, AUTH_UNACCEPTABLE))
                return False
            sock.sendall(struct.pack("!BB", 0x05, AUTH_USERPASS))
            ver = read_exactly(sock, 1)[0]
            if ver != 0x01:
                return False
            ulen = read_exactly(sock, 1)[0]
            user = read_exactly(sock, ulen).decode()
            plen = read_exactly(sock, 1)[0]
            password = read_exactly(sock, plen).decode()
            ok = user == self.args.username and password == self.args.password
            sock.sendall(struct.pack("!BB", 0x01, 0x00 if ok else 0x01))
            return ok

        if AUTH_NONE not in methods:
            sock.sendall(struct.pack("!BB", 0x05, AUTH_UNACCEPTABLE))
            return False
        sock.sendall(struct.pack("!BB", 0x05, AUTH_NONE))
        return True

    def reply(self, sock: socket.socket, code: int, host: str = "0.0.0.0", port: int = 0) -> None:
        sock.sendall(bytes([0x05, code, 0x00]) + encode_address(host, port))

    # -- commands ----------------------------------------------------------

    def handle(self, sock: socket.socket, peer: tuple[str, int]) -> None:
        udp_relay: Optional[UdpRelay] = None
        try:
            if not self.handshake(sock):
                self.audit.record(event="handshake_failed", client=f"{peer[0]}:{peer[1]}")
                return

            version, cmd, _reserved = struct.unpack("!BBB", read_exactly(sock, 3))
            if version != 0x05:
                return
            host, port = read_address(sock)

            if cmd == CMD_CONNECT:
                self.do_connect(sock, peer, host, port)
            elif cmd == CMD_UDP_ASSOCIATE:
                udp_relay = self.do_udp_associate(sock, peer)
            else:
                self.audit.record(
                    event="unsupported_command", client=f"{peer[0]}:{peer[1]}", cmd=cmd
                )
                self.reply(sock, REP_CMD_NOT_SUPPORTED)
        except (ConnectionError, OSError, ValueError, struct.error) as exc:
            self.audit.record(event="session_error", client=f"{peer[0]}:{peer[1]}", error=str(exc))
        finally:
            if udp_relay is not None:
                udp_relay.stop()
            sock.close()

    def do_connect(self, sock: socket.socket, peer: tuple[str, int], host: str, port: int) -> None:
        target = self.resolve_target(host, port)
        rewritten = target != (host, port)
        self.audit.record(
            event="connect",
            client=f"{peer[0]}:{peer[1]}",
            requested=f"{host}:{port}",
            dialled=f"{target[0]}:{target[1]}",
            rewritten=rewritten,
        )

        if self.args.answer_first:
            # Success before anything was dialled, as some proxies (mihomo) answer.
            self.reply(sock, REP_SUCCESS)

        try:
            upstream = socket.create_connection(target, timeout=5)
        except OSError as exc:
            self.audit.record(event="connect_failed", requested=f"{host}:{port}", error=str(exc))
            if not self.args.answer_first:
                # Refused is a reply of its own, as RFC 1928 has it and Dante sends it: the
                # destination answered, where every other failure is the network's.
                refused = isinstance(exc, ConnectionRefusedError)
                self.reply(sock, REP_CONNECTION_REFUSED if refused else REP_GENERAL_FAILURE)
            return

        if not self.args.answer_first:
            bound = upstream.getsockname()
            self.reply(sock, REP_SUCCESS, bound[0], bound[1])
        pump(sock, upstream)

    def do_udp_associate(self, sock: socket.socket, peer: tuple[str, int]) -> "UdpRelay":
        relay = UdpRelay(self)
        relay.start()
        self.audit.record(
            event="udp_associate",
            client=f"{peer[0]}:{peer[1]}",
            relay=f"{relay.host}:{relay.port}",
        )
        self.reply(sock, REP_SUCCESS, relay.host, relay.port)
        # The association lives as long as the TCP control connection.
        try:
            while sock.recv(1):
                pass
        except OSError:
            pass
        return relay


class UdpRelay:
    """One SOCKS5 UDP association: strips the SOCKS header and relays both ways."""

    def __init__(self, server: Socks5Server) -> None:
        self.server = server
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((server.args.listen, 0))
        self.host, self.port = self.sock.getsockname()
        self.upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._client: Optional[tuple[str, int]] = None
        self._running = True
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        for target in (self._from_client, self._from_upstream):
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            self._threads.append(thread)

    def stop(self) -> None:
        self._running = False
        self.sock.close()
        self.upstream.close()

    def _from_client(self) -> None:
        while self._running:
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                return
            self._client = addr
            try:
                # RSV(2) FRAG(1) then a standard address block.
                if len(data) < 5 or data[2] != 0x00:
                    continue
                view = memoryview(data)
                atyp = view[3]
                offset = 4
                if atyp == ATYP_IPV4:
                    host = socket.inet_ntop(socket.AF_INET, bytes(view[offset:offset + 4]))
                    offset += 4
                elif atyp == ATYP_IPV6:
                    host = socket.inet_ntop(socket.AF_INET6, bytes(view[offset:offset + 16]))
                    offset += 16
                elif atyp == ATYP_DOMAIN:
                    length = view[offset]
                    offset += 1
                    host = bytes(view[offset:offset + length]).decode("idna")
                    offset += length
                else:
                    continue
                port = struct.unpack("!H", bytes(view[offset:offset + 2]))[0]
                offset += 2
                payload = bytes(view[offset:])
            except (IndexError, struct.error, UnicodeDecodeError):
                continue

            target = self.server.resolve_target(host, port)
            self.server.audit.record(
                event="udp_send",
                client=f"{addr[0]}:{addr[1]}",
                requested=f"{host}:{port}",
                dialled=f"{target[0]}:{target[1]}",
                bytes=len(payload),
            )
            self._last_target = (host, port)
            try:
                self.upstream.sendto(payload, target)
            except OSError as exc:
                self.server.audit.record(event="udp_send_failed", error=str(exc))

    def _from_upstream(self) -> None:
        while self._running:
            try:
                data, _addr = self.upstream.recvfrom(65535)
            except OSError:
                return
            client = self._client
            if client is None:
                continue
            # Reply using the address the client originally asked for, so the client's
            # matching logic sees the destination it requested.
            host, port = getattr(self, "_last_target", ("0.0.0.0", 0))
            header = b"\x00\x00\x00" + encode_address(host, port)
            self.server.audit.record(event="udp_reply", to=f"{client[0]}:{client[1]}", bytes=len(data))
            try:
                self.sock.sendto(header + data, client)
            except OSError:
                return


def pump(a: socket.socket, b: socket.socket) -> None:
    """Bidirectional copy until either side closes."""
    sel = selectors.DefaultSelector()
    a.setblocking(False)
    b.setblocking(False)
    sel.register(a, selectors.EVENT_READ, b)
    sel.register(b, selectors.EVENT_READ, a)
    try:
        open_sides = 2
        while open_sides > 0:
            for key, _mask in sel.select(timeout=30):
                src: socket.socket = key.fileobj  # type: ignore[assignment]
                dst: socket.socket = key.data
                try:
                    chunk = src.recv(65536)
                except BlockingIOError:
                    continue
                except OSError:
                    chunk = b""
                if not chunk:
                    sel.unregister(src)
                    open_sides -= 1
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                try:
                    dst.sendall(chunk)
                except OSError:
                    return
            else:
                if not sel.get_map():
                    return
    finally:
        sel.close()
        b.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=11080)
    parser.add_argument("--log", required=True, help="JSONL audit log path")
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument(
        "--rewrite",
        action="append",
        metavar="HOST:PORT=HOST:PORT",
        help="Dial a different address than the client requested. Repeatable.",
    )
    parser.add_argument(
        "--answer-first",
        action="store_true",
        help="Report a CONNECT as made before dialling, and close if the dial fails.",
    )
    args = parser.parse_args()

    server = Socks5Server(args)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.listen, args.port))
    listener.listen(64)
    print(f"socks5 listening on {args.listen}:{args.port}", flush=True)

    while True:
        try:
            conn, peer = listener.accept()
        except KeyboardInterrupt:
            return 0
        threading.Thread(target=server.handle, args=(conn, peer), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
