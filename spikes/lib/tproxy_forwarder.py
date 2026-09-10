#!/usr/bin/env python3
"""TPROXY -> SOCKS5 forwarder: the prototype of Yura's in-daemon transparent forwarder.

Yura does not embed a routing engine. The kernel classifier (cgroup v2 + nftables) decides
*which* traffic to capture; this process is what the captured traffic is handed to, and it
re-originates each flow towards a user-supplied SOCKS5 proxy.

The two facts that make this work:

  * With IP_TRANSPARENT + TPROXY, an accepted TCP socket's own local address *is* the
    original destination. No conntrack, no NAT, no SO_ORIGINAL_DST.
  * For UDP the original destination arrives out of band in an IP_ORIGDSTADDR control
    message, and replies must be sent from a transparent socket bound to that address so
    the client sees an answer from the peer it addressed.

Loop prevention: every socket this process opens towards the proxy carries SO_MARK, and the
nftables ruleset returns early on that mark. Without it the forwarder's own upstream
connection would be reclassified and fed back into itself.

Requires CAP_NET_ADMIN / CAP_NET_RAW (in practice: root).
"""

from __future__ import annotations

import argparse
import errno
import json
import selectors
import socket
import struct
import sys
import threading
import time

# Socket option numbers. Python's socket module does not expose all of these.
SOL_IP = 0
IP_TRANSPARENT = 19
IP_RECVORIGDSTADDR = 20
IP_ORIGDSTADDR = 20

ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04


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


def read_exactly(sock: socket.socket, count: int) -> bytes:
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ConnectionError("proxy closed during handshake")
        buf += chunk
    return buf


def encode_address(host: str, port: int) -> bytes:
    try:
        return bytes([ATYP_IPV4]) + socket.inet_pton(socket.AF_INET, host) + struct.pack("!H", port)
    except OSError:
        pass
    try:
        return bytes([ATYP_IPV6]) + socket.inet_pton(socket.AF_INET6, host) + struct.pack("!H", port)
    except OSError:
        pass
    raw = host.encode("idna")
    return bytes([ATYP_DOMAIN, len(raw)]) + raw + struct.pack("!H", port)


def skip_address(sock: socket.socket) -> tuple[str, int]:
    atyp = read_exactly(sock, 1)[0]
    if atyp == ATYP_IPV4:
        host = socket.inet_ntop(socket.AF_INET, read_exactly(sock, 4))
    elif atyp == ATYP_IPV6:
        host = socket.inet_ntop(socket.AF_INET6, read_exactly(sock, 16))
    elif atyp == ATYP_DOMAIN:
        host = read_exactly(sock, read_exactly(sock, 1)[0]).decode("idna")
    else:
        raise ValueError(f"bad address type {atyp:#x}")
    return host, struct.unpack("!H", read_exactly(sock, 2))[0]


class Forwarder:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.audit = AuditLog(args.log)
        host, _, port = args.socks.rpartition(":")
        self.socks = (host, int(port))

    # -- SOCKS5 client -----------------------------------------------------

    def dial_proxy(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Loop prevention: this socket must not be reclassified back into the forwarder.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, self.args.mark)
        sock.settimeout(self.args.timeout)
        sock.connect(self.socks)
        return sock

    def socks_handshake(self, sock: socket.socket) -> None:
        sock.sendall(b"\x05\x01\x00")
        reply = read_exactly(sock, 2)
        if reply[0] != 0x05 or reply[1] != 0x00:
            raise ConnectionError(f"proxy rejected auth negotiation: {reply!r}")

    def socks_request(self, sock: socket.socket, cmd: int, host: str, port: int) -> tuple[str, int]:
        sock.sendall(bytes([0x05, cmd, 0x00]) + encode_address(host, port))
        header = read_exactly(sock, 3)
        if header[0] != 0x05:
            raise ConnectionError("bad SOCKS version in reply")
        if header[1] != 0x00:
            raise ConnectionError(f"proxy refused request, reply code {header[1]:#x}")
        return skip_address(sock)

    # -- TCP ---------------------------------------------------------------

    def serve_tcp(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.setsockopt(SOL_IP, IP_TRANSPARENT, 1)
        listener.bind((self.args.listen, self.args.port))
        listener.listen(128)
        print(f"tproxy tcp on {self.args.listen}:{self.args.port}", flush=True)

        while True:
            conn, peer = listener.accept()
            threading.Thread(target=self.handle_tcp, args=(conn, peer), daemon=True).start()

    def handle_tcp(self, conn: socket.socket, peer: tuple[str, int]) -> None:
        # With TPROXY the accepted socket's local address is the ORIGINAL destination,
        # not our listener address.
        original = conn.getsockname()
        self.audit.record(
            event="tcp_capture", client=f"{peer[0]}:{peer[1]}", original=f"{original[0]}:{original[1]}"
        )
        upstream = None
        try:
            upstream = self.dial_proxy()
            self.socks_handshake(upstream)
            self.socks_request(upstream, 0x01, original[0], original[1])
            upstream.settimeout(None)
            self.audit.record(
                event="tcp_forwarded",
                client=f"{peer[0]}:{peer[1]}",
                original=f"{original[0]}:{original[1]}",
                proxy=f"{self.socks[0]}:{self.socks[1]}",
            )
            pump(conn, upstream)
        except (OSError, ConnectionError, ValueError, struct.error) as exc:
            self.audit.record(
                event="tcp_failed",
                client=f"{peer[0]}:{peer[1]}",
                original=f"{original[0]}:{original[1]}",
                error=str(exc),
            )
            conn.close()
            if upstream is not None:
                upstream.close()

    # -- UDP ---------------------------------------------------------------

    def serve_udp(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(SOL_IP, IP_TRANSPARENT, 1)
        sock.setsockopt(SOL_IP, IP_RECVORIGDSTADDR, 1)
        sock.bind((self.args.listen, self.args.port))
        print(f"tproxy udp on {self.args.listen}:{self.args.port}", flush=True)

        sessions: dict[tuple[tuple[str, int], tuple[str, int]], UdpSession] = {}
        lock = threading.Lock()

        while True:
            try:
                data, ancdata, _flags, client = sock.recvmsg(65535, socket.CMSG_SPACE(24))
            except OSError as exc:
                if exc.errno == errno.EINTR:
                    continue
                raise

            original = parse_origdstaddr(ancdata)
            if original is None:
                self.audit.record(event="udp_no_origdst", client=f"{client[0]}:{client[1]}")
                continue

            key = (client, original)
            with lock:
                session = sessions.get(key)
                if session is None:
                    self.audit.record(
                        event="udp_capture",
                        client=f"{client[0]}:{client[1]}",
                        original=f"{original[0]}:{original[1]}",
                    )
                    try:
                        session = UdpSession(self, client, original)
                        session.start()
                        sessions[key] = session
                    except (OSError, ConnectionError, ValueError, struct.error) as exc:
                        self.audit.record(
                            event="udp_failed",
                            client=f"{client[0]}:{client[1]}",
                            original=f"{original[0]}:{original[1]}",
                            error=str(exc),
                        )
                        continue
            session.send(data)


def parse_origdstaddr(ancdata: list[tuple[int, int, bytes]]) -> tuple[str, int] | None:
    for level, ctype, payload in ancdata:
        if level == SOL_IP and ctype == IP_ORIGDSTADDR:
            _family, port = struct.unpack("!HH", payload[:4])
            host = socket.inet_ntop(socket.AF_INET, payload[4:8])
            return host, port
    return None


class UdpSession:
    """One captured UDP flow relayed through a SOCKS5 UDP association."""

    def __init__(self, fwd: Forwarder, client: tuple[str, int], original: tuple[str, int]) -> None:
        self.fwd = fwd
        self.client = client
        self.original = original
        self.control = fwd.dial_proxy()
        fwd.socks_handshake(self.control)
        relay_host, relay_port = fwd.socks_request(self.control, 0x03, "0.0.0.0", 0)
        if relay_host in ("0.0.0.0", "::"):
            relay_host = fwd.socks[0]
        self.relay = (relay_host, relay_port)
        self.control.settimeout(None)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, fwd.args.mark)
        self.sock.connect(self.relay)

        # Replies must appear to come from the address the client addressed, which needs a
        # transparent socket bound to that (foreign) address.
        self.reply_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.reply_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.reply_sock.setsockopt(SOL_IP, IP_TRANSPARENT, 1)
        self.reply_sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, fwd.args.mark)
        self.reply_sock.bind(self.original)

    def start(self) -> None:
        threading.Thread(target=self._pump_replies, daemon=True).start()

    def send(self, payload: bytes) -> None:
        header = b"\x00\x00\x00" + encode_address(self.original[0], self.original[1])
        try:
            self.sock.send(header + payload)
        except OSError as exc:
            self.fwd.audit.record(event="udp_send_failed", error=str(exc))

    def _pump_replies(self) -> None:
        while True:
            try:
                data = self.sock.recv(65535)
            except OSError:
                return
            if len(data) < 5:
                continue
            atyp = data[3]
            offset = 4
            if atyp == ATYP_IPV4:
                offset += 4
            elif atyp == ATYP_IPV6:
                offset += 16
            elif atyp == ATYP_DOMAIN:
                offset += 1 + data[offset]
            else:
                continue
            offset += 2
            payload = data[offset:]
            self.fwd.audit.record(
                event="udp_reply",
                to=f"{self.client[0]}:{self.client[1]}",
                spoofed_from=f"{self.original[0]}:{self.original[1]}",
                bytes=len(payload),
            )
            try:
                self.reply_sock.sendto(payload, self.client)
            except OSError as exc:
                self.fwd.audit.record(event="udp_reply_failed", error=str(exc))
                return


def pump(a: socket.socket, b: socket.socket) -> None:
    sel = selectors.DefaultSelector()
    a.setblocking(False)
    b.setblocking(False)
    sel.register(a, selectors.EVENT_READ, b)
    sel.register(b, selectors.EVENT_READ, a)
    try:
        while sel.get_map():
            for key, _mask in sel.select(timeout=60):
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
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                try:
                    dst.sendall(chunk)
                except OSError:
                    return
    finally:
        sel.close()
        a.close()
        b.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--socks", required=True, metavar="HOST:PORT")
    parser.add_argument("--mark", type=lambda v: int(v, 0), default=0x712,
                        help="SO_MARK applied to upstream sockets for loop prevention")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--log", required=True)
    args = parser.parse_args()

    fwd = Forwarder(args)
    threading.Thread(target=fwd.serve_udp, daemon=True).start()
    fwd.serve_tcp()
    return 0


if __name__ == "__main__":
    sys.exit(main())
