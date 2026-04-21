#!/usr/bin/env python3
"""
Minimal CompanionLink mDNS advertiser and TCP listener.

This is a research harness, not a full mDNS implementation. It advertises one
_companion-link._tcp.local service instance and logs inbound TCP connections so
we can see whether macOS rapportd attempts to connect to a synthetic peer.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import select
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass


MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353
CLASS_IN = 1
CLASS_IN_FLUSH = 0x8001
TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33
TYPE_ANY = 255


@dataclass(frozen=True)
class PeerConfig:
    service_type: str
    instance: str
    hostname: str
    port: int
    txt: tuple[str, ...]
    ipv4: str | None
    ipv6: str | None
    multicast_ipv4: str | None

    @property
    def service_fqdn(self) -> str:
        return dotted(self.service_type)

    @property
    def instance_fqdn(self) -> str:
        return dotted(f"{self.instance}.{self.service_type}")

    @property
    def host_fqdn(self) -> str:
        return dotted(self.hostname)


def dotted(name: str) -> str:
    return name if name.endswith(".") else f"{name}."


def encode_name(name: str) -> bytes:
    out = bytearray()
    for label in dotted(name).split("."):
        if not label:
            out.append(0)
            break
        raw = label.encode("utf-8")
        if len(raw) > 63:
            raise ValueError(f"DNS label too long: {label!r}")
        out.append(len(raw))
        out.extend(raw)
    return bytes(out)


def decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    next_offset = offset

    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]

        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if not jumped:
                next_offset = offset + 2
            offset = pointer
            jumped = True
            continue

        if length == 0:
            if not jumped:
                next_offset = offset + 1
            break

        offset += 1
        if offset + length > len(packet):
            raise ValueError("truncated DNS label")
        labels.append(packet[offset : offset + length].decode("utf-8", errors="replace"))
        offset += length

    return ".".join(labels) + ".", next_offset


def question_names(packet: bytes) -> list[tuple[str, int]]:
    if len(packet) < 12:
        return []
    _tid, _flags, qdcount, _ancount, _nscount, _arcount = struct.unpack("!HHHHHH", packet[:12])
    offset = 12
    out: list[tuple[str, int]] = []
    for _ in range(qdcount):
        try:
            name, offset = decode_name(packet, offset)
        except ValueError:
            return out
        if offset + 4 > len(packet):
            return out
        qtype, _qclass = struct.unpack("!HH", packet[offset : offset + 4])
        offset += 4
        out.append((name.lower(), qtype))
    return out


def rr(name: str, rtype: int, rclass: int, ttl: int, rdata: bytes) -> bytes:
    return (
        encode_name(name)
        + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata))
        + rdata
    )


def ptr_rr(name: str, target: str, ttl: int = 120) -> bytes:
    return rr(name, TYPE_PTR, CLASS_IN, ttl, encode_name(target))


def srv_rr(name: str, target: str, port: int, ttl: int = 120) -> bytes:
    return rr(name, TYPE_SRV, CLASS_IN_FLUSH, ttl, struct.pack("!HHH", 0, 0, port) + encode_name(target))


def txt_rr(name: str, txt: tuple[str, ...], ttl: int = 120) -> bytes:
    payload = bytearray()
    for item in txt:
        raw = item.encode("utf-8")
        if len(raw) > 255:
            raise ValueError(f"TXT item too long: {item!r}")
        payload.append(len(raw))
        payload.extend(raw)
    return rr(name, TYPE_TXT, CLASS_IN_FLUSH, ttl, bytes(payload))


def a_rr(name: str, addr: str, ttl: int = 120) -> bytes:
    return rr(name, TYPE_A, CLASS_IN_FLUSH, ttl, socket.inet_aton(addr))


def aaaa_rr(name: str, addr: str, ttl: int = 120) -> bytes:
    return rr(name, TYPE_AAAA, CLASS_IN_FLUSH, ttl, ipaddress.IPv6Address(addr).packed)


def response_records(config: PeerConfig) -> list[bytes]:
    records = [
        ptr_rr(config.service_fqdn, config.instance_fqdn),
        srv_rr(config.instance_fqdn, config.host_fqdn, config.port),
        txt_rr(config.instance_fqdn, config.txt),
    ]
    if config.ipv4:
        records.append(a_rr(config.host_fqdn, config.ipv4))
    if config.ipv6:
        records.append(aaaa_rr(config.host_fqdn, config.ipv6))
    return records


def build_response(config: PeerConfig) -> bytes:
    records = response_records(config)
    return struct.pack("!HHHHHH", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)


def should_answer(config: PeerConfig, packet: bytes) -> bool:
    names = question_names(packet)
    if not names:
        return False

    interesting = {
        config.service_fqdn.lower(),
        config.instance_fqdn.lower(),
        config.host_fqdn.lower(),
        "_services._dns-sd._udp.local.",
    }
    return any(name in interesting and qtype in {TYPE_PTR, TYPE_SRV, TYPE_TXT, TYPE_A, TYPE_AAAA, TYPE_ANY} for name, qtype in names)


def mdns_loop(config: PeerConfig, stop: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except OSError:
        pass
    sock.bind(("", MDNS_PORT))
    membership_addr = config.multicast_ipv4 or "0.0.0.0"
    sock.setsockopt(
        socket.IPPROTO_IP,
        socket.IP_ADD_MEMBERSHIP,
        socket.inet_aton(MDNS_ADDR) + socket.inet_aton(membership_addr),
    )
    if config.multicast_ipv4:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(config.multicast_ipv4))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    sock.setblocking(False)

    response = build_response(config)
    next_announce = 0.0

    while not stop.is_set():
        now = time.monotonic()
        if now >= next_announce:
            sock.sendto(response, (MDNS_ADDR, MDNS_PORT))
            print(f"[mdns] announced {config.instance_fqdn} -> {config.host_fqdn}:{config.port}", flush=True)
            next_announce = now + 5.0

        readable, _, _ = select.select([sock], [], [], 0.5)
        for ready in readable:
            try:
                packet, addr = ready.recvfrom(9000)
            except BlockingIOError:
                continue
            if should_answer(config, packet):
                ready.sendto(response, (MDNS_ADDR, MDNS_PORT))
                names = ", ".join(f"{name}/{qtype}" for name, qtype in question_names(packet))
                print(f"[mdns] answered {addr}: {names}", flush=True)


def tcp_loop(config: PeerConfig, stop: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET6 if config.ipv6 and not config.ipv4 else socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bind_addr: tuple
    if sock.family == socket.AF_INET6:
        bind_addr = ("::", config.port)
    else:
        bind_addr = ("0.0.0.0", config.port)
    sock.bind(bind_addr)
    sock.listen(16)
    sock.setblocking(False)
    print(f"[tcp] listening on port {config.port}", flush=True)

    while not stop.is_set():
        readable, _, _ = select.select([sock], [], [], 0.5)
        for ready in readable:
            conn, addr = ready.accept()
            threading.Thread(target=handle_conn, args=(conn, addr), daemon=True).start()


def handle_conn(conn: socket.socket, addr) -> None:
    print(f"[tcp] accepted {addr}", flush=True)
    conn.settimeout(10.0)
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                print(f"[tcp] closed {addr}", flush=True)
                return
            print(f"[tcp] {addr} {len(data)} bytes: {data[:64].hex()}", flush=True)
    except TimeoutError:
        print(f"[tcp] timeout {addr}", flush=True)
    except OSError as exc:
        print(f"[tcp] error {addr}: {exc}", flush=True)
    finally:
        conn.close()


def default_ipv4() -> str | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instance", default="linux-peer")
    parser.add_argument("--service-type", default="_companion-link._tcp.local")
    parser.add_argument("--hostname", default=None)
    parser.add_argument("--port", type=int, default=49152)
    parser.add_argument("--ipv4", default=None)
    parser.add_argument("--ipv6", default=None)
    parser.add_argument("--multicast-ipv4", default=None)
    parser.add_argument("--txt", action="append", default=[])
    parser.add_argument("--duration", type=int, default=0, help="seconds to run; 0 means until interrupted")
    args = parser.parse_args(argv)

    hostname = args.hostname or f"{socket.gethostname().split('.')[0]}.local"
    ipv4 = args.ipv4 if args.ipv4 != "none" else None
    if ipv4 is None and args.ipv4 != "none":
        ipv4 = default_ipv4()

    txt = tuple(
        args.txt
        or [
            "rpMac=0",
            f"rpHN={os.urandom(6).hex()}",
            "rpFl=0x20000",
            f"rpHA={os.urandom(6).hex()}",
            "rpVr=715.2",
            f"rpAD={os.urandom(6).hex()}",
            f"rpHI={os.urandom(8).hex()}",
            f"rpBA={os.urandom(6).hex(':').upper()}",
        ]
    )

    config = PeerConfig(
        service_type=args.service_type,
        instance=args.instance,
        hostname=hostname,
        port=args.port,
        txt=txt,
        ipv4=ipv4,
        ipv6=args.ipv6,
        multicast_ipv4=args.multicast_ipv4 or ipv4,
    )

    print("[peer] config", flush=True)
    print(f"  instance: {config.instance_fqdn}", flush=True)
    print(f"  hostname: {config.host_fqdn}", flush=True)
    print(f"  port: {config.port}", flush=True)
    print(f"  ipv4: {config.ipv4}", flush=True)
    print(f"  ipv6: {config.ipv6}", flush=True)
    print(f"  multicast_ipv4: {config.multicast_ipv4}", flush=True)
    for item in config.txt:
        print(f"  txt: {item}", flush=True)

    stop = threading.Event()
    threads = [
        threading.Thread(target=mdns_loop, args=(config, stop), daemon=True),
        threading.Thread(target=tcp_loop, args=(config, stop), daemon=True),
    ]
    for thread in threads:
        thread.start()

    try:
        if args.duration:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
