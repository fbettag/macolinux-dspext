#!/usr/bin/env python3
"""
Summarize visible Universal Control TCP records in an AWDL pcap.

This is intentionally small and dependency-free. It does not decrypt Rapport or
CompanionLink payloads; it only extracts IPv6/TCP payloads and recognizes the
clear 4-byte record header observed on Universal Control streams:

    TT LL LL LL

where TT is the Rapport frame type, LL LL LL is a 24-bit big-endian body
length, and the TCP payload length is 4 + body_length.
"""

from __future__ import annotations

import argparse
import collections
import ipaddress
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", "usec"),
    b"\xa1\xb2\xc3\xd4": (">", "usec"),
    b"\x4d\x3c\xb2\xa1": ("<", "nsec"),
    b"\xa1\xb2\x3c\x4d": (">", "nsec"),
}

DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 101

RAPPORT_FRAME_TYPES = {
    0x00: "Invalid",
    0x01: "NoOp",
    0x03: "PairSetupStart",
    0x04: "PairSetupNext",
    0x05: "PairVerifyStart",
    0x06: "PairVerifyNext",
    0x07: "U_OPACK",
    0x08: "E_OPACK",
    0x09: "P_OPACK",
    0x0A: "PA_Req",
    0x0B: "PA_Rsp",
    0x12: "FamilyIdentityRequest",
    0x20: "FamilyIdentityUpdate",
    0x21: "FamilyIdentityResponse",
    0x22: "FriendIdentityUpdate",
    0x30: "WatchIdentityRequest",
    0x31: "WatchIdentityResponse",
    0x40: "FriendIdentityRequest",
    0x41: "FriendIdentityResponse",
    0x42: "FriendIdentityUpdate",
}

# Keep the dependency-free parser conservative. If TCP data starts in the middle
# of an encrypted record, the first four bytes can accidentally resemble a
# known frame type with a nonsensical length.
MAX_REASONABLE_RECORD_BODY_LEN = 1024 * 1024


@dataclass(frozen=True)
class TcpPayload:
    src: str
    sport: int
    dst: str
    dport: int
    length: int
    payload: bytes


def read_pcap(path: Path):
    with path.open("rb") as f:
        magic = f.read(4)
        if magic not in PCAP_MAGICS:
            raise ValueError(f"{path} is not a classic pcap file")

        endian, precision = PCAP_MAGICS[magic]
        header = f.read(20)
        if len(header) != 20:
            raise ValueError(f"{path} has a truncated pcap header")

        _version_major, _version_minor, _thiszone, _sigfigs, _snaplen, linktype = struct.unpack(
            endian + "HHiiii", header
        )

        packet_header = struct.Struct(endian + "IIII")
        while True:
            raw_header = f.read(packet_header.size)
            if not raw_header:
                break
            if len(raw_header) != packet_header.size:
                print("warning: ignoring truncated pcap packet header", file=sys.stderr)
                break

            ts_sec, ts_frac, incl_len, _orig_len = packet_header.unpack(raw_header)
            data = f.read(incl_len)
            if len(data) != incl_len:
                print("warning: ignoring truncated pcap packet data", file=sys.stderr)
                break

            yield precision, linktype, ts_sec, ts_frac, data


def extract_ipv6(linktype: int, frame: bytes) -> bytes | None:
    if linktype == DLT_EN10MB:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack("!H", frame[12:14])[0]
        offset = 14

        # Skip a single 802.1Q VLAN tag if present.
        if ethertype == 0x8100 and len(frame) >= 18:
            ethertype = struct.unpack("!H", frame[16:18])[0]
            offset = 18

        if ethertype != 0x86DD:
            return None
        return frame[offset:]

    if linktype == DLT_RAW:
        if frame and frame[0] >> 4 == 6:
            return frame
        return None

    if linktype == DLT_NULL:
        if len(frame) < 4:
            return None
        family_le = struct.unpack("<I", frame[:4])[0]
        family_be = struct.unpack(">I", frame[:4])[0]
        # AF_INET6 is 30 on Darwin/BSD pcap DLT_NULL.
        if family_le == 30 or family_be == 30:
            return frame[4:]
        return None

    return None


def extract_tcp_payload(ipv6: bytes) -> TcpPayload | None:
    if len(ipv6) < 40 or ipv6[0] >> 4 != 6:
        return None

    payload_len = struct.unpack("!H", ipv6[4:6])[0]
    next_header = ipv6[6]
    src = str(ipaddress.IPv6Address(ipv6[8:24]))
    dst = str(ipaddress.IPv6Address(ipv6[24:40]))
    offset = 40
    remaining = min(len(ipv6) - offset, payload_len)

    # Handle common extension headers enough for AWDL captures.
    while next_header in {0, 43, 44, 50, 51, 60}:
        if remaining < 8:
            return None
        if next_header == 44:
            ext_len = 8
        else:
            ext_len = (ipv6[offset + 1] + 1) * 8
        next_header = ipv6[offset]
        offset += ext_len
        remaining -= ext_len

    if next_header != 6 or remaining < 20:
        return None

    tcp = ipv6[offset : offset + remaining]
    sport, dport = struct.unpack("!HH", tcp[:4])
    data_offset = (tcp[12] >> 4) * 4
    if data_offset < 20 or len(tcp) < data_offset:
        return None

    payload = tcp[data_offset:]
    return TcpPayload(src, sport, dst, dport, len(payload), payload)


def record_header(payload: bytes) -> tuple[int, int] | None:
    if len(payload) < 4:
        return None

    frame_type = payload[0]
    body_len = int.from_bytes(payload[1:4], "big")
    if frame_type not in RAPPORT_FRAME_TYPES:
        return None
    if body_len > MAX_REASONABLE_RECORD_BODY_LEN:
        return None

    return frame_type, body_len


def stream_key(packet: TcpPayload) -> tuple[tuple[str, int], tuple[str, int]]:
    a = (packet.src, packet.sport)
    b = (packet.dst, packet.dport)
    return tuple(sorted((a, b)))  # type: ignore[return-value]


def direction(packet: TcpPayload) -> str:
    return f"{packet.src}%{packet.sport} -> {packet.dst}%{packet.dport}"


def summarize(path: Path, show_records: int) -> int:
    packets = 0
    tcp_packets = 0
    payload_packets = 0
    stream_counts = collections.Counter()
    direction_lengths: dict[str, collections.Counter[int]] = collections.defaultdict(collections.Counter)
    record_counts: dict[str, collections.Counter[tuple[int, int, bool]]] = collections.defaultdict(
        collections.Counter
    )
    examples: list[tuple[str, int, int, int, bool, bytes]] = []

    linktypes = collections.Counter()

    for _precision, linktype, _ts_sec, _ts_frac, frame in read_pcap(path):
        packets += 1
        linktypes[linktype] += 1

        ipv6 = extract_ipv6(linktype, frame)
        if ipv6 is None:
            continue

        tcp_payload = extract_tcp_payload(ipv6)
        if tcp_payload is None:
            continue

        tcp_packets += 1
        stream_counts[stream_key(tcp_payload)] += 1

        if tcp_payload.length == 0:
            continue

        payload_packets += 1
        dir_key = direction(tcp_payload)
        direction_lengths[dir_key][tcp_payload.length] += 1

        header = record_header(tcp_payload.payload)
        if header:
            frame_type, body_len = header
            complete = tcp_payload.length == body_len + 4
            record_counts[dir_key][(frame_type, body_len, complete)] += 1
            if len(examples) < show_records:
                examples.append(
                    (
                        dir_key,
                        tcp_payload.length,
                        frame_type,
                        body_len,
                        complete,
                        tcp_payload.payload[:32],
                    )
                )

    print(f"pcap: {path}")
    print(f"packets: {packets}")
    print(f"linktypes: {dict(linktypes)}")
    print(f"tcp packets: {tcp_packets}")
    print(f"tcp packets with payload: {payload_packets}")
    print()

    print("streams:")
    for key, count in stream_counts.most_common():
        (left_host, left_port), (right_host, right_port) = key
        print(f"  {left_host}%{left_port} <-> {right_host}%{right_port}: {count} packets")
    print()

    print("payload lengths by direction:")
    for dir_key in sorted(direction_lengths):
        lengths = ", ".join(
            f"{length}x{count}" for length, count in direction_lengths[dir_key].most_common()
        )
        print(f"  {dir_key}: {lengths}")
    print()

    print("Rapport record headers:")
    if not record_counts:
        print("  none")
    for dir_key in sorted(record_counts):
        print(f"  {dir_key}:")
        for (frame_type, body_len, complete), count in record_counts[dir_key].most_common():
            status = "complete" if complete else "partial-or-coalesced"
            name = RAPPORT_FRAME_TYPES.get(frame_type, "unknown")
            print(
                f"    type=0x{frame_type:02x} ({name}) body_len={body_len} "
                f"{status}: {count}"
            )

    if examples:
        print()
        print("examples:")
        for dir_key, total_len, frame_type, body_len, complete, prefix in examples:
            status = "complete" if complete else "partial-or-coalesced"
            name = RAPPORT_FRAME_TYPES.get(frame_type, "unknown")
            print(
                f"  {dir_key} len={total_len} type=0x{frame_type:02x} ({name}) "
                f"body_len={body_len} {status} first32={prefix.hex()}"
            )

    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument(
        "--show-records",
        type=int,
        default=8,
        help="number of example records to print",
    )
    args = parser.parse_args(argv)
    return summarize(args.pcap, args.show_records)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
