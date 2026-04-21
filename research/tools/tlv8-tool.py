#!/usr/bin/env python3
"""Decode HomeKit/Continuity TLV8 blobs from logs or packet captures."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from macolinux_dspext.tlv8 import TLV8Error, decode_tlv8, encode_tlv8  # noqa: E402


TLV8_NAMES = {
    0x00: "Method",
    0x01: "Identifier",
    0x02: "Salt",
    0x03: "PublicKey",
    0x04: "Proof",
    0x05: "EncryptedData",
    0x06: "State",
    0x07: "Error",
    0x08: "RetryDelay",
    0x09: "Certificate",
    0x0A: "Signature",
    0x0B: "Permissions",
    0x0C: "FragmentData",
    0x0D: "FragmentLast",
    0x19: "AppFlags",
}


def _hex_to_bytes(value: str) -> bytes:
    cleaned = "".join(value.split()).removeprefix("0x")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _parse_typed_hex(value: str) -> tuple[int, bytes]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("expected TYPE=HEX")
    type_text, hex_text = value.split("=", 1)
    try:
        tlv_type = int(type_text, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid TLV type {type_text!r}") from exc
    if not 0 <= tlv_type <= 0xFF:
        raise argparse.ArgumentTypeError("TLV type must fit in one byte")
    return tlv_type, _hex_to_bytes(hex_text)


def _decode(args: argparse.Namespace) -> int:
    data = _hex_to_bytes(args.hex)
    try:
        items = decode_tlv8(data)
    except TLV8Error as exc:
        print(f"tlv8-tool: {exc}", file=sys.stderr)
        return 1

    for tlv_type, value in items.items():
        name = TLV8_NAMES.get(tlv_type, "Unknown")
        print(f"0x{tlv_type:02x} {name:<13} len={len(value):>3} hex={value.hex()}")
    return 0


def _encode(args: argparse.Namespace) -> int:
    items = [_parse_typed_hex(item) for item in args.item]
    print(encode_tlv8(items).hex())
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    decode_parser = subparsers.add_parser("decode", help="decode a TLV8 hex blob")
    decode_parser.add_argument("hex", help="hex-encoded TLV8 bytes")
    decode_parser.set_defaults(func=_decode)

    encode_parser = subparsers.add_parser("encode", help="encode TYPE=HEX entries")
    encode_parser.add_argument("item", nargs="+", help="TLV entry, for example 0x06=01")
    encode_parser.set_defaults(func=_encode)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
