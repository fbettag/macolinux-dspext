#!/usr/bin/env python3
"""Build or run Apple Continuity BLE advertisements with BlueZ btmgmt.

This is an experiment harness for the Sharing.framework SFBLEScanner path.
It does not claim to implement Universal Control discovery by itself.
"""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys


APPLE_COMPANY_ID_LE = bytes.fromhex("4c00")
AD_TYPE_FLAGS = 0x01
AD_TYPE_MANUFACTURER = 0xFF
CONTINUITY_NEARBY_ACTION = 0x0F
CONTINUITY_NEARBY_INFO = 0x10


def clean_hex(value: str) -> bytes:
    cleaned = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(cleaned) % 2:
        raise argparse.ArgumentTypeError(f"odd-length hex: {value!r}")
    return bytes.fromhex(cleaned)


def ad_structure(ad_type: int, payload: bytes) -> bytes:
    length = 1 + len(payload)
    if length > 0xFF:
        raise ValueError("AD structure too long")
    return bytes([length, ad_type]) + payload


def continuity_tlv(tlv_type: int, payload: bytes, length_flags: int = 0) -> bytes:
    if not 0 <= tlv_type <= 0xFF:
        raise ValueError("Continuity TLV type must fit in one byte")
    if len(payload) > 0x1F:
        raise ValueError("Continuity TLV payload length must fit in five bits")
    if length_flags & 0x1F:
        raise ValueError("length flags occupy only the high three bits")
    return bytes([tlv_type, length_flags | len(payload)]) + payload


def build_adv(args: argparse.Namespace) -> bytes:
    continuity = bytearray()

    for item in args.tlv:
        try:
            tlv_type_text, payload_text = item.split(":", 1)
            tlv_type = int(tlv_type_text, 16)
        except ValueError as exc:
            raise SystemExit(f"invalid --tlv {item!r}; expected TYPE:HEX") from exc
        continuity.extend(continuity_tlv(tlv_type, clean_hex(payload_text), args.length_flags))

    if args.nearby_info is not None:
        continuity.extend(
            continuity_tlv(CONTINUITY_NEARBY_INFO, clean_hex(args.nearby_info), args.length_flags)
        )
    if args.nearby_action is not None:
        continuity.extend(
            continuity_tlv(CONTINUITY_NEARBY_ACTION, clean_hex(args.nearby_action), args.length_flags)
        )

    if not continuity:
        raise SystemExit("provide --nearby-info, --nearby-action, or --tlv")

    adv = bytearray()
    if args.flags:
        adv.extend(ad_structure(AD_TYPE_FLAGS, clean_hex(args.flags)))
    adv.extend(ad_structure(AD_TYPE_MANUFACTURER, APPLE_COMPANY_ID_LE + bytes(continuity)))
    if len(adv) > 31:
        raise SystemExit(f"legacy advertising data is {len(adv)} bytes; maximum is 31")
    return bytes(adv)


def btmgmt_script(index: str, adv_hex: str, duration: int, instance: int) -> str:
    commands = [
        f"btmgmt --index {shlex.quote(index)} power off",
        f"btmgmt --index {shlex.quote(index)} le on",
        f"btmgmt --index {shlex.quote(index)} bredr off",
        f"btmgmt --index {shlex.quote(index)} connectable on",
        f"btmgmt --index {shlex.quote(index)} power on",
        f"btmgmt --index {shlex.quote(index)} clr-adv || true",
        (
            f"btmgmt --index {shlex.quote(index)} add-adv -c "
            f"-d {shlex.quote(adv_hex)} -t {duration:d} {instance:d}"
        ),
        f"btmgmt --index {shlex.quote(index)} info",
    ]
    return "set -euo pipefail\n" + "\n".join(commands)


def run_script(host: str | None, script: str) -> int:
    if host:
        cmd = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            host,
            f"nix-shell -p bluez --run {shlex.quote(script)}",
        ]
    else:
        cmd = ["sh", "-lc", script]
    return subprocess.call(cmd)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", default="0", help="BlueZ controller index, e.g. 0 for hci0")
    parser.add_argument("--host", help="optional SSH host, e.g. root@linux-peer")
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--instance", type=int, default=1)
    parser.add_argument("--flags", default="06", help="LE flags payload; empty disables flags")
    parser.add_argument(
        "--length-flags",
        type=lambda s: int(s, 0),
        default=0,
        help="high bits ORed into the Continuity TLV length byte",
    )
    parser.add_argument("--nearby-info", help="payload for Continuity TLV type 0x10")
    parser.add_argument("--nearby-action", help="payload for Continuity TLV type 0x0f")
    parser.add_argument(
        "--tlv",
        action="append",
        default=[],
        help="raw Continuity TLV as TYPE:HEX, e.g. 10:0000",
    )
    parser.add_argument("--run", action="store_true", help="run btmgmt instead of only printing")
    args = parser.parse_args(argv)

    adv = build_adv(args)
    adv_hex = adv.hex()
    print(f"advertising_data={adv_hex}")
    print(f"length={len(adv)}")
    print()
    script = btmgmt_script(args.index, adv_hex, args.duration, args.instance)
    print(script)

    if not args.run:
        return 0
    return run_script(args.host, script)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
