#!/usr/bin/env python3
"""Dump Rapport RPConnection frames from a raw byte stream or hex input."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from macolinux_dspext.rapport import RapportFrameError, decode_many


HEX_RE = re.compile(rb"[^0-9a-fA-F]")


def read_input(path: str | None, is_hex: bool) -> bytes:
    if path:
        candidate = Path(path)
        if is_hex and not candidate.exists():
            raw = path.encode("ascii")
        else:
            raw = candidate.read_bytes()
    else:
        raw = sys.stdin.buffer.read()

    if not is_hex:
        return raw

    cleaned = HEX_RE.sub(b"", raw)
    if len(cleaned) % 2:
        raise SystemExit("hex input has an odd number of digits")
    return bytes.fromhex(cleaned.decode("ascii"))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", help="raw stream file; stdin if omitted")
    parser.add_argument("--hex", action="store_true", help="input is hex text")
    parser.add_argument("--prefix", type=int, default=32, help="body prefix bytes to print")
    parser.add_argument(
        "--allow-trailing",
        action="store_true",
        help="allow a final incomplete trailing fragment",
    )
    args = parser.parse_args(argv)

    data = read_input(args.path, args.hex)
    try:
        frames = decode_many(data, allow_trailing=args.allow_trailing)
    except RapportFrameError as exc:
        raise SystemExit(str(exc)) from exc

    for index, frame in enumerate(frames):
        prefix = frame.body[: args.prefix].hex()
        print(
            f"{index}: type=0x{frame.frame_type:02x} ({frame.name}) "
            f"body_len={len(frame.body)} prefix={prefix}"
        )

    print(f"frames: {len(frames)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
