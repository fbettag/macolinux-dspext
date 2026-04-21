"""Rapport RPConnection frame helpers.

The visible Rapport TCP record layer is:

    TT LL LL LL BODY...

where TT is a one-byte frame type and LL LL LL is a 24-bit big-endian body
length. The OPACK payload may be unencrypted, paired, or encrypted depending on
the frame type and session state.
"""

from __future__ import annotations

from dataclasses import dataclass


HEADER_LEN = 4
MAX_BODY_LEN = 0xFFFFFF

FRAME_TYPES = {
    0x00: "Invalid",
    0x01: "NoOp",
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

STATUS_FLAG_BASE = 1 << 2
STATUS_FLAG_APPLE_PAY = 1 << 23
STATUS_FLAG_DEVICE_INFO_PAIRING_HINT = 1 << 24
STATUS_PRESERVE_MASK = 0xFBF27EBA7FFFF7FB


class RapportFrameError(ValueError):
    """Raised when a byte stream cannot be parsed as Rapport records."""


@dataclass(frozen=True)
class RapportFrame:
    frame_type: int
    body: bytes

    @property
    def name(self) -> str:
        return FRAME_TYPES.get(self.frame_type, "unknown")

    def encode(self) -> bytes:
        if not 0 <= self.frame_type <= 0xFF:
            raise RapportFrameError(f"invalid frame type: {self.frame_type}")
        if len(self.body) > MAX_BODY_LEN:
            raise RapportFrameError(f"body too large: {len(self.body)}")
        return bytes([self.frame_type]) + len(self.body).to_bytes(3, "big") + self.body

    @classmethod
    def decode_complete(cls, data: bytes) -> "RapportFrame":
        frame, used = decode_one(data)
        if used != len(data):
            raise RapportFrameError(f"trailing bytes after complete frame: {len(data) - used}")
        return frame


def frame_type_name(frame_type: int) -> str:
    return FRAME_TYPES.get(frame_type, "unknown")


def status_flags_from_bonjour_rpfl(
    rpfl: int,
    *,
    previous: int = 0,
    supports_apple_pay: bool = False,
    device_info: int = 0,
) -> int:
    """Translate Bonjour TXT rpFl bits into Rapport endpoint status flags.

    This mirrors the bit construction recovered from
    -[RPEndpoint updateWithBonjourDevice:] in Rapport.framework.
    """

    rpfl &= (1 << 64) - 1

    status = previous & STATUS_PRESERVE_MASK
    status |= STATUS_FLAG_BASE

    if supports_apple_pay:
        status |= STATUS_FLAG_APPLE_PAY
    if device_info & 0x18:
        status |= STATUS_FLAG_DEVICE_INFO_PAIRING_HINT

    status |= (rpfl << 4) & (1 << 35)
    status |= (rpfl << 18) & (1 << 32)
    status |= (rpfl << 34) & (1 << 22)
    status |= (rpfl << 10) & (1 << 42)
    status |= (rpfl >> 2) & (1 << 11)
    status |= ((rpfl >> 19) & 1) << 31
    status |= 0x50000 & (rpfl << 2)
    status |= ((rpfl >> 23) & 1) << 34

    return status


def header_body_len(header: bytes) -> int:
    if len(header) != HEADER_LEN:
        raise RapportFrameError(f"header must be {HEADER_LEN} bytes")
    return int.from_bytes(header[1:4], "big")


def decode_one(data: bytes, *, allow_unknown_type: bool = True) -> tuple[RapportFrame, int]:
    if len(data) < HEADER_LEN:
        raise RapportFrameError("not enough data for Rapport header")

    frame_type = data[0]
    if not allow_unknown_type and frame_type not in FRAME_TYPES:
        raise RapportFrameError(f"unknown frame type: 0x{frame_type:02x}")

    body_len = header_body_len(data[:HEADER_LEN])
    total_len = HEADER_LEN + body_len
    if len(data) < total_len:
        raise RapportFrameError(
            f"incomplete frame: need {total_len} bytes, have {len(data)}"
        )

    return RapportFrame(frame_type, data[HEADER_LEN:total_len]), total_len


def decode_many(data: bytes, *, allow_trailing: bool = False) -> list[RapportFrame]:
    frames: list[RapportFrame] = []
    offset = 0

    while offset < len(data):
        remaining = len(data) - offset
        if allow_trailing and remaining < HEADER_LEN:
            break
        frame, used = decode_one(data[offset:])
        frames.append(frame)
        offset += used

    return frames


class RapportStreamParser:
    """Incremental parser for TCP byte streams."""

    def __init__(self, *, max_body_len: int = MAX_BODY_LEN) -> None:
        self._buffer = bytearray()
        self.max_body_len = max_body_len

    @property
    def buffered_len(self) -> int:
        return len(self._buffer)

    def feed(self, data: bytes) -> list[RapportFrame]:
        self._buffer.extend(data)
        frames: list[RapportFrame] = []

        while len(self._buffer) >= HEADER_LEN:
            frame_type = self._buffer[0]
            body_len = int.from_bytes(self._buffer[1:4], "big")
            if body_len > self.max_body_len:
                raise RapportFrameError(
                    f"frame 0x{frame_type:02x} body too large: {body_len}"
                )
            total_len = HEADER_LEN + body_len
            if len(self._buffer) < total_len:
                break
            body = bytes(self._buffer[HEADER_LEN:total_len])
            del self._buffer[:total_len]
            frames.append(RapportFrame(frame_type, body))

        return frames
