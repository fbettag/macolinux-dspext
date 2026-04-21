"""HomeKit/Continuity TLV8 helpers.

PairVerify messages in CoreUtils use the common HomeKit TLV8 shape:

    TT LL VALUE...

where TT is a one-byte type and LL is a one-byte chunk length. Values longer
than 255 bytes are split across consecutive records with the same type.
"""

from __future__ import annotations

from collections import OrderedDict


class TLV8Error(ValueError):
    """Raised when bytes cannot be parsed as TLV8."""


def encode_tlv8(items: list[tuple[int, bytes]]) -> bytes:
    out = bytearray()
    for tlv_type, value in items:
        if not 0 <= tlv_type <= 0xFF:
            raise TLV8Error(f"invalid TLV type: {tlv_type}")
        offset = 0
        while offset < len(value) or (offset == 0 and not value):
            chunk = value[offset : offset + 255]
            out.extend((tlv_type, len(chunk)))
            out.extend(chunk)
            offset += len(chunk)
            if not chunk:
                break
    return bytes(out)


def decode_tlv8(data: bytes) -> "OrderedDict[int, bytes]":
    out: "OrderedDict[int, bytes]" = OrderedDict()
    offset = 0

    while offset < len(data):
        if offset + 2 > len(data):
            raise TLV8Error("truncated TLV8 header")
        tlv_type = data[offset]
        length = data[offset + 1]
        offset += 2
        if offset + length > len(data):
            raise TLV8Error(
                f"truncated TLV8 value for type 0x{tlv_type:02x}: "
                f"need {length} bytes, have {len(data) - offset}"
            )
        out[tlv_type] = out.get(tlv_type, b"") + data[offset : offset + length]
        offset += length

    return out

