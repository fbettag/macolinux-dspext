"""Reverse-engineered HomeKit PairVerify constants used by CoreUtils."""

from __future__ import annotations

TLV_METHOD = 0x00
TLV_IDENTIFIER = 0x01
TLV_PUBLIC_KEY = 0x03
TLV_ENCRYPTED_DATA = 0x05
TLV_STATE = 0x06
TLV_ERROR = 0x07
TLV_SIGNATURE = 0x0A
TLV_APP_FLAGS = 0x19

PAIR_VERIFY_ECDH_SALT = b"Pair-Verify-ECDH-Salt"
PAIR_VERIFY_ECDH_INFO = b"Pair-Verify-ECDH-Info"
PAIR_VERIFY_ENCRYPT_SALT = b"Pair-Verify-Encrypt-Salt"
PAIR_VERIFY_ENCRYPT_INFO = b"Pair-Verify-Encrypt-Info"

PAIR_VERIFY_M2_NONCE = b"PV-Msg02"
PAIR_VERIFY_M3_NONCE = b"PV-Msg03"
PAIR_VERIFY_M4_SERVER_NONCE = b"PV-Msg4s"
PAIR_VERIFY_M4_NONCE = b"PV-Msg04"

PAIR_VERIFY_RESUME_SESSION_ID_SALT = b"Pair-Verify-ResumeSessionID-Salt"
PAIR_VERIFY_RESUME_SESSION_ID_INFO = b"Pair-Verify-ResumeSessionID-Info"

MFI_PAIR_VERIFY_SALT = b"MFi-Pair-Verify-Salt"
MFI_PAIR_VERIFY_INFO = b"MFi-Pair-Verify-Info"

PAIRVERIFY_PUBLIC_KEY_LENGTH = 32
PAIRVERIFY_KEY_LENGTH = 32
CHACHA20_POLY1305_TAG_LENGTH = 16


def pairing_stream_info(stream_name: str, *, client_to_server: bool) -> bytes:
    prefix = "ClientEncrypt" if client_to_server else "ServerEncrypt"
    return f"{prefix}-{stream_name}".encode("utf-8")
