import unittest

from macolinux_dspext.pairverify import (
    PAIR_VERIFY_ECDH_INFO,
    PAIR_VERIFY_ECDH_SALT,
    PAIR_VERIFY_ENCRYPT_INFO,
    PAIR_VERIFY_ENCRYPT_SALT,
    PAIR_VERIFY_M2_NONCE,
    PAIR_VERIFY_M3_NONCE,
    TLV_APP_FLAGS,
    TLV_ENCRYPTED_DATA,
    TLV_PUBLIC_KEY,
    TLV_STATE,
    pairing_stream_info,
)
from macolinux_dspext.rapport import (
    RapportFrame,
    RapportFrameError,
    RapportStreamParser,
    decode_many,
    decode_one,
    status_flags_from_bonjour_rpfl,
)
from macolinux_dspext.tlv8 import TLV8Error, decode_tlv8, encode_tlv8


class RapportFrameTests(unittest.TestCase):
    def test_encode_decode_complete(self):
        frame = RapportFrame(0x08, bytes.fromhex("010203"))
        encoded = frame.encode()

        self.assertEqual(encoded, bytes.fromhex("08000003010203"))
        decoded = RapportFrame.decode_complete(encoded)
        self.assertEqual(decoded.frame_type, 0x08)
        self.assertEqual(decoded.name, "E_OPACK")
        self.assertEqual(decoded.body, bytes.fromhex("010203"))

    def test_decode_many(self):
        data = RapportFrame(0x0A, b"abc").encode() + RapportFrame(0x0B, b"defg").encode()

        frames = decode_many(data)

        self.assertEqual([(f.frame_type, f.body) for f in frames], [(0x0A, b"abc"), (0x0B, b"defg")])

    def test_incremental_parser(self):
        encoded = RapportFrame(0x08, b"abcdef").encode()
        parser = RapportStreamParser()

        self.assertEqual(parser.feed(encoded[:3]), [])
        self.assertEqual(parser.buffered_len, 3)
        frames = parser.feed(encoded[3:])

        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].body, b"abcdef")
        self.assertEqual(parser.buffered_len, 0)

    def test_incomplete_decode_one_raises(self):
        with self.assertRaises(RapportFrameError):
            decode_one(bytes.fromhex("08000005aa"))

    def test_status_flags_from_empty_bonjour_rpfl(self):
        self.assertEqual(status_flags_from_bonjour_rpfl(0), 1 << 2)

    def test_status_flags_from_bonjour_rpfl_scalar_bits(self):
        cases = [
            (13, 11),
            (14, 16),
            (14, 32),
            (16, 18),
            (19, 31),
            (23, 34),
            (31, 35),
            (32, 42),
        ]

        for rpfl_bit, status_bit in cases:
            with self.subTest(rpfl_bit=rpfl_bit, status_bit=status_bit):
                status = status_flags_from_bonjour_rpfl(1 << rpfl_bit)
                self.assertTrue(status & (1 << status_bit))

    def test_status_flags_from_bonjour_rpfl_context_bits(self):
        self.assertTrue(status_flags_from_bonjour_rpfl(0, device_info=0x18) & (1 << 24))
        self.assertTrue(status_flags_from_bonjour_rpfl(0, supports_apple_pay=True) & (1 << 23))

    def test_status_flags_from_bonjour_rpfl_preserves_masked_previous_bits(self):
        self.assertTrue(status_flags_from_bonjour_rpfl(0, previous=1 << 19) & (1 << 19))


class TLV8Tests(unittest.TestCase):
    def test_tlv8_round_trip(self):
        encoded = encode_tlv8([(0x06, b"\x01"), (0x03, b"abc")])

        self.assertEqual(encoded, bytes.fromhex("0601010303616263"))
        self.assertEqual(decode_tlv8(encoded), {0x06: b"\x01", 0x03: b"abc"})

    def test_tlv8_reassembles_split_values(self):
        value = bytes(range(256))
        encoded = encode_tlv8([(0x05, value)])

        self.assertEqual(encoded[:2], bytes([0x05, 0xFF]))
        self.assertEqual(encoded[257:259], bytes([0x05, 0x01]))
        self.assertEqual(decode_tlv8(encoded)[0x05], value)

    def test_tlv8_truncated_value_raises(self):
        with self.assertRaises(TLV8Error):
            decode_tlv8(bytes.fromhex("0502aa"))


class PairVerifyConstantsTests(unittest.TestCase):
    def test_pairverify_tlv_constants_match_observed_fields(self):
        self.assertEqual(TLV_STATE, 0x06)
        self.assertEqual(TLV_PUBLIC_KEY, 0x03)
        self.assertEqual(TLV_ENCRYPTED_DATA, 0x05)
        self.assertEqual(TLV_APP_FLAGS, 0x19)

    def test_pairverify_hkdf_and_nonce_constants(self):
        self.assertEqual(PAIR_VERIFY_ECDH_SALT, b"Pair-Verify-ECDH-Salt")
        self.assertEqual(PAIR_VERIFY_ECDH_INFO, b"Pair-Verify-ECDH-Info")
        self.assertEqual(PAIR_VERIFY_ENCRYPT_SALT, b"Pair-Verify-Encrypt-Salt")
        self.assertEqual(PAIR_VERIFY_ENCRYPT_INFO, b"Pair-Verify-Encrypt-Info")
        self.assertEqual(PAIR_VERIFY_M2_NONCE, b"PV-Msg02")
        self.assertEqual(PAIR_VERIFY_M3_NONCE, b"PV-Msg03")

    def test_pairing_stream_info_labels(self):
        self.assertEqual(pairing_stream_info("main", client_to_server=True), b"ClientEncrypt-main")
        self.assertEqual(pairing_stream_info("main", client_to_server=False), b"ServerEncrypt-main")


if __name__ == "__main__":
    unittest.main()
