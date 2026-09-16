#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_crypto.py — Unit Test toàn diện cho Module crypto.py
Kiểm thử tính chính xác của toàn bộ các hàm mật mã học dựa trên test vectors chuẩn và traffic thực tế.
"""

import base64
import json
import unittest
from crypto import (
    key32, password_hash, compute_sig,
    encrypt_http_data, decrypt_http_data,
    encrypt_aes_gcm, decrypt_aes_gcm,
    encrypt_e2ee_cbc, decrypt_e2ee_cbc,
    xor_d3, x25519, x25519_keypair, x25519_shared_secret,
    gzip_compress, gzip_decompress,
    DEFAULT_XK, DEFAULT_BASE_KEY, DEFAULT_SECRET
)

class TestZaloCrypto(unittest.TestCase):

    def setUp(self):
        # Dữ liệu thực tế từ HAR
        self.real_zcid = "75BBAA2486F8843614C94034EF9D7C1F90BF780A1AAB94D80726CBCB02533A554A29B2526E6BBEC721CC041C63F6A361400973B7D0988F9112BDCFF9B5A001AAE4D92C55DBC81593C2DAB614C5C188B6"
        self.phone = "+84993903236"
        self.password = "141722789@Ss"
        self.api_key = "0be3747aacc670a51a83230bcfe80173"

    def test_01_key32_derivation(self):
        """Kiểm tra trích xuất khóa 32 bytes từ ZCID."""
        k = key32(self.real_zcid)
        self.assertEqual(len(k), 32)
        # Kiểm tra thuật toán chẵn
        part1 = "".join(self.real_zcid[i] for i in range(0, 32, 2))
        part2 = "".join(self.real_zcid[len(self.real_zcid) - 1 - 2 * i] for i in range(16))
        self.assertEqual(k, (part1 + part2).encode('latin1'))

    def test_02_password_hash(self):
        """Kiểm tra băm mật khẩu AES-128-ECB."""
        h = password_hash(self.phone, self.password)
        self.assertIsInstance(h, str)
        self.assertEqual(len(h), 32)  # 16 bytes = 32 hex chars

    def test_03_signature_calculation(self):
        """Kiểm tra tính chữ ký MD5."""
        data_hex = "ABCD1234EF"
        sig = compute_sig(data_hex, self.api_key)
        self.assertEqual(len(sig), 32)
        # Đối chiếu công thức
        expected = "8cd0fc6c58e88e78d62db52f0e093367"
        import hashlib
        calc = hashlib.md5(f"api_key={self.api_key}data={data_hex}{expected}".encode('utf-8')).hexdigest()
        self.assertEqual(sig, calc)

    def test_04_http_data_encrypt_decrypt_roundtrip(self):
        """Kiểm tra mã hóa và giải mã HTTP payload (AES-CBC)."""
        params = {
            "phone_num": "+84993903236",
            "device_identifier": "3000.SSZ-xCSL8Q0CiyhOwZice5B-qzUXEspfLhE4sxWzRw02e8lG-MLpi5cnn9dwONQtNVh2dF4aTBLHyyMHCpOp.1",
            "ts": 1789354112
        }
        enc_hex = encrypt_http_data(params, self.real_zcid)
        self.assertIsInstance(enc_hex, str)
        dec_params = decrypt_http_data(enc_hex, self.real_zcid)
        self.assertEqual(params, dec_params)

    def test_05_aes_256_gcm_socket_frame(self):
        """Kiểm tra mã hóa và giải mã Outer Socket Frame (AES-256-GCM)."""
        dk = bytes.fromhex("6f383957d70cb9394adcd40b7f74854d35bc6615711c5b6800014985276db84c")
        inner_packet = b"\x01\x02\x03\x04\x05\x06Hello Zalo Socket Frame"
        
        # Mã hóa
        encrypted_frame = encrypt_aes_gcm(inner_packet, dk)
        self.assertEqual(len(encrypted_frame), len(inner_packet) + 16 + 12)  # Plain + 16B Tag + 12B IV

        # Giải mã
        decrypted = decrypt_aes_gcm(encrypted_frame, dk)
        self.assertEqual(decrypted, inner_packet)

        # Kiểm tra phát hiện can thiệp dữ liệu (Tamper Resistance)
        tampered = bytearray(encrypted_frame)
        tampered[0] ^= 0xFF
        with self.assertRaises(Exception):
            decrypt_aes_gcm(bytes(tampered), dk)

    def test_06_e2ee_cbc_message(self):
        """Kiểm tra mã hóa E2EE tin nhắn 1-1 (AES-128-CBC)."""
        cryptkey = base64.b64decode("NrfD2tg2jEDfzjt63crRqw==")
        text = "Bản tin bí mật E2EE end-to-end encryption".encode('utf-8')

        ct, iv = encrypt_e2ee_cbc(text, cryptkey)
        self.assertEqual(len(iv), 16)
        self.assertEqual(len(ct) % 16, 0)

        decrypted = decrypt_e2ee_cbc(ct, cryptkey, iv)
        self.assertEqual(decrypted, text)

    def test_07_xor_d3_masking(self):
        """Kiểm tra tính đối xứng của phép toán XOR D3."""
        payload = b"Sample JSON payload for D3 message encoding and decoding"
        masked = xor_d3(payload, DEFAULT_XK)
        self.assertNotEqual(masked, payload)
        unmasked = xor_d3(masked, DEFAULT_XK)
        self.assertEqual(unmasked, payload)

    def test_08_x25519_ecdh_rfc7748(self):
        """Kiểm tra X25519 ECDH theo RFC 7748 và trao đổi khóa Alice-Bob."""
        # Test vector RFC 7748
        scalar = bytes.fromhex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4')
        u_coord = bytes.fromhex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c')
        expected = bytes.fromhex('c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552')
        self.assertEqual(x25519(scalar, u_coord), expected)

        # Alice và Bob trao đổi khóa
        alice_priv, alice_pub = x25519_keypair()
        bob_priv, bob_pub = x25519_keypair()

        shared_alice = x25519_shared_secret(alice_priv, bob_pub)
        shared_bob = x25519_shared_secret(bob_priv, alice_pub)
        self.assertEqual(shared_alice, shared_bob)
        self.assertEqual(len(shared_alice), 32)

    def test_09_gzip_compression(self):
        """Kiểm tra nén và giải nén GZIP CMD 1867."""
        original_json = json.dumps({"e": 0, "msg": [{"text": {"msg": "Chào bạn"}}]}, ensure_ascii=False).encode('utf-8')
        compressed = gzip_compress(original_json)
        self.assertTrue(compressed.startswith(b"\x1f\x8b"))
        decompressed = gzip_decompress(compressed)
        self.assertEqual(decompressed, original_json)

if __name__ == '__main__':
    unittest.main(verbosity=2)
