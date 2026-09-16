#!/usr/bin/env python3
"""
test_photo.py — Kiểm tra chức năng gửi tin nhắn hình ảnh (photo attachments) và lệnh /img.
"""

import unittest
from unittest.mock import MagicMock
from core.socket.protocol import (
    build_photo_attach,
    build_d3_payload_group,
    build_d3_payload_1to1,
    build_photo_message_packet
)
from core.utils.helpers import resolve_photo_metadata
from core.client import ZaloClient
from main import generate_bot_response


class TestPhotoMessage(unittest.TestCase):
    def test_build_photo_attach(self):
        url = "https://example.com/image.png"
        att = build_photo_attach(url, width=1280, height=720, total_size=54321, title="Ảnh đẹp")
        self.assertEqual(att["url"], url)
        self.assertEqual(att["href"], url)
        self.assertEqual(att["thumb"], url)
        self.assertEqual(att["hdUrl"], url)
        self.assertEqual(att["width"], 1280)
        self.assertEqual(att["height"], 720)
        self.assertEqual(att["totalSize"], 54321)
        self.assertEqual(att["title"], "Ảnh đẹp")

    def test_build_d3_payload_with_attach(self):
        att = build_photo_attach("https://example.com/test.jpg", 800, 600, 12345)
        d3_group = build_d3_payload_group("Caption nhóm", attach=att)
        self.assertIn(b"https://example.com/test.jpg", d3_group)
        self.assertIn(b"Caption nh\xc3\xb3m", d3_group)

        fake_cryptkey = b"\x00" * 16
        d3_1to1 = build_d3_payload_1to1("Caption 1-1", cryptkey=fake_cryptkey, attach=att)
        self.assertIn(b"https://example.com/test.jpg", d3_1to1)

    def test_build_photo_binary_payload(self):
        from core.socket.protocol import (
            build_photo_binary_payload,
            SUB_PHOTO_MSG,
            SUB_PHOTO_ATTACH_MSG
        )
        payload = build_photo_binary_payload(
            url="https://photo-stal-32.zdn.vn/test.jpg",
            title="Tiêu Đề Ảnh",
            description="Mô Tả Ảnh Chi Tiết",
            width=800,
            height=600,
            total_size=12345,
            sub_type=SUB_PHOTO_MSG
        )
        self.assertEqual(SUB_PHOTO_MSG, 32)
        self.assertEqual(SUB_PHOTO_ATTACH_MSG, 37)
        # Header starts with [type=32 (2B LE)][blocks=0 (1B)]
        self.assertEqual(payload[:3], b'\x20\x00\x00')
        self.assertIn("Tiêu Đề Ảnh".encode('utf-8'), payload)
        self.assertIn("Mô Tả Ảnh Chi Tiết".encode('utf-8'), payload)
        self.assertIn(b"https://photo-stal-32.zdn.vn/test.jpg", payload)
        self.assertIn(b'"width":800', payload)

        # Test sub 37 (API / Attachment)
        payload37 = build_photo_binary_payload(
            url="https://photo-stal-32.zdn.vn/test.jpg",
            title="Tiêu Đề 37",
            sub_type=37,
            is_original=True,
            total_size=54321
        )
        self.assertEqual(payload37[:3], b'\x25\x00\x00')
        self.assertIn("Tiêu Đề 37".encode('utf-8'), payload37)
        self.assertIn(b'"is_original":1', payload37)
        self.assertIn(b'"hdSize":54321', payload37)

    def test_build_photo_message_packet(self):
        pkt_group = build_photo_message_packet(
            uid=12345,
            target_id=67890,
            photo_url="https://example.com/pic.jpg",
            seq=1,
            ck_val=100,
            cmsg_id=200,
            is_group=True,
            caption="Ảnh nhóm",
            native=True
        )
        self.assertIsInstance(pkt_group, bytes)
        self.assertGreater(len(pkt_group), 32)

        # Test fallback non-native mode
        pkt_fallback = build_photo_message_packet(
            uid=12345,
            target_id=67890,
            photo_url="https://example.com/pic.jpg",
            seq=1,
            ck_val=100,
            cmsg_id=200,
            is_group=True,
            caption="Ảnh nhóm",
            native=False
        )
        self.assertIsInstance(pkt_fallback, bytes)
        self.assertGreater(len(pkt_fallback), 32)

        fake_cryptkey = b"\x00" * 16
        pkt_1to1 = build_photo_message_packet(
            uid=12345,
            target_id=67890,
            photo_url="https://example.com/pic.jpg",
            seq=1,
            ck_val=100,
            cmsg_id=200,
            is_group=False,
            caption="Ảnh 1-1",
            cryptkey=fake_cryptkey,
            native=True
        )
        self.assertIsInstance(pkt_1to1, bytes)
        self.assertGreater(len(pkt_1to1), 32)

    def test_resolve_photo_metadata_fallback(self):
        url, w, h, sz = resolve_photo_metadata("https://invalid-non-existent-domain-1234567.com/pic.jpg")
        self.assertEqual(url, "https://invalid-non-existent-domain-1234567.com/pic.jpg")
        self.assertEqual(w, 800)
        self.assertEqual(h, 600)
        self.assertEqual(sz, 0)

    def test_bot_img_command(self):
        # Lệnh /img với link
        resp = generate_bot_response(
            msg_txt="/img https://picsum.photos/400/300 Ảnh test",
            prefix="/",
            from_uid=123,
            group_id=456
        )
        self.assertIsNotNone(resp)
        self.assertIn("__ACTION_SEND_PHOTO:", resp)
        self.assertIn("https://picsum.photos/400/300", resp)
        self.assertIn("Ảnh test", resp)

        # Lệnh /img không đối số -> hướng dẫn
        resp_guide = generate_bot_response(
            msg_txt="/img",
            prefix="/",
            from_uid=123,
            group_id=456
        )
        self.assertIn("[HƯỚNG DẪN LỆNH /img]", resp_guide)

    def test_client_send_photo(self):
        mock_sock = MagicMock()
        mock_sock.is_connected = True
        mock_sock.send_photo.return_value = True

        client = ZaloClient(session={"uid": 12345, "dk_hex": "00"*32})
        client.socket = mock_sock

        ok = client.send_photo(67890, "https://example.com/photo.jpg", caption="Demo")
        self.assertTrue(ok)
        mock_sock.send_photo.assert_called_once()


if __name__ == '__main__':
    unittest.main()
