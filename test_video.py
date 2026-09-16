#!/usr/bin/env python3
"""
test_video.py — Kiểm tra chức năng gửi tin nhắn video (native & attachment) và lệnh /video.
"""

import unittest
from unittest.mock import MagicMock
from core.socket.protocol import (
    build_video_attach,
    build_video_binary_payload,
    build_video_message_packet,
    SUB_PHOTO_MSG,
    SUB_VIDEO_MSG
)
from core.utils.helpers import resolve_video_metadata
from core.client import ZaloClient
from main import generate_bot_response


class TestVideoMessage(unittest.TestCase):
    def test_build_video_attach(self):
        url = "https://example.com/video.mp4"
        att = build_video_attach(url, width=1920, height=1080, duration=15, total_size=99999, title="Video Demo")
        self.assertEqual(att["url"], url)
        self.assertEqual(att["href"], url)
        self.assertEqual(att["tType"], 4)
        self.assertEqual(att["width"], 1920)
        self.assertEqual(att["height"], 1080)
        self.assertEqual(att["duration"], 15)
        self.assertEqual(att["totalSize"], 99999)
        self.assertEqual(att["title"], "Video Demo")

    def test_build_video_binary_payload(self):
        payload = build_video_binary_payload(
            url="https://video-stal-48.dlmd.me/test_video.mp4",
            title="Video Tiêu Đề",
            description="Mô tả video",
            width=1280,
            height=720,
            duration_ms=12000,
            total_size=2989225
        )
        self.assertIsInstance(payload, bytes)
        # Header starts with [type=44 (0x2C) (2B LE)][blocks=0 (1B)]
        self.assertEqual(payload[:3], b'\x2c\x00\x00')
        self.assertIn("Video Tiêu Đề".encode('utf-8'), payload)
        self.assertIn(b"https://video-stal-48.dlmd.me/test_video.mp4", payload)
        self.assertIn(b'"duration":12000', payload)
        self.assertIn(b'"video_width":1280', payload)
        self.assertIn(b'"fileSize":2989225', payload)

    def test_build_video_message_packet(self):
        pkt_group = build_video_message_packet(
            uid=12345,
            target_id=67890,
            video_url="https://example.com/video.mp4",
            seq=1,
            ck_val=100,
            cmsg_id=200,
            is_group=True,
            caption="Video nhóm",
            duration_ms=5000,
            native=True
        )
        self.assertIsInstance(pkt_group, bytes)
        self.assertGreater(len(pkt_group), 32)

        # Non-native fallback
        pkt_fallback = build_video_message_packet(
            uid=12345,
            target_id=67890,
            video_url="https://example.com/video.mp4",
            seq=1,
            ck_val=100,
            cmsg_id=200,
            is_group=True,
            caption="Video nhóm fallback",
            duration_ms=5000,
            native=False
        )
        self.assertIsInstance(pkt_fallback, bytes)
        self.assertGreater(len(pkt_fallback), 32)

    def test_resolve_video_metadata_fallback(self):
        url, w, h, dur, sz = resolve_video_metadata("https://invalid-non-existent-domain-1234567.com/vid.mp4")
        self.assertEqual(url, "https://invalid-non-existent-domain-1234567.com/vid.mp4")
        self.assertEqual(w, 1280)
        self.assertEqual(h, 720)
        self.assertEqual(dur, 10000)
        self.assertEqual(sz, 0)

    def test_bot_video_command(self):
        # 1 URL format
        resp = generate_bot_response(
            msg_txt="/video https://example.com/test.mp4 Clip ngắn",
            prefix="/",
            from_uid=123,
            group_id=456
        )
        self.assertIsNotNone(resp)
        self.assertIn("__ACTION_SEND_VIDEO:", resp)
        self.assertIn("https://example.com/test.mp4", resp)
        self.assertIn("Clip ngắn", resp)

        # 2 URLs format: /vid <url thumb> <url vid> [caption]
        resp2 = generate_bot_response(
            msg_txt="/vid https://example.com/thumb.jpg https://example.com/test.mp4 Clip hai link",
            prefix="/",
            from_uid=123,
            group_id=456
        )
        self.assertIsNotNone(resp2)
        self.assertIn("__ACTION_SEND_VIDEO:", resp2)
        self.assertIn('"url": "https://example.com/test.mp4"', resp2)
        self.assertIn('"thumb_url": "https://example.com/thumb.jpg"', resp2)
        self.assertIn("Clip hai link", resp2)

    def test_bot_doodle_and_image_thumb_command(self):
        # Image with thumb: /img <url thumb> <url img> [caption]
        resp_img = generate_bot_response(
            msg_txt="/img https://example.com/thumb.png https://example.com/full.png Anh demo",
            prefix="/",
            from_uid=123,
            group_id=456
        )
        self.assertIsNotNone(resp_img)
        self.assertIn("__ACTION_SEND_PHOTO:", resp_img)
        self.assertIn('"url": "https://example.com/full.png"', resp_img)
        self.assertIn('"thumb_url": "https://example.com/thumb.png"', resp_img)

        # Doodle with thumb: /doodle <url thumb> <url doodle> [caption]
        resp_doodle = generate_bot_response(
            msg_txt="/doodle https://example.com/thumb.png https://example.com/draw.png Hinh ve",
            prefix="/",
            from_uid=123,
            group_id=456
        )
        self.assertIsNotNone(resp_doodle)
        self.assertIn("__ACTION_SEND_DOODLE:", resp_doodle)
        self.assertIn('"url": "https://example.com/draw.png"', resp_doodle)
        self.assertIn('"thumb_url": "https://example.com/thumb.png"', resp_doodle)

    def test_client_send_video(self):
        mock_sock = MagicMock()
        mock_sock.is_connected = True
        mock_sock.send_video.return_value = True

        client = ZaloClient(session={"uid": 12345, "dk_hex": "00"*32})
        client.socket = mock_sock

        ok = client.send_video(67890, "https://example.com/test.mp4", thumb_url="https://example.com/thumb.jpg", caption="Demo Video")
        self.assertTrue(ok)
        mock_sock.send_video.assert_called_once()

    def test_client_send_doodle(self):
        mock_sock = MagicMock()
        mock_sock.is_connected = True
        mock_sock.send_photo.return_value = True

        client = ZaloClient(session={"uid": 12345, "dk_hex": "00"*32})
        client.socket = mock_sock

        ok = client.send_doodle(67890, "https://example.com/doodle.png", thumb_url="https://example.com/thumb.png", caption="Demo Doodle")
        self.assertTrue(ok)
        mock_sock.send_photo.assert_called_once()
        call_kwargs = mock_sock.send_photo.call_args[1]
        self.assertEqual(call_kwargs.get("sub_type"), 37)
        self.assertEqual(call_kwargs.get("thumb_url"), "https://example.com/thumb.png")


if __name__ == '__main__':
    unittest.main()
