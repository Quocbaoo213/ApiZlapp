#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_socket_client.py — Unit & Integration Test cho Socket Client & Bot Engine.
Kiểm thử toàn bộ các cơ chế: Quản lý Sequence, Sinh Packet gửi, Xử lý Anti-Loop, Rate Limiter và Bot Commands.
"""

import json
import os
import unittest
from socket_client import ZaloSocketClient
from main import ZaloBotEngine, load_session

class TestZaloSocketAndBot(unittest.TestCase):

    def setUp(self):
        self.uid = 463450795
        self.group_id = 686355764
        self.dk = bytes.fromhex("6f383957d70cb9394adcd40b7f74854d35bc6615711c5b6800014985276db84c")
        self.cryptkey = bytes.fromhex("36b7c3dad8368c40dfce3b7adcca91ab")
        self.state_file = "/root/zalo/scratch/test_state.json"
        os.makedirs("/root/zalo/scratch", exist_ok=True)

        self.client = ZaloSocketClient(
            uid=self.uid,
            dk=self.dk,
            cryptkey=self.cryptkey,
            frame0_path="/root/zalo/frame0.bin",
            state_file=self.state_file
        )

    def tearDown(self):
        if os.path.isfile(self.state_file):
            try:
                os.remove(self.state_file)
            except Exception:
                pass

    def test_01_monotonic_counters(self):
        """Kiểm tra tính tăng đơn điệu của cmsg_id, ck_val và giảm dần của seq."""
        seq1 = self.client._next_seq()
        seq2 = self.client._next_seq()
        self.assertEqual(seq2, seq1 - 1)

        cmsg1 = self.client._next_cmsg_id()
        cmsg2 = self.client._next_cmsg_id()
        self.assertEqual(cmsg2, cmsg1 + 1)

        ck1 = self.client._next_ck_val()
        ck2 = self.client._next_ck_val()
        self.assertEqual(ck2, ck1 + 1)

        self.client._save_state(force=True)
        # Kiểm tra ghi state ra file
        self.assertTrue(os.path.isfile(self.state_file))
        with open(self.state_file) as f:
            s = json.load(f)
            self.assertEqual(s['cmsg_id'], cmsg2)

    def test_02_bot_engine_anti_loop(self):
        """Kiểm tra cơ chế Anti-Loop (bỏ qua tin nhắn từ chính mình)."""
        bot = ZaloBotEngine(self.client, prefix="/")
        replies = []
        bot._process_command = lambda *args: replies.append(args)

        # Giả lập tin nhắn từ chính Bot UID
        parsed_self = {
            'cmd': 1867,
            'sub': 0,
            'parsed_data': {
                'messages': [
                    {'from_uid': self.uid, 'to_group': self.group_id, 'content': '/ping'}
                ]
            }
        }
        bot.handle_message(parsed_self)
        self.assertEqual(len(replies), 0)  # Phải bị chặn

        # Giả lập tin nhắn từ UID khác
        parsed_other = {
            'cmd': 1867,
            'sub': 0,
            'parsed_data': {
                'messages': [
                    {'from_uid': 999999999, 'to_group': self.group_id, 'content': '/ping'}
                ]
            }
        }
        bot.handle_message(parsed_other)
        self.assertEqual(len(replies), 1)

    def test_03_bot_command_routing(self):
        """Kiểm tra xử lý logic các lệnh Bot: /ping, /time, /calc, /echo, /uid, /help."""
        bot = ZaloBotEngine(self.client, prefix="/", rate_limit_sec=0.0)
        sent_messages = []
        self.client.send_group_message = lambda gid, txt, **kwargs: sent_messages.append((gid, txt))
        self.client.send_typing = lambda *args, **kwargs: None

        # /ping
        bot._process_command(self.group_id, 999, "UserA", "/ping", {})
        self.assertIn("Pong", sent_messages[-1][1])

        # /calc
        bot._process_command(self.group_id, 999, "UserA", "/calc (25 + 5) * 4", {})
        self.assertIn("120", sent_messages[-1][1])

        # /echo
        bot._process_command(self.group_id, 999, "UserA", "/echo Test Zalo Message", {})
        self.assertIn("Test Zalo Message", sent_messages[-1][1])

        # /help
        bot._process_command(self.group_id, 999, "UserA", "/help", {})
        self.assertIn("DANH SÁCH LỆNH BOT", sent_messages[-1][1])

        # /uid
        bot._process_command(self.group_id, 999, "UserA", "/uid", {})
        self.assertIn(str(self.uid), sent_messages[-1][1])

    def test_04_session_loader(self):
        """Kiểm tra nạp session từ file fresh_session.json."""
        s = load_session("/root/zalo/fresh_session.json")
        self.assertEqual(s['uid'], 463450795)
        self.assertEqual(len(s['dk']), 32)
        self.assertIsNotNone(s.get('cryptkey'))
        self.assertIsNotNone(s.get('session_key'))
        self.assertIsNotNone(s.get('ksid'))

    def test_05_dynamic_client_configuration(self):
        """Kiểm tra khởi tạo ZaloSocketClient với dynamic PROV credentials."""
        client = ZaloSocketClient(
            uid=self.uid,
            dk=self.dk,
            session_key="test_sk",
            ksid="test_ksid",
            server_pubkey_b64="wT8wgnjOcojhsXxJPuSTbLwwIk5AodMRHENKDqqqNhg=",
            state_file=self.state_file
        )
        self.assertEqual(client.session_key, "test_sk")
        self.assertEqual(client.ksid, "test_ksid")
        self.assertEqual(client.ping_interval, 10.0)

    def test_06_bot_ttl_and_actions(self):
        """Kiểm tra xử lý lệnh /setttl và /ttl cùng action gọi set_conversation_ttl."""
        bot = ZaloBotEngine(self.client, prefix="/", rate_limit_sec=0.0)
        ttl_calls = []
        self.client.set_conversation_ttl = lambda dest, sec, is_group: ttl_calls.append((dest, sec, is_group))
        sent_messages = []
        self.client.send_group_message = lambda gid, txt, **kwargs: sent_messages.append((gid, txt))
        self.client.send_typing = lambda *args, **kwargs: None

        # /setttl 30s
        bot._process_command(self.group_id, 999, "UserA", "/setttl 30s", {})
        self.assertEqual(bot.ttl, 30)
        self.assertIn("30 giây", sent_messages[-1][1])

        # /setttl 0 (Tắt)
        bot._process_command(self.group_id, 999, "UserA", "/setttl 0", {})
        self.assertEqual(bot.ttl, 0)
        self.assertIn("Đã tắt", sent_messages[-1][1])

        # /ttl
        bot._process_command(self.group_id, 999, "UserA", "/ttl", {})
        self.assertIn("TTL (Time-To-Live)", sent_messages[-1][1])

    def test_07_mention_and_tag_reply(self):
        """Kiểm tra auto-prefix khi tag bot và tự động @tag người gửi trong group reply."""
        bot = ZaloBotEngine(self.client, prefix="/", rate_limit_sec=0.0)
        sent_messages = []
        self.client.send_group_message = lambda gid, txt, **kwargs: sent_messages.append((gid, txt))
        self.client.send_typing = lambda *args, **kwargs: None

        # Giả lập tin nhắn có mention bot UID: "@Bot ping"
        ev = {
            'is_group': True,
            'to_group': self.group_id,
            'from_uid': 888,
            'from_name': 'NguyenVanA',
            'content': '@Bot ping',
            'mentions': [{'uid': self.uid, 'pos': 0, 'len': 4, 'type': 0}]
        }
        bot.handle_message({
            'cmd': 1867,
            'sub': 0,
            'parsed_data': {'messages': [ev]}
        })
        self.assertTrue(len(sent_messages) > 0)
        self.assertIn("@NguyenVanA", sent_messages[-1][1])
        self.assertIn("Pong", sent_messages[-1][1])

    def test_08_helper_functions(self):
        """Kiểm tra các hàm tiện ích: utf16_len, parse_ttl_duration, clean_message_text, build_quote_object."""
        from main import utf16_len, parse_ttl_duration, clean_message_text, build_quote_object, build_quote_from_event

        # UTF-16 len
        self.assertEqual(utf16_len("Hello"), 5)
        self.assertEqual(utf16_len("👋"), 2)  # Emoji surrogate pair = 2 UTF-16 units

        # parse_ttl_duration
        self.assertEqual(parse_ttl_duration("7d"), 604800)
        self.assertEqual(parse_ttl_duration("1d"), 86400)
        self.assertEqual(parse_ttl_duration("1h"), 3600)
        self.assertEqual(parse_ttl_duration("30s"), 30)
        self.assertEqual(parse_ttl_duration("0"), 0)

        # clean_message_text
        clean, is_bot, uids = clean_message_text("@Bot ping", [{'uid': self.uid, 'pos': 0, 'len': 4}], bot_uid=self.uid)
        self.assertTrue(is_bot)
        self.assertEqual(clean, "ping")

        # build_quote_object
        q = build_quote_object(12345, 67890, 999, "UserA", "Hello World", group_id=self.group_id)
        self.assertEqual(q['globalMsgId'], 12345)
        self.assertEqual(q['cliMsgId'], 67890)
        self.assertEqual(q['ownerId'], 999)
        self.assertEqual(q['gOwnerId'], self.group_id)
        self.assertEqual(q['fromD'], "UserA")
        self.assertEqual(q['msg'], "Hello World")

    def test_09_keyword_and_fixed_reply(self):
        """Kiểm tra phản hồi theo từ khóa và fixed reply."""
        from main import generate_bot_response

        # Keyword hello
        resp = generate_bot_response("hello", prefix="/", is_bot_mentioned=True)
        self.assertIn("Hello! Rất vui được trò chuyện", resp)

        # Fixed reply
        resp_fixed = generate_bot_response("bất kỳ", prefix=None, fixed_reply="Auto-reply cố định")
        self.assertEqual(resp_fixed, "Auto-reply cố định")

    def test_10_rate_limiter(self):
        """Kiểm tra per-user rate limiter 1.2s."""
        bot = ZaloBotEngine(self.client, prefix="/", rate_limit_sec=1.2)
        sent_messages = []
        self.client.send_group_message = lambda gid, txt, **kwargs: sent_messages.append((gid, txt))
        self.client.send_typing = lambda *args, **kwargs: None

        # Lần 1: Cho phép
        bot._process_command(self.group_id, 999, "UserA", "/ping", {})
        self.assertEqual(len(sent_messages), 1)

        # Lần 2 (ngay lập tức): Bị chặn bởi rate limit
        bot._process_command(self.group_id, 999, "UserA", "/ping", {})
        self.assertEqual(len(sent_messages), 1)

if __name__ == '__main__':
    unittest.main(verbosity=2)
