#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_core_sdk.py — Unit Tests cho toàn bộ package `core/` (Zalo App Core SDK).
Kiểm thử tính nhất quán, các Models, Enums, API wrappers, Login module và ZaloClient.
"""

import os
import json
import time
import unittest
from unittest.mock import MagicMock, patch

from core.client import ZaloClient
from core.login.client import ZaloLoginClient
from core.login.device import DeviceProfile
from core.login.session import SessionManager
from core.models.enums import ThreadType, Gender, MessageType, ReactionIcon
from core.models.user import UserProfile
from core.models.message import Message, Quote
from core.api.user import UserAPI
from core.api.message import MessageAPI
from core.api.group.api import GroupAPI
from core.utils.helpers import sign_params, parse_ttl_duration, utf16_len, extract_target_uid


class TestCoreSDK(unittest.TestCase):

    def setUp(self):
        self.session_path = "/root/zalo/fresh_session.json"

    def test_enums_and_models(self):
        # Gender
        self.assertEqual(Gender.to_display_string(0), "Nam")
        self.assertEqual(Gender.to_display_string(1), "Nữ")
        self.assertEqual(Gender.to_display_string(2), "Không công khai")

        # ReactionIcon
        self.assertEqual(ReactionIcon.from_str("heart"), "/-heart")
        self.assertEqual(ReactionIcon.from_str("like"), ":>")

        # Quote
        q = Quote(
            owner_uid=123456,
            owner_name="Tester",
            msg_text="Hello Zalo",
            msg_id=98765,
            cli_msg_id=54321,
            group_id=686355764
        )
        qd = q.to_dict()
        self.assertEqual(qd["ownerId"], 123456)
        self.assertEqual(qd["fromD"], "Tester")
        self.assertEqual(qd["msg"], "Hello Zalo")
        self.assertEqual(qd["gOwnerId"], 686355764)

        # UserProfile
        u = UserProfile.from_dict({
            "userId": 123456,
            "displayName": "Test User",
            "gender": 0,
            "isFr": 1
        })
        self.assertEqual(u.user_id, 123456)
        self.assertEqual(u.display_name, "Test User")
        self.assertTrue(u.is_friend)

    def test_utils(self):
        # TTL duration parser
        self.assertEqual(parse_ttl_duration("7d"), 7 * 86400)
        self.assertEqual(parse_ttl_duration("1d"), 86400)
        self.assertEqual(parse_ttl_duration("10s"), 10)
        self.assertEqual(parse_ttl_duration("0"), 0)

        # UTF-16 len
        self.assertEqual(utf16_len("Hello 👋"), 8)

        # Extract target UID
        self.assertEqual(extract_target_uid("999999"), 999999)
        self.assertEqual(extract_target_uid("@test", mentioned_uids=[111, 222], bot_uid=111), 222)

    def test_login_and_session_manager(self):
        self.assertTrue(os.path.isfile(self.session_path))
        sess = SessionManager.load(self.session_path)
        self.assertTrue(SessionManager.validate(sess))
        dk = SessionManager.extract_dk(sess)
        self.assertIsNotNone(dk)
        self.assertEqual(len(dk), 32)

        # DeviceProfile
        dp = DeviceProfile.default()
        self.assertEqual(dp.android_id, "ba1a2432a7ffd531")

    def test_client_integration(self):
        client = ZaloClient(session_path=self.session_path)
        self.assertEqual(client.uid, 463450795)
        self.assertIsNotNone(client.dk)
        self.assertIsNotNone(client.users)
        self.assertIsNotNone(client.messages)
        self.assertIsNotNone(client.groups)

        # Mock Socket for client APIs
        mock_socket = MagicMock()
        mock_socket.is_connected = True
        mock_socket.send_group_message.return_value = True
        mock_socket.send_1to1_message.return_value = True
        mock_socket.send_typing.return_value = True
        mock_socket.send_reaction.return_value = True
        mock_socket.pin_message.return_value = True
        mock_socket.unpin_message.return_value = True
        mock_socket.disband_group.return_value = True

        client.socket = mock_socket

        # Test message methods
        self.assertTrue(client.send_group_message(686355764, "Test Group"))
        mock_socket.send_group_message.assert_called()

        self.assertTrue(client.send_1to1_message(123456, "Test 1-1"))
        mock_socket.send_1to1_message.assert_called()

        self.assertTrue(client.send_reaction(686355764, 111, 222, "❤️"))
        mock_socket.send_reaction.assert_called()

        self.assertTrue(client.pin_message(686355764, "Ghim test"))
        mock_socket.pin_message.assert_called()

        self.assertTrue(client.unpin_message(686355764, 222, 111))
        mock_socket.unpin_message.assert_called()

        self.assertTrue(client.send_typing(686355764, is_group=True))
        mock_socket.send_typing.assert_called_with(target_id=686355764, is_group=True)

        self.assertTrue(client.disband_group(686355764))
        mock_socket.disband_group.assert_called()

        mock_socket.kick_member.return_value = True
        self.assertTrue(client.kick_member(686355764, [123456]))
        mock_socket.kick_member.assert_called_with(group_id=686355764, member_uids=[123456], is_block=False)

        mock_socket.add_member.return_value = True
        self.assertTrue(client.add_member(686355764, [123456]))
        mock_socket.add_member.assert_called_with(group_id=686355764, member_uids=[123456], is_invite=False)

        mock_socket.join_group.return_value = True
        res_join = client.join_group(686355764)
        self.assertTrue(res_join["success"])
        mock_socket.join_group.assert_called_with(group_id=686355764, source=1)

    def test_revamped_bot_commands(self):
        from main import generate_bot_response

        # 1. System commands
        resp_help = generate_bot_response("/help", prefix="/")
        self.assertIn("DANH SÁCH LỆNH BOT", resp_help)
        self.assertIn("avatar", resp_help)
        self.assertIn("uptime", resp_help)
        self.assertIn("grid", resp_help)

        resp_uptime = generate_bot_response("/uptime", prefix="/", start_time=time.time() - 3665, msg_count=12)
        self.assertIn("THỐNG KÊ HOẠT ĐỘNG BOT", resp_uptime)
        self.assertIn("1 giờ 1 phút 5 giây", resp_uptime)
        self.assertIn("12 tin nhắn", resp_uptime)

        resp_time = generate_bot_response("/time", prefix="/")
        self.assertIn("Thời gian hệ thống", resp_time)

        resp_botinfo = generate_bot_response("/botinfo", prefix="/", bot_uid=463450795)
        self.assertIn("ZALO REALTIME SOCKET BOT", resp_botinfo)
        self.assertIn("463450795", resp_botinfo)

        # 2. Utilities & Group Commands
        resp_echo = generate_bot_response("/echo Xin chào thế giới", prefix="/")
        self.assertEqual(resp_echo, "Xin chào thế giới")

        resp_calc = generate_bot_response("/calc (10 + 20) * 3", prefix="/")
        self.assertIn("90", resp_calc)

        resp_grid = generate_bot_response("/grid https://zalo.me/g/krgx195dxdbjx1bm2fbd", prefix="/")
        # /grid now shows full group preview: name, link, join button
        self.assertTrue(
            "GROUP ID" in resp_grid or "NHÓM ZALO" in resp_grid or "THAM GIA" in resp_grid,
            f"Expected group info in /grid response, got: {resp_grid}"
        )
        self.assertIn("krgx195dxdbjx1bm2fbd", resp_grid)


        resp_unpin = generate_bot_response("/unpin", prefix="/")
        self.assertIn("__ACTION_UNPIN__", resp_unpin)

        resp_recall = generate_bot_response("/recall 123456", prefix="/")
        self.assertIn("__ACTION_RECALL:", resp_recall)
        self.assertIn("thu hồi", resp_recall)

        resp_delete = generate_bot_response("/delete 123456", prefix="/")
        self.assertIn("__ACTION_DELETE:", resp_delete)
        self.assertIn("Đã xóa tin nhắn", resp_delete)

        # /delete onlyme chỉ xóa phía mình
        resp_delete_me = generate_bot_response("/delete onlyme 123456", prefix="/")
        self.assertIn("__ACTION_DELETE:", resp_delete_me)
        self.assertIn("xóa tin nhắn khỏi cuộc trò chuyện của bạn", resp_delete_me)


if __name__ == '__main__':
    unittest.main(verbosity=2)

