#!/usr/bin/env python3
"""
test_group_interaction.py — Unit tests cho các tương tác Socket-Native (Reaction, Ghim tin nhắn, Giải tán nhóm).
"""

import unittest
from unittest.mock import MagicMock, patch
import json
import time

from core.models.enums import ReactionIcon
from core.api.group.api import GroupAPI
from protocol import (
    build_reaction_packet, build_pin_topic_packet,
    build_unpin_topic_packet, build_disband_group_packet
)
from main import generate_bot_response, ZaloBotEngine


class TestGroupInteraction(unittest.TestCase):

    def test_reaction_icon_mapping(self):
        self.assertEqual(ReactionIcon.from_str("heart"), "/-heart")
        self.assertEqual(ReactionIcon.from_str("tim"), "/-heart")
        self.assertEqual(ReactionIcon.from_str("like"), ":>")
        self.assertEqual(ReactionIcon.from_str("thich"), ":>")
        self.assertEqual(ReactionIcon.from_str("haha"), ":-D")
        self.assertEqual(ReactionIcon.from_str("wow"), ":-O")
        self.assertEqual(ReactionIcon.from_str("cry"), ":-((")
        self.assertEqual(ReactionIcon.from_str("angry"), ":-t")
        self.assertEqual(ReactionIcon.from_str("🔥"), "🔥")

    def test_build_reaction_packet(self):
        pkt = build_reaction_packet(
            uid=463450795,
            target_id=686355764,
            cli_msg_id=1789382931139,
            global_msg_id=8262679528325,
            icon="❤️",
            is_group=True,
            seq=-100
        )
        self.assertTrue(len(pkt) > 18)
        import struct
        ck, bb, ty, seq, uid, ver, cmd, sub = struct.unpack('<IBBiIBHB', pkt[:18])
        self.assertEqual(cmd, 1785)
        self.assertEqual(sub, 0)
        self.assertEqual(uid, 463450795)

    def test_build_pin_and_unpin_packets(self):
        pin_pkt = build_pin_topic_packet(
            uid=463450795,
            group_id=692675055,
            global_msg_id=8262679528325,
            seq=-100
        )
        self.assertTrue(len(pin_pkt) > 18)

        unpin_pkt = build_unpin_topic_packet(
            uid=463450795,
            group_id=692675055,
            global_msg_id=8262679528325,
            seq=-100
        )
        self.assertTrue(len(unpin_pkt) > 18)

    def test_build_disband_packet(self):
        disband_pkt = build_disband_group_packet(
            uid=463450795,
            group_id=700756094,
            seq=-100
        )
        self.assertTrue(len(disband_pkt) > 18)

    def test_send_reaction_socket(self):
        mock_sock = MagicMock()
        mock_sock.is_connected = True
        mock_sock.send_reaction.return_value = True
        group_api = GroupAPI(socket_client=mock_sock)
        res = group_api.send_reaction(target_id=686355764, cli_msg_id=1789382931139, global_msg_id=8262679528325, icon="❤️", is_group=True)
        self.assertTrue(res)
        mock_sock.send_reaction.assert_called_once()

    def test_pin_message_socket(self):
        mock_sock = MagicMock()
        mock_sock.is_connected = True
        mock_sock.pin_message.return_value = True
        group_api = GroupAPI(socket_client=mock_sock)
        res = group_api.pin_message(group_id=692675055, title="Uhshs", cli_msg_id=1789382920790)
        self.assertTrue(res)
        mock_sock.pin_message.assert_called_once()

    def test_disband_group_socket(self):
        mock_sock = MagicMock()
        mock_sock.is_connected = True
        mock_sock.disband_group.return_value = True
        group_api = GroupAPI(socket_client=mock_sock)
        res = group_api.disband_group(group_id=700756094)
        self.assertTrue(res)
        mock_sock.disband_group.assert_called_once()

    def test_leave_group_socket(self):
        mock_sock = MagicMock()
        mock_sock.is_connected = True
        mock_sock.leave_group.return_value = True
        group_api = GroupAPI(socket_client=mock_sock)
        res = group_api.leave_group(group_id=700756094, silent=True, block_readd=True)
        self.assertTrue(res)
        mock_sock.leave_group.assert_called_with(
            group_id=700756094,
            new_owner_id=0,
            silent=True,
            block_readd=True,
            wait_response=True,
            timeout=5.0
        )

    def test_kick_and_add_member_socket(self):
        mock_sock = MagicMock()
        mock_sock.is_connected = True
        mock_sock.kick_member.return_value = True
        mock_sock.add_member.return_value = True
        group_api = GroupAPI(socket_client=mock_sock)

        # Kick
        res_kick = group_api.kick_member(group_id=700756094, member_uids=[123456], is_block=False)
        self.assertTrue(res_kick)
        mock_sock.kick_member.assert_called_with(group_id=700756094, member_uids=[123456], is_block=False)

        # Ban (is_block=True)
        res_ban = group_api.ban(700756094, [123456])
        self.assertTrue(res_ban)
        mock_sock.kick_member.assert_called_with(group_id=700756094, member_uids=[123456], is_block=True)

        # Add
        res_add = group_api.add_member(group_id=700756094, member_uids=[123456], is_invite=False)
        self.assertTrue(res_add)
        mock_sock.add_member.assert_called_with(group_id=700756094, member_uids=[123456], is_invite=False)

    def test_bot_generate_reply_interaction_commands(self):
        # /react command
        resp_react = generate_bot_response("/react like", group_id=686355764, from_uid=999)
        self.assertIn("__ACTION_REACT::>__", resp_react)

        # /pin command
        resp_pin = generate_bot_response("/pin Thông báo mới", group_id=686355764, from_uid=999)
        self.assertIn("__ACTION_PIN:Thông báo mới__", resp_pin)

        # /disband command
        resp_disband = generate_bot_response("/disband", group_id=686355764, from_uid=999)
        self.assertIn("__ACTION_DISBAND__", resp_disband)

        # /kick command
        resp_kick = generate_bot_response("/kick 123456", group_id=686355764, from_uid=999, bot_uid=463450795)
        self.assertIn("__ACTION_KICK:", resp_kick)
        self.assertIn('"uid": 123456', resp_kick)
        self.assertIn('"is_block": false', resp_kick)

        # /ban command
        resp_ban = generate_bot_response("/ban 123456", group_id=686355764, from_uid=999, bot_uid=463450795)
        self.assertIn("__ACTION_KICK:", resp_ban)
        self.assertIn('"uid": 123456', resp_ban)
        self.assertIn('"is_block": true', resp_ban)

        # Anti-self kick
        resp_self_kick = generate_bot_response("/kick 463450795", group_id=686355764, from_uid=999, bot_uid=463450795)
        self.assertIn("Không thể tự kick chính bot", resp_self_kick)

        # /data command with quote
        quote_sample = {
            "ownerId": 385784957,
            "fromD": "Trần Bảo Nam",
            "cliMsgId": 1789382931139,
            "globalMsgId": 8262679528325,
            "cliMsgType": 1,
            "msg": "@Trần Khải Đăng đéo bt",
            "attach": '{"thumb":"","mentions":[{"uid":420416772,"pos":0,"len":15,"type":0,"ignoreNickname":0}]}',
            "mentions": [{"uid": 420416772, "pos": 0, "len": 15, "type": 0, "ignoreNickname": 0}],
            "ts": 1773505868317,
            "ttl": 0
        }
        resp_data = generate_bot_response("/data", group_id=686355764, from_uid=999, quote_data=quote_sample)
        self.assertIn("[DATA QUOTE]", resp_data)
        self.assertIn("id: 8262679528325", resp_data)
        self.assertIn("cli_msg_id: 1789382931139", resp_data)
        self.assertIn("from_uid: 385784957", resp_data)
        self.assertIn("from_name: Trần Bảo Nam", resp_data)
        self.assertIn("msg: @Trần Khải Đăng đéo bt", resp_data)
        self.assertIn("raw:", resp_data)

    def test_group_target_parsing(self):
        # 1. Full URL
        t1, gid1, code1 = GroupAPI.parse_group_target("https://zalo.me/g/abc123xyz")
        self.assertEqual(t1, "link")
        self.assertIsNone(gid1)
        self.assertEqual(code1, "abc123xyz")

        # 2. Short URL
        t2, gid2, code2 = GroupAPI.parse_group_target("zalo.me/g/grp456")
        self.assertEqual(t2, "link")
        self.assertEqual(code2, "grp456")

        # 3. Numeric ID / UID
        t3, gid3, code3 = GroupAPI.parse_group_target("753123456789")
        self.assertEqual(t3, "id")
        self.assertEqual(gid3, 753123456789)
        self.assertIsNone(code3)

        # 4. Int ID
        t4, gid4, code4 = GroupAPI.parse_group_target(686355764)
        self.assertEqual(t4, "id")
        self.assertEqual(gid4, 686355764)

        # 5. Raw code
        t5, gid5, code5 = GroupAPI.parse_group_target("mygroupcode")
        self.assertEqual(t5, "link")
        self.assertEqual(code5, "mygroupcode")

    def test_join_group_by_id_socket(self):
        mock_sock = MagicMock()
        mock_sock.is_connected = True
        mock_sock.join_group.return_value = True
        mock_sock.request_join_group.return_value = True
        group_api = GroupAPI(socket_client=mock_sock)

        with patch.object(group_api, '_call_group_api', return_value={"error_code": 0}):
            res = group_api.join_group_by_id(group_id=753123456, source=0)
            self.assertTrue(res['success'])
            self.assertEqual(res['type'], 'id')
            self.assertEqual(res['group_id'], 753123456)
            mock_sock.join_group.assert_called_with(group_id=753123456, source=0)
            mock_sock.request_join_group.assert_called_with(group_id=753123456, link_url="", msg="", source=0)

    def test_join_group_by_link(self):
        mock_sock = MagicMock()
        mock_sock.is_connected = True
        mock_sock.join_group.return_value = True
        mock_sock.request_join_group.return_value = True
        mock_sock.join_group_by_link.return_value = {'sent': True, 'group_id': 753123456}
        group_api = GroupAPI(socket_client=mock_sock)

        # Mock HTTP group join response returning groupId
        with patch.object(group_api, '_call_group_api', return_value={"error_code": 0, "data": {"groupId": 753123456}}):
            res = group_api.join_group_by_link("https://zalo.me/g/abc123xyz")
            self.assertTrue(res['success'])
            self.assertEqual(res['type'], 'link')
            self.assertEqual(res['link_code'], 'abc123xyz')
            self.assertEqual(res['group_id'], 753123456)
            mock_sock.join_group_by_link.assert_called_with(
                link_url='https://zalo.me/g/abc123xyz', group_id=0, msg='', source=1, wait_response=True, timeout=8.0
            )

    def test_preview_group_link(self):
        mock_sock = MagicMock()
        mock_sock.is_connected = True
        mock_sock.preview_link_901.return_value = {
            'sent': True,
            'got_response': True,
            'group_id': 753123456
        }
        group_api = GroupAPI(socket_client=mock_sock)

        mock_http_data = {
            "error_code": 0,
            "data": {
                "groupId": 753123456,
                "name": "Nhóm Lập Trình Python",
                "creatorName": "Nguyễn Văn A",
                "creatorId": 123456,
                "totalMember": 42,
                "desc": "Cộng đồng chia sẻ kiến thức Python",
                "isCommunity": False,
                "createdTime": 1700000000,
                "setting": {"joinAppr": 0}
            }
        }
        with patch.object(group_api, 'get_group_info_by_link', return_value=mock_http_data):
            preview = group_api.preview_group_link("https://zalo.me/g/abc123xyz")
            self.assertTrue(preview['success'])
            self.assertEqual(preview['group_id'], 753123456)
            self.assertEqual(preview['name'], "Nhóm Lập Trình Python")
            self.assertEqual(preview['creator_name'], "Nguyễn Văn A")
            self.assertEqual(preview['total_member'], 42)
            self.assertFalse(preview['is_community'])
            self.assertIn("Nhóm của: Nguyễn Văn A", preview['formatted_preview'])
            self.assertIn("Số thành viên: 42", preview['formatted_preview'])
            self.assertIn("[THAM GIA]", preview['formatted_preview'])

    def test_preview_community_link(self):
        mock_sock = MagicMock()
        mock_sock.is_connected = True
        mock_sock.preview_link_901.return_value = {'sent': True, 'got_response': True, 'group_id': 999888777}
        group_api = GroupAPI(socket_client=mock_sock)

        mock_http_data = {
            "error_code": 0,
            "data": {
                "groupId": 999888777,
                "name": "Cộng Đồng Zalo Official",
                "creatorName": "Zalo Admin",
                "creatorId": 999999,
                "totalMember": 1500,
                "desc": "Cộng đồng lớn nhất",
                "isCommunity": True,
                "createdTime": 1710000000,
                "setting": {"joinAppr": 1},
                "question": "Bạn biết nhóm qua đâu?"
            }
        }
        with patch.object(group_api, 'get_group_info_by_link', return_value=mock_http_data):
            preview = group_api.preview_group_link("https://zalo.me/g/comm123")
            self.assertTrue(preview['success'])
            self.assertEqual(preview['group_id'], 999888777)
            self.assertTrue(preview['is_community'])
            self.assertTrue(preview['requires_approval'])
            self.assertIn("Cộng đồng của: Zalo Admin", preview['formatted_preview'])
            self.assertIn("Cần phê duyệt", preview['formatted_preview'])
            self.assertIn("[THAM GIA]", preview['formatted_preview'])

    def test_build_request_join_group_packet(self):
        from protocol import build_request_join_group_packet
        import struct
        pkt = build_request_join_group_packet(
            uid=463450795,
            group_id=0,
            msg="Xin chào nhóm",
            link_url="4eclv9gylywyxv4avxuu",
            source=0,
            seq=-100
        )
        self.assertTrue(len(pkt) > 18)
        ck, bb, ty, seq, uid, ver, cmd, sub = struct.unpack('<IBBiIBHB', pkt[:18])
        self.assertEqual(cmd, 244)
        self.assertEqual(sub, 4)
        self.assertEqual(uid, 463450795)

    def test_bot_generate_reply_join_command(self):
        # 1. Join by URL
        resp_url = generate_bot_response(".join https://zalo.me/g/abc123xyz", prefix=".")
        self.assertIn("__ACTION_JOIN:", resp_url)
        self.assertIn('"type": "link"', resp_url)
        self.assertIn('"target": "abc123xyz"', resp_url)

        # 2. Join by Group ID
        resp_id = generate_bot_response(".join 753123456", prefix=".")
        self.assertIn("__ACTION_JOIN:", resp_id)
        self.assertIn('"type": "id"', resp_id)
        self.assertIn('"target": 753123456', resp_id)

        # 3. Join without arg -> Guide
        resp_guide = generate_bot_response(".join", prefix=".")
        self.assertIn("[HƯỚNG DẪN LỆNH .join]", resp_guide)
        self.assertIn(".join <link_nhóm>", resp_guide)
        self.assertIn(".join <group_id>", resp_guide)

    def test_bot_grid_and_echo_command(self):
        # 1. Grid with Link — now returns full group preview (name + THAM GIA) or GROUP ID
        resp_grid = generate_bot_response(".grid https://zalo.me/g/krgx195dxdbjx1bm2fbd", prefix=".")
        self.assertTrue(
            "[GROUP ID]" in resp_grid or "NHÓM ZALO" in resp_grid or "THAM GIA" in resp_grid,
            f"Expected group info in /grid response, got: {resp_grid}"
        )
        self.assertIn("krgx195dxdbjx1bm2fbd", resp_grid)

        # 2. Grid with ID
        resp_grid_id = generate_bot_response(".grid 686355764", prefix=".")
        self.assertIn("686355764", resp_grid_id)


        # 3. Echo without "Echo:" prefix
        resp_echo = generate_bot_response(".echo hi", prefix=".")
        self.assertEqual(resp_echo, "hi")

        resp_echo_long = generate_bot_response(".echo Alo 1234 test bot", prefix=".")
        self.assertEqual(resp_echo_long, "Alo 1234 test bot")

    def test_bot_preview_command(self):
        # 1. Preview guide without args
        resp_guide = generate_bot_response(".preview", prefix=".")
        self.assertIn("Cú pháp: .preview", resp_guide)

        # 2. Preview with mocked GroupAPI
        mock_g_api = MagicMock()
        mock_g_api.preview_group_link.return_value = {
            "success": True,
            "formatted_preview": "🏷️ [NHÓM ZALO] Nhóm Test\n🔗 Liên kết: https://zalo.me/g/abc123xyz\n👑 Nhóm của: Trưởng nhóm"
        }
        resp_p = generate_bot_response(".preview https://zalo.me/g/abc123xyz", prefix=".", group_api=mock_g_api)
        self.assertIn("🏷️ [NHÓM ZALO] Nhóm Test", resp_p)
        self.assertIn("Nhóm của: Trưởng nhóm", resp_p)


class TestBotEngineInteractions(unittest.TestCase):

    def setUp(self):
        self.mock_client = MagicMock()
        self.mock_client.uid = 463450795
        self.mock_client.is_connected = True
        self.bot = ZaloBotEngine(self.mock_client, prefix="/", rate_limit_sec=0.0)

    @patch("core.api.group.api.GroupAPI.send_reaction")
    def test_bot_executes_react_action(self, mock_send_reaction):
        mock_send_reaction.return_value = True
        event = {
            "cmd": 201,
            "is_group": True,
            "to_group": 686355764,
            "from_uid": 123456,
            "from_name": "UserA",
            "content": "/react ❤️",
            "text": "/react ❤️",
            "quote": {
                "ownerId": 78910,
                "cliMsgId": 1789382931139,
                "globalMsgId": 8262679528325
            }
        }
        self.bot._process_event(event)
        mock_send_reaction.assert_called_once_with(
            target_id=686355764,
            cli_msg_id=1789382931139,
            global_msg_id=8262679528325,
            icon="/-heart",
            is_group=True
        )

    @patch("core.api.group.api.GroupAPI.send_reaction")
    def test_bot_executes_custom_emoji_react(self, mock_send_reaction):
        mock_send_reaction.return_value = True
        event = {
            "cmd": 201,
            "is_group": True,
            "to_group": 686355764,
            "from_uid": 123456,
            "from_name": "UserA",
            "content": "/react 👉",
            "text": "/react 👉",
            "quote": {
                "ownerId": 78910,
                "cliMsgId": 1789382931139,
                "globalMsgId": 8262679528325
            }
        }
        self.bot._process_event(event)
        mock_send_reaction.assert_called_once_with(
            target_id=686355764,
            cli_msg_id=1789382931139,
            global_msg_id=8262679528325,
            icon="👉",
            is_group=True
        )

    @patch("core.api.group.api.GroupAPI.send_reaction")
    def test_bot_executes_custom_text_react(self, mock_send_reaction):
        mock_send_reaction.return_value = True
        event = {
            "cmd": 201,
            "is_group": True,
            "to_group": 686355764,
            "from_uid": 123456,
            "from_name": "UserA",
            "content": "/react h",
            "text": "/react h",
            "quote": {
                "ownerId": 78910,
                "cliMsgId": 1789382931139,
                "globalMsgId": 8262679528325
            }
        }
        self.bot._process_event(event)
        mock_send_reaction.assert_called_once_with(
            target_id=686355764,
            cli_msg_id=1789382931139,
            global_msg_id=8262679528325,
            icon="h",
            is_group=True
        )

    @patch("core.api.group.api.GroupAPI.pin_message")
    def test_bot_executes_pin_action(self, mock_pin_message):
        mock_pin_message.return_value = True
        event = {
            "cmd": 201,
            "is_group": True,
            "to_group": 686355764,
            "from_uid": 123456,
            "from_name": "UserA",
            "content": "/pin Họp nhóm lúc 20h",
            "text": "/pin Họp nhóm lúc 20h",
            "quote": {
                "ownerId": 78910,
                "cliMsgId": 1789382931139,
                "globalMsgId": 8262679528325
            }
        }
        self.bot._process_event(event)
        mock_pin_message.assert_called_once()

    @patch("core.api.group.api.GroupAPI.kick_member")
    def test_bot_executes_kick_action(self, mock_kick_member):
        mock_kick_member.return_value = True
        event = {
            "cmd": 201,
            "is_group": True,
            "to_group": 686355764,
            "from_uid": 123456,
            "from_name": "UserA",
            "content": "/kick 987654321",
            "text": "/kick 987654321",
        }
        self.bot._process_event(event)
        mock_kick_member.assert_called_once_with(
            group_id=686355764,
            member_uids=[987654321],
            is_block=False
        )

    @patch("core.api.group.api.GroupAPI.kick_member")
    def test_bot_executes_ban_action(self, mock_kick_member):
        mock_kick_member.return_value = True
        event = {
            "cmd": 201,
            "is_group": True,
            "to_group": 686355764,
            "from_uid": 123456,
            "from_name": "UserA",
            "content": "/ban 987654321",
            "text": "/ban 987654321",
        }
        self.bot._process_event(event)
        mock_kick_member.assert_called_once_with(
            group_id=686355764,
            member_uids=[987654321],
            is_block=True
        )

    @patch("core.api.group.api.GroupAPI.join_group")
    def test_bot_executes_join_action(self, mock_join_group):
        mock_join_group.return_value = {"success": True, "status": "OK"}
        event = {
            "cmd": 201,
            "is_group": True,
            "to_group": 686355764,
            "from_uid": 123456,
            "from_name": "UserA",
            "content": "/join https://zalo.me/g/abc123xyz",
            "text": "/join https://zalo.me/g/abc123xyz",
        }
        self.bot._process_event(event)
        # Give daemon thread a brief moment to run
        time.sleep(0.05)
        mock_join_group.assert_called_once_with("abc123xyz")

    def test_bot_executes_data_command(self):
        event = {
            "cmd": 201,
            "is_group": True,
            "to_group": 686355764,
            "from_uid": 123456,
            "from_name": "UserA",
            "content": "/data",
            "text": "/data",
            "quote": {
                "ownerId": 78910,
                "fromD": "UserB",
                "cliMsgId": 1789382931139,
                "globalMsgId": 8262679528325,
                "msg": "Tin nhắn mẫu để kiểm tra",
                "attach": "",
                "ttl": 604800000
            }
        }
        with patch.object(self.bot, '_send_reply') as mock_reply:
            self.bot._process_event(event)
            mock_reply.assert_called_once()
            args, kwargs = mock_reply.call_args
            dest_id, reply_text = args[0], args[1]
            self.assertEqual(dest_id, 686355764)
            self.assertIn("[DATA QUOTE]", reply_text)
            self.assertIn("id: 8262679528325", reply_text)
            self.assertIn("from_uid: 78910", reply_text)
            self.assertIn("from_name: UserB", reply_text)
            self.assertIn("msg: Tin nhắn mẫu để kiểm tra", reply_text)
            self.assertIn("ttl: 604800000", reply_text)
            self.assertIn("raw:", reply_text)

    def test_test_command_guide(self):
        resp = generate_bot_response(".test", prefix=".")
        self.assertIsNotNone(resp)
        self.assertIn("[HƯỚNG DẪN LỆNH TEST]", resp)
        self.assertIn(".test font <tên/id> <text>", resp)
        self.assertIn(".test size <50-300> <text>", resp)
        self.assertIn(".test color <hex> <text>", resp)
        self.assertIn(".test bold <text>", resp)

    def test_test_command_font(self):
        # 1. Font ID số
        resp1 = generate_bot_response(".test font 15433 Hello Young", prefix=".")
        self.assertIsNotNone(resp1)
        self.assertIn("__ACTION_SEND_STYLE:", resp1)
        self.assertIn('"style_id": 15433', resp1)
        self.assertIn("Hello Young", resp1)

        # 2. Font theo tên (retro -> 13625)
        resp2 = generate_bot_response(".test font retro Hello Retro", prefix=".")
        self.assertIn('"style_id": 13625', resp2)
        self.assertIn("Hello Retro", resp2)

        # 3. Font theo tên (young -> 15433)
        resp3 = generate_bot_response(".test font young Xin chào", prefix=".")
        self.assertIn('"style_id": 15433', resp3)

        # 4. Gõ mỗi '.test font' -> In danh sách font chuẩn
        resp_list = generate_bot_response(".test font", prefix=".")
        self.assertIn("[DANH SÁCH FONT CHỮ ZALO]", resp_list)
        self.assertIn("young", resp_list)
        self.assertIn("retro", resp_list)
        self.assertIn("15433", resp_list)
        self.assertIn("13625", resp_list)

        # 5. Font sai tên -> In lỗi kèm danh sách font chuẩn
        resp_err = generate_bot_response(".test font abcxyz Hello", prefix=".")
        self.assertIn("Font 'abcxyz' không hợp lệ", resp_err)
        self.assertIn("[DANH SÁCH FONT CHỮ ZALO]", resp_err)

    def test_test_command_size(self):
        resp = generate_bot_response(".test size 200 Big Size Text", prefix=".")
        self.assertIsNotNone(resp)
        self.assertIn("__ACTION_SEND_STYLE:", resp)
        self.assertIn('"size": 200', resp)
        self.assertIn("Big Size Text", resp)

    def test_test_command_color(self):
        # Hex color
        resp1 = generate_bot_response(".test color db342e Red Hex", prefix=".")
        self.assertIn('"color": "db342e"', resp1)
        self.assertIn("Red Hex", resp1)

        # Named color
        resp2 = generate_bot_response(".test color red Red Named", prefix=".")
        self.assertIn('"color": "db342e"', resp2)
        self.assertIn("Red Named", resp2)

        resp3 = generate_bot_response(".test color green Green Named", prefix=".")
        self.assertIn('"color": "15a85f"', resp3)

    def test_test_command_styles_rtf(self):
        # Bold
        resp_b = generate_bot_response(".test bold Bold message", prefix=".")
        self.assertIn('"bold": true', resp_b)
        self.assertIn("Bold message", resp_b)

        # Italic
        resp_i = generate_bot_response(".test italic Italic message", prefix=".")
        self.assertIn('"italic": true', resp_i)

        # Underline
        resp_u = generate_bot_response(".test underline Underline message", prefix=".")
        self.assertIn('"underline": true', resp_u)

        # Strike
        resp_s = generate_bot_response(".test strike Strike message", prefix=".")
        self.assertIn('"strike": true', resp_s)

        # Fontsize
        resp_f = generate_bot_response(".test fontsize 18 RTF Size", prefix=".")
        self.assertIn('"fontsize": 18', resp_f)

        # List
        resp_l = generate_bot_response(".test list 1 Bullet item", prefix=".")
        self.assertIn('"list_type": 1', resp_l)

        # Full RTF
        resp_rtf = generate_bot_response(".test rtf Rich format", prefix=".")
        self.assertIn('"bold": true', resp_rtf)
        self.assertIn('"color": "db342e"', resp_rtf)

    def test_bot_executes_test_style_reply(self):
        event = {
            "cmd": 201,
            "is_group": True,
            "to_group": 686355764,
            "from_uid": 123456,
            "from_name": "UserA",
            "content": "/test size 200 Test big message",
            "text": "/test size 200 Test big message",
        }
        with patch.object(self.bot, '_send_reply') as mock_reply:
            self.bot._process_event(event)
            mock_reply.assert_called_once()
            args, kwargs = mock_reply.call_args
            dest_id, reply_text = args[0], args[1]
            style_params = kwargs.get('style_params') or (args[4] if len(args) > 4 else {})
            self.assertEqual(dest_id, 686355764)
            self.assertIn("Test big message", reply_text)
            self.assertEqual(style_params.get("size"), 200)

    def test_bot_with_default_font_style(self):
        mock_client = MagicMock()
        mock_client.uid = 463450795
        mock_client.send_group_message.return_value = True

        bot_retro = ZaloBotEngine(
            client=mock_client,
            prefix="/",
            default_style={"style_id": 13625}  # font Retro
        )

        event = {
            "cmd": 201,
            "is_group": True,
            "to_group": 686355764,
            "from_uid": 123456,
            "from_name": "UserA",
            "content": "/ping",
            "text": "/ping",
        }
        bot_retro._process_event(event)
        mock_client.send_group_message.assert_called_once()
        call_kwargs = mock_client.send_group_message.call_args[1]
        self.assertEqual(call_kwargs.get("style_id"), 13625)

    def test_test_command_combination_font_and_size(self):
        # 1. Font + Size
        resp1 = generate_bot_response(".test font retro size 200 Xin chào Retro Big", prefix=".")
        self.assertIn("__ACTION_SEND_STYLE:", resp1)
        self.assertIn('"style_id": 13625', resp1)
        self.assertIn('"size": 200', resp1)
        self.assertIn("Xin chào Retro Big", resp1)

    def test_group_api_poll_block_leave_recall(self):
        mock_sock = MagicMock()
        mock_sock.is_connected = True
        mock_sock.create_poll.return_value = True
        mock_sock.block_user.return_value = True
        mock_sock.leave_group.return_value = True
        mock_sock.delete_message.return_value = True
        mock_sock.block_group_member.return_value = True

        group_api = GroupAPI(socket_client=mock_sock)

        # 1. Create Poll
        self.assertTrue(group_api.create_poll(686355764, "Trưa nay ăn gì?", ["Cơm", "Phở"]))
        mock_sock.create_poll.assert_called_once_with(group_id=686355764, question="Trưa nay ăn gì?", options=["Cơm", "Phở"])

        # 2. Block User
        self.assertTrue(group_api.block_user(123456, is_block=True))
        mock_sock.block_user.assert_called_once_with(target_uid=123456, is_block=True)

        # 3. Leave Group
        self.assertTrue(group_api.leave_group(686355764))
        mock_sock.leave_group.assert_called_once_with(
            group_id=686355764,
            new_owner_id=0,
            silent=False,
            block_readd=False,
            wait_response=True,
            timeout=5.0
        )

        # 4. Recall / Delete Message
        self.assertTrue(group_api.delete_message(686355764, cli_msg_id=1789382931139, is_group=True, only_me=True))
        mock_sock.delete_message.assert_called_once()
        self.assertTrue(group_api.recall_message(686355764, cli_msg_id=1789382931139, is_group=True))
        mock_sock.recall_message.assert_called_once()

        # 5. Block Group Member
        self.assertTrue(group_api.block_group_member(686355764, [123456]))
        mock_sock.block_group_member.assert_called_once()

    def test_bot_executes_poll_leave_block_recall_commands(self):
        # 1. Poll command
        resp_poll = generate_bot_response("/poll Ăn gì trưa nay? | Cơm tấm | Bún riêu", group_id=686355764, from_uid=999)
        self.assertIn("__ACTION_POLL:", resp_poll)
        self.assertIn("Ăn gì trưa nay?", resp_poll)
        self.assertIn("Cơm tấm", resp_poll)

        # 2. Block command
        resp_block = generate_bot_response("/block 123456", group_id=686355764, from_uid=999)
        self.assertIn("__ACTION_BLOCK:", resp_block)
        self.assertIn('"uid": 123456', resp_block)

        # 3. Leave command
        resp_leave = generate_bot_response("/leave", group_id=686355764, from_uid=999)
        self.assertIn("__ACTION_LEAVE", resp_leave)

        # 4. Recall command with arg
        resp_recall = generate_bot_response("/recall 1789382931139", group_id=686355764, from_uid=999)
        self.assertIn("__ACTION_RECALL:", resp_recall)
        self.assertIn("1789382931139", resp_recall)

        # 5. Unpin command
        resp_unpin = generate_bot_response("/unpin", group_id=686355764, from_uid=999)
        self.assertIn("__ACTION_UNPIN__", resp_unpin)

    @patch("core.api.group.api.GroupAPI.create_poll")
    def test_bot_executes_poll_action(self, mock_create_poll):
        mock_create_poll.return_value = True
        event = {
            "cmd": 201,
            "is_group": True,
            "to_group": 686355764,
            "from_uid": 123456,
            "from_name": "UserA",
            "content": "/poll Họp lúc mấy giờ? | 8h | 9h | 10h",
            "text": "/poll Họp lúc mấy giờ? | 8h | 9h | 10h",
        }
        self.bot._process_event(event)
        mock_create_poll.assert_called_once_with(
            group_id=686355764,
            question="Họp lúc mấy giờ?",
            options=["8h", "9h", "10h"]
        )

    @patch("core.api.group.api.GroupAPI.leave_group")
    def test_bot_executes_leave_action(self, mock_leave_group):
        mock_leave_group.return_value = True
        event = {
            "cmd": 201,
            "is_group": True,
            "to_group": 686355764,
            "from_uid": 123456,
            "from_name": "UserA",
            "content": "/leave",
            "text": "/leave",
        }
        self.bot._process_event(event)
        mock_leave_group.assert_called_once_with(group_id=686355764)

    @patch("core.api.group.api.GroupAPI.block_user")
    def test_bot_executes_block_action(self, mock_block_user):
        mock_block_user.return_value = True
        event = {
            "cmd": 201,
            "is_group": True,
            "to_group": 686355764,
            "from_uid": 123456,
            "from_name": "UserA",
            "content": "/block 987654321",
            "text": "/block 987654321",
        }
        self.bot._process_event(event)
        mock_block_user.assert_called_once_with(target_uid=987654321, is_block=True)


if __name__ == "__main__":
    unittest.main()
