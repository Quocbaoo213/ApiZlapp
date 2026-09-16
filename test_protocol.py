#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_protocol.py — Unit Test toàn diện cho Module protocol.py
Kiểm thử tính chính xác của toàn bộ các cấu trúc gói tin, framing nhị phân, D3 payload và S2C parser.
"""

import gzip
import json
import struct
import unittest
from protocol import (
    InnerPacketHeader, OuterFrame,
    compute_checksum, xor_encode_d3, xor_decode_d3,
    build_ping_packet, build_typing_packet,
    build_group_message_packet, build_1to1_message_packet,
    build_outer_frame, parse_incoming_frame,
    parse_group_sync_1867, build_prov_frame, build_init_frames,
    build_join_group_packet, build_join_group_invite_packet,
    CMD_PING, CMD_GROUP_MSG, CMD_1TO1_MSG, CMD_GROUP_TYPING,
    CMD_GROUP_SYNC_BROADCAST, FRAME_TYPE_DATA, FRAME_TYPE_CONTROL,
    CMD_JOIN_GROUP, SUB_JOIN_GROUP, CMD_JOIN_GROUP_INVITE, SUB_JOIN_GROUP_INVITE,
    INNER_HEADER_SIZE
)
from crypto import decrypt_aes_gcm

class TestZaloProtocol(unittest.TestCase):

    def setUp(self):
        self.uid = 463450795
        self.group_id = 686355764
        self.target_uid = 123456789
        self.dk = bytes.fromhex("6f383957d70cb9394adcd40b7f74854d35bc6615711c5b6800014985276db84c")
        self.cryptkey = bytes.fromhex("36b7c3dad8368c40dfce3b7adcca91ab")

    def test_01_inner_header_pack_unpack(self):
        """Kiểm tra đóng gói và giải mã Header 18 bytes (<IBBiIBHB)."""
        hdr = InnerPacketHeader(
            ck=0x7778634c,
            bb=1,
            ty=2,
            seq=-118,
            uid=self.uid,
            ver=3,
            cmd=CMD_GROUP_MSG,
            sub=1
        )
        packed = hdr.pack()
        self.assertEqual(len(packed), INNER_HEADER_SIZE)
        self.assertEqual(len(packed), 18)

        unpacked = InnerPacketHeader.unpack(packed)
        self.assertEqual(unpacked.ck, 0x7778634c)
        self.assertEqual(unpacked.bb, 1)
        self.assertEqual(unpacked.ty, 2)
        self.assertEqual(unpacked.seq, -118)
        self.assertEqual(unpacked.uid, self.uid)
        self.assertEqual(unpacked.ver, 3)
        self.assertEqual(unpacked.cmd, CMD_GROUP_MSG)
        self.assertEqual(unpacked.sub, 1)

    def test_02_outer_frame_stream_buffer(self):
        """Kiểm tra bóc tách Outer Frame từ Stream Buffer (hỗ trợ phân mảnh)."""
        body = b"Test outer frame body data 123456"
        frame = OuterFrame(total_len=len(body) + 5, ftype=FRAME_TYPE_DATA, body=body)
        packed = frame.pack()
        self.assertEqual(len(packed), len(body) + 5)

        # Buffer chưa đủ dữ liệu
        incomplete_buf = packed[:10]
        res_none = OuterFrame.unpack_from_buffer(incomplete_buf)
        self.assertIsNone(res_none)

        # Buffer đầy đủ
        res_frame, consumed = OuterFrame.unpack_from_buffer(packed)
        self.assertIsNotNone(res_frame)
        self.assertEqual(consumed, len(packed))
        self.assertEqual(res_frame.ftype, FRAME_TYPE_DATA)
        self.assertEqual(res_frame.body, body)

    def test_03_checksum_computation(self):
        """Kiểm tra tính Checksum ck_val với XOR magic 0x6ce7daa0."""
        ck = compute_checksum(cmd=207, sub=1, seq=-41, uid=self.uid, target=self.group_id, cmsg=2500000000)
        self.assertIsInstance(ck, int)
        self.assertTrue(0 <= ck <= 0xFFFFFFFF)

    def test_04_d3_xor_roundtrip(self):
        """Kiểm tra mã hóa và giải mã XOR D3 đối xứng."""
        plain = b"Hello Zalo Protocol D3 Message Encoding Test Payload"
        encoded = xor_encode_d3(plain, self.uid)
        self.assertNotEqual(encoded, plain)
        self.assertEqual(len(encoded), len(plain))
        decoded = xor_decode_d3(encoded, self.uid)
        self.assertEqual(decoded, plain)

    def test_05_build_ping_packet(self):
        """Kiểm tra tạo gói tin Ping Keepalive (CMD 1971 SUB 0)."""
        pkt = build_ping_packet(uid=self.uid, seq=-1, ck_val=0x77780001)
        self.assertEqual(len(pkt), 18 + 5)
        hdr = InnerPacketHeader.unpack(pkt)
        self.assertEqual(hdr.cmd, CMD_PING)
        self.assertEqual(hdr.sub, 0)
        self.assertEqual(hdr.bb, 0)
        self.assertEqual(hdr.ty, 1)

    def test_06_build_typing_packet(self):
        """Kiểm tra tạo gói tin Typing Notification (Group & 1-1)."""
        # Group typing
        grp_pkt = build_typing_packet(uid=self.uid, target_id=self.group_id, is_group=True, seq=-2, ck_val=0x8e900000, cmsg_id=2600000000)
        hdr_grp = InnerPacketHeader.unpack(grp_pkt)
        self.assertEqual(hdr_grp.cmd, CMD_GROUP_TYPING)
        self.assertEqual(hdr_grp.sub, 1)

        # 1-1 typing
        p2p_pkt = build_typing_packet(uid=self.uid, target_id=self.target_uid, is_group=False, seq=-3, ck_val=0x8e900000, cmsg_id=2600000001)
        hdr_p2p = InnerPacketHeader.unpack(p2p_pkt)
        self.assertEqual(hdr_p2p.cmd, 106)
        self.assertEqual(hdr_p2p.sub, 1)

    def test_07_build_group_message_packet(self):
        """Kiểm tra tạo gói tin gửi tin nhắn nhóm D3 (CMD 207 SUB 1)."""
        msg_text = "Chào mừng tới Zalo Bot Socket!"
        pkt = build_group_message_packet(
            uid=self.uid,
            group_id=self.group_id,
            text=msg_text,
            seq=-41,
            ck_val=0xb3b80001,
            cmsg_id=2600000100,
            ttl_ms=604800000  # 7 ngày
        )
        hdr = InnerPacketHeader.unpack(pkt)
        self.assertEqual(hdr.cmd, CMD_GROUP_MSG)
        self.assertEqual(hdr.sub, 1)
        self.assertEqual(hdr.uid, self.uid)

        # Kiểm tra đóng gói Outer Frame AES-GCM
        outer = build_outer_frame(pkt, self.dk)
        self.assertTrue(len(outer) > len(pkt))
        # Giải mã lại Outer Frame
        dec_body = decrypt_aes_gcm(outer[5:], self.dk)
        self.assertEqual(dec_body, pkt)

    def test_08_build_1to1_message_packet(self):
        """Kiểm tra tạo gói tin gửi tin nhắn 1-1 E2EE CBC (CMD 113 SUB 41)."""
        msg_text = "Tin nhắn bí mật gửi 1-1"
        pkt = build_1to1_message_packet(
            uid=self.uid,
            target_uid=self.target_uid,
            text=msg_text,
            cryptkey=self.cryptkey,
            seq=-42,
            ck_val=0xb3b80002,
            cmsg_id=2600000101
        )
        hdr = InnerPacketHeader.unpack(pkt)
        self.assertEqual(hdr.cmd, CMD_1TO1_MSG)
        self.assertEqual(hdr.sub, 41)

    def test_09_parse_incoming_group_sync_1867(self):
        """Kiểm tra phân giải bản tin Broadcast phân phối tin nhắn nhóm (CMD 1867 SUB 0)."""
        sample_json = {
            "e": 0,
            "last": "1789305007022",
            "msg": [
                {
                    "text": {
                        "type": "webchat",
                        "data": {
                            "to": 686355764,
                            "id": 8259342810073,
                            "cliMsgId": 1789304172687,
                            "fromU": 463450795,
                            "fromD": "Xihuan Thuy",
                            "msg": "Hello from Zalo test",
                            "ttl": 0
                        }
                    }
                }
            ]
        }
        gz_payload = gzip.compress(json.dumps(sample_json).encode('utf-8'))
        # Giả lập params body với header prefix ngẫu nhiên + GZIP
        params_body = b"\x00\x01\x02\x03\x04\x05" + gz_payload

        parsed = parse_group_sync_1867(params_body)
        self.assertEqual(len(parsed['messages']), 1)
        m = parsed['messages'][0]
        self.assertEqual(m['to_group'], 686355764)
        self.assertEqual(m['from_uid'], 463450795)
        self.assertEqual(m['from_display'], "Xihuan Thuy")
        self.assertEqual(m['content'], "Hello from Zalo test")

    def test_10_parse_control_error_frame(self):
        """Kiểm tra phân giải khung lỗi từ Server (Frame Type 3 Code -22)."""
        err_body = struct.pack('<HHi', 3, 0, -22)
        frame = OuterFrame(total_len=len(err_body) + 5, ftype=FRAME_TYPE_CONTROL, body=err_body)
        res = parse_incoming_frame(frame, self.dk)
        self.assertTrue(res['is_error'])
        self.assertEqual(res['cmd'], 3)
        self.assertEqual(res['sub'], 0)
        self.assertEqual(res['error_code'], -22)

    def test_11_build_prov_frame(self):
        """Kiểm tra tự sinh Handshake Khởi tạo PROV Frame (Type 8 X25519 ECDH + AES-256-GCM 2 lớp)."""
        session_key = "zXSs.463450795.a1.9cmdIrGG2Lh_efP1L109MbGG2LfK40bQLR-7_Jvl2Le"
        ksid = "zDzfP7XhyEWQPdl_"
        server_pub = "wT8wgnjOcojhsXxJPuSTbLwwIk5AodMRHENKDqqqNhg="
        f0 = build_prov_frame(
            session_key=session_key,
            dk=self.dk,
            ksid=ksid,
            server_pubkey_b64=server_pub,
            uid=self.uid
        )
        self.assertEqual(len(f0), 270)
        flen, ftype = struct.unpack('<IB', f0[:5])
        self.assertEqual(flen, 270)
        self.assertEqual(ftype, 8)

    def test_12_build_init_frames(self):
        """Kiểm tra sinh danh sách các frame khởi tạo Active Session."""
        frames = build_init_frames(self.uid)
        self.assertTrue(len(frames) >= 20)
        cmd0, sub0, bb0, ty0, params0 = frames[0]
        self.assertEqual(cmd0, 384)
        self.assertEqual(ty0, 1)

    def test_13_build_styled_and_rtf_messages(self):
        """Kiểm tra tạo gói tin tin nhắn có kiểu chữ, màu sắc, font size và RTF spans."""
        # 1. Styled text (size, color, bold/italic, typoId)
        pkt_styled = build_1to1_message_packet(
            uid=self.uid,
            target_uid=self.target_uid,
            text="Hello Styled Zalo",
            cryptkey=self.cryptkey,
            seq=-45,
            ck_val=123456,
            cmsg_id=7891011,
            style_id=15433,
            size=150,
            color="db342e",
            bold=True,
            italic=True
        )
        self.assertTrue(len(pkt_styled) > 30)

        # 2. RTF spans (bold, italic, underline, strike, fontsize, list)
        pkt_rtf = build_1to1_message_packet(
            uid=self.uid,
            target_uid=self.target_uid,
            text="Line 1\nLine 2",
            cryptkey=self.cryptkey,
            seq=-46,
            ck_val=123457,
            cmsg_id=7891012,
            bold=True,
            italic=True,
            underline=True,
            strike=True,
            fontsize=18,
            color="15a85f",
            list_type=1,
            rtf_mode='fwd'
        )
        self.assertTrue(len(pkt_rtf) > 50)

    def test_14_build_d3_quote_group_and_1to1(self):
        """Kiểm tra cấu trúc nhị phân D3 Quote chuẩn Zalo cho cả Group và 1-1."""
        from protocol import build_d3_payload_group, build_d3_payload_1to1
        quote_info = {
            "ownerId": 432577723,
            "ts": 1789304172000,
            "globalMsgId": 9876543210,
            "cliMsgId": 1789304172000,
            "cliMsgType": 1,
            "msg": "/ping",
            "attach": "",
            "fromD": "Qbn"
        }

        # 1. Group Quote
        reply_txt = "@Qbn 🏓 Pong! Bot Socket đang trực tuyến mượt mà."
        d3_grp = build_d3_payload_group(reply_txt, ttl_ms=0, quote_data=quote_info)
        self.assertEqual(d3_grp[:5], bytes([0x01, 0x00, 0x03, 0x0b, 0x01]))
        self.assertEqual(struct.unpack_from('<I', d3_grp, 5)[0], 0)
        mention_len = struct.unpack_from('<H', d3_grp, 9)[0]
        self.assertEqual(mention_len, len("@Qbn"))
        owner_id1 = struct.unpack_from('<I', d3_grp, 11)[0]
        self.assertEqual(owner_id1, 432577723)
        self.assertEqual(d3_grp[15], 0x02)
        owner_id2 = struct.unpack_from('<I', d3_grp, 16)[0]
        self.assertEqual(owner_id2, 432577723)
        q_ts = struct.unpack_from('<Q', d3_grp, 20)[0]
        self.assertEqual(q_ts, 1789304172000)
        q_gmi = struct.unpack_from('<Q', d3_grp, 28)[0]
        self.assertEqual(q_gmi, 9876543210)
        q_cmi = struct.unpack_from('<Q', d3_grp, 36)[0]
        self.assertEqual(q_cmi, 1789304172000)
        q_typ = struct.unpack_from('<H', d3_grp, 44)[0]
        self.assertEqual(q_typ, 1)

        # 2. 1-1 Quote
        d3_1to1 = build_d3_payload_1to1(reply_txt, cryptkey=self.cryptkey, ttl_ms=0, quote_data=quote_info)
        self.assertEqual(d3_1to1[:5], bytes([0x29, 0x00, 0x03, 0x0b, 0x01]))
        self.assertEqual(struct.unpack_from('<I', d3_1to1, 5)[0], 0)
        mention_len_1to1 = struct.unpack_from('<H', d3_1to1, 9)[0]
        self.assertEqual(mention_len_1to1, len("@Qbn"))

        # 3. Group Quote with TTL (TTL gắn vào bot reply qua block 0x08, count=4, q_ttl_ms giữ nguyên TTL của tin bị quote)
        d3_grp_ttl = build_d3_payload_group(reply_txt, ttl_ms=30000, quote_data=quote_info)
        self.assertEqual(d3_grp_ttl[:5], bytes([0x01, 0x00, 0x04, 0x0b, 0x01]))
        q_ttl_offset = 50 + len(quote_info['msg'].encode('utf-8')) + len(quote_info['attach'].encode('utf-8'))
        self.assertEqual(struct.unpack_from('<Q', d3_grp_ttl, q_ttl_offset)[0], 0)  # q_ttl_ms = 0
        self.assertIn(bytes([0x08]) + struct.pack('<I', 30000) + bytes(4), d3_grp_ttl)  # block TTL của bot reply
        self.assertTrue(d3_grp_ttl.endswith(reply_txt.encode('utf-8')))

    def test_15_build_pin_unpin_disband_packets(self):
        """Kiểm tra cấu trúc nhị phân của Pin, Unpin và Disband (bb=0, ty=1, basic checksum, xor_enc)."""
        from protocol import (
            build_pin_topic_packet, build_unpin_topic_packet, build_disband_group_packet,
            build_block_group_member_packet, build_block_user_packet,
            build_leave_group_packet, build_leave_group_225_packet, build_create_poll_packet, build_delete_message_packet,
            dekey, CMD_PIN_TOPIC, SUB_PIN_TOPIC, CMD_UNPIN_TOPIC, SUB_UNPIN_TOPIC
        )

        # 1. Pin Topic (CMD 1752 SUB 2)
        pkt_pin = build_pin_topic_packet(self.uid, self.group_id, title="Test Pin", global_msg_id=8262981726572, seq=-50)
        hdr_pin = InnerPacketHeader.unpack(pkt_pin)
        self.assertEqual(hdr_pin.cmd, CMD_PIN_TOPIC)
        self.assertEqual(hdr_pin.sub, SUB_PIN_TOPIC)
        self.assertEqual(hdr_pin.bb, 0)
        self.assertEqual(hdr_pin.ty, 1)
        self.assertEqual(hdr_pin.ver, 3)
        
        # Verify XOR decoded params
        enc_params = pkt_pin[18:]
        key = dekey(len(enc_params) + 23, self.uid)
        pt = bytes(enc_params[i] ^ key[i % 32] for i in range(len(enc_params)))
        self.assertEqual(pt[0], 0x01) # byte prefix
        vercode = struct.unpack_from('<I', pt, 1)[0]
        self.assertEqual(vercode, 260802903)
        gid = struct.unpack_from('<I', pt, 11)[0]
        self.assertEqual(gid, self.group_id)
        self.assertIn(b'needPin', pt)
        self.assertIn(b'topicType', pt)

        # 2. Unpin Topic (CMD 1703 SUB 0)
        pkt_unpin = build_unpin_topic_packet(self.uid, self.group_id, seq=-51)
        hdr_unpin = InnerPacketHeader.unpack(pkt_unpin)
        self.assertEqual(hdr_unpin.cmd, CMD_UNPIN_TOPIC)
        self.assertEqual(hdr_unpin.sub, SUB_UNPIN_TOPIC)
        self.assertEqual(hdr_unpin.bb, 0)
        self.assertEqual(hdr_unpin.ty, 1)
        
        enc_unpin = pkt_unpin[18:]
        key_u = dekey(len(enc_unpin) + 23, self.uid)
        pt_u = bytes(enc_unpin[i] ^ key_u[i % 32] for i in range(len(enc_unpin)))
        self.assertEqual(pt_u[0], 0x01)
        self.assertEqual(struct.unpack_from('<I', pt_u, 1)[0], 260802903)
        self.assertEqual(struct.unpack_from('<I', pt_u, 11)[0], self.group_id)

        # 3. Disband Group (CMD 242 SUB 0)
        pkt_disband = build_disband_group_packet(self.uid, self.group_id, seq=-52)
        hdr_disband = InnerPacketHeader.unpack(pkt_disband)
        self.assertEqual(hdr_disband.cmd, 242)
        self.assertEqual(hdr_disband.sub, 0)
        self.assertEqual(hdr_disband.bb, 0)
        self.assertEqual(hdr_disband.ty, 1)

        # 4. Block Group Member (CMD 234 SUB 0 with is_block=1)
        pkt_bgm = build_block_group_member_packet(self.uid, self.group_id, [123456], seq=-53)
        hdr_bgm = InnerPacketHeader.unpack(pkt_bgm)
        self.assertEqual(hdr_bgm.cmd, 234)
        self.assertEqual(hdr_bgm.sub, 0)

        # 5. Block User 1-1 (CMD 382 SUB 0)
        pkt_bu = build_block_user_packet(self.uid, 123456, is_block=True, seq=-54)
        hdr_bu = InnerPacketHeader.unpack(pkt_bu)
        self.assertEqual(hdr_bu.cmd, 382)
        self.assertEqual(hdr_bu.sub, 0)

        # 6. Leave Group (CMD 225 SUB 3)
        pkt_lg = build_leave_group_225_packet(self.uid, self.group_id, seq=-55)
        hdr_lg = InnerPacketHeader.unpack(pkt_lg)
        self.assertEqual(hdr_lg.cmd, 225)
        self.assertEqual(hdr_lg.sub, 3)

        # 7. Create Poll (CMD 1640 SUB 3)
        pkt_poll = build_create_poll_packet(self.uid, self.group_id, "Hoi gi?", ["A", "B"], seq=-56)
        hdr_poll = InnerPacketHeader.unpack(pkt_poll)
        self.assertEqual(hdr_poll.cmd, 1640)
        self.assertEqual(hdr_poll.sub, 3)

        # 8. Delete / Recall Message (CMD 205 SUB 3)
        pkt_del = build_delete_message_packet(self.uid, self.group_id, 12345678, seq=-57)
        hdr_del = InnerPacketHeader.unpack(pkt_del)
        self.assertEqual(hdr_del.cmd, 205)
        self.assertEqual(hdr_del.sub, 3)

    def test_16_build_kick_and_add_member_packets(self):
        """Kiểm tra cấu trúc nhị phân của Kick (CMD 234) và Add Member (CMD 235)."""
        from protocol import build_kick_member_packet, build_add_member_packet, dekey, CMD_KICK_MEMBER, CMD_ADD_MEMBER

        # 1. Kick Member (CMD 234 SUB 0, is_block=0)
        target_uid = 987654321
        pkt_kick = build_kick_member_packet(self.uid, self.group_id, member_uids=[target_uid], is_block=False, seq=-60)
        hdr_kick = InnerPacketHeader.unpack(pkt_kick)
        self.assertEqual(hdr_kick.cmd, CMD_KICK_MEMBER)
        self.assertEqual(hdr_kick.sub, 0)
        self.assertEqual(hdr_kick.bb, 0)
        self.assertEqual(hdr_kick.ty, 1)
        self.assertEqual(hdr_kick.ver, 3)

        # Giải mã XOR params kiểm tra payload nhị phân
        enc_params = pkt_kick[18:]
        key = dekey(len(enc_params) + 23, self.uid)
        pt = bytes(enc_params[i] ^ key[i % 32] for i in range(len(enc_params)))
        gid, is_block, count, member_id = struct.unpack('<IBII', pt)
        self.assertEqual(gid, self.group_id)
        self.assertEqual(is_block, 0)
        self.assertEqual(count, 1)
        self.assertEqual(member_id, target_uid)

        # 2. Ban Member (CMD 234 SUB 0, is_block=1)
        pkt_ban = build_kick_member_packet(self.uid, self.group_id, member_uids=[target_uid], is_block=True, seq=-61)
        enc_ban = pkt_ban[18:]
        key_ban = dekey(len(enc_ban) + 23, self.uid)
        pt_ban = bytes(enc_ban[i] ^ key_ban[i % 32] for i in range(len(enc_ban)))
        gid_b, is_block_b, count_b, member_id_b = struct.unpack('<IBII', pt_ban)
        self.assertEqual(is_block_b, 1)

        # 3. Add Member (CMD 235 SUB 0, is_invite=0)
        uids_to_add = [111222333, 444555666]
        pkt_add = build_add_member_packet(self.uid, self.group_id, member_uids=uids_to_add, is_invite=False, seq=-62)
        hdr_add = InnerPacketHeader.unpack(pkt_add)
        self.assertEqual(hdr_add.cmd, CMD_ADD_MEMBER)
        self.assertEqual(hdr_add.sub, 0)
        self.assertEqual(hdr_add.bb, 0)
        self.assertEqual(hdr_add.ty, 1)

        enc_add = pkt_add[18:]
        key_add = dekey(len(enc_add) + 23, self.uid)
        pt_add = bytes(enc_add[i] ^ key_add[i % 32] for i in range(len(enc_add)))
        gid_a = struct.unpack_from('<I', pt_add, 0)[0]
        is_inv = pt_add[4]
        count_a = struct.unpack_from('<I', pt_add, 5)[0]
        self.assertEqual(gid_a, self.group_id)
        self.assertEqual(is_inv, 0)
        self.assertEqual(count_a, 2)
        m1 = struct.unpack_from('<I', pt_add, 9)[0]
        m2 = struct.unpack_from('<I', pt_add, 13)[0]
        self.assertEqual(m1, uids_to_add[0])
        self.assertEqual(m2, uids_to_add[1])

    def test_17_build_join_group_packets(self):
        """Kiểm tra cấu trúc nhị phân của Join Group (CMD 246 SUB 3) và Join Group Invite (CMD 250 SUB 1)."""
        from protocol import dekey

        # 1. Join Group by ID (CMD 246 SUB 3)
        now_ts = 1789304567000
        pkt_join = build_join_group_packet(self.uid, self.group_id, source=0, seq=-70, ts_ms=now_ts)
        hdr_join = InnerPacketHeader.unpack(pkt_join)
        self.assertEqual(hdr_join.cmd, CMD_JOIN_GROUP)
        self.assertEqual(hdr_join.sub, SUB_JOIN_GROUP)
        self.assertEqual(hdr_join.bb, 0)
        self.assertEqual(hdr_join.ty, 1)
        self.assertEqual(hdr_join.ver, 3)

        enc_params = pkt_join[18:]
        key = dekey(len(enc_params) + 23, self.uid)
        pt = bytes(enc_params[i] ^ key[i % 32] for i in range(len(enc_params)))
        self.assertEqual(pt[0], 0x01)
        vercode = struct.unpack_from('<I', pt, 1)[0]
        self.assertEqual(vercode, 260802903)
        str_len = struct.unpack_from('<I', pt, 5)[0]
        self.assertEqual(str_len, 0)
        lang = struct.unpack_from('<H', pt, 9)[0]
        self.assertEqual(lang, 0)
        gid = struct.unpack_from('<I', pt, 11)[0]
        self.assertEqual(gid, self.group_id)
        source = struct.unpack_from('<I', pt, 15)[0]
        self.assertEqual(source, 0)
        ts_val = struct.unpack_from('<q', pt, 19)[0]
        self.assertEqual(ts_val, now_ts)

        # 2. Join Group Invite (CMD 250 SUB 1)
        inviter_uid = 333444555
        pkt_inv = build_join_group_invite_packet(self.uid, self.group_id, inviter_uid=inviter_uid, seq=-71)
        hdr_inv = InnerPacketHeader.unpack(pkt_inv)
        self.assertEqual(hdr_inv.cmd, CMD_JOIN_GROUP_INVITE)
        self.assertEqual(hdr_inv.sub, SUB_JOIN_GROUP_INVITE)
        self.assertEqual(hdr_inv.bb, 0)
        self.assertEqual(hdr_inv.ty, 1)
        self.assertEqual(hdr_inv.ver, 3)

        enc_inv = pkt_inv[18:]
        key_inv = dekey(len(enc_inv) + 23, self.uid)
        pt_inv = bytes(enc_inv[i] ^ key_inv[i % 32] for i in range(len(enc_inv)))
        self.assertEqual(pt_inv[0], 0x01)
        gid_inv = struct.unpack_from('<I', pt_inv, 11)[0]
        self.assertEqual(gid_inv, self.group_id)
        inv_uid = struct.unpack_from('<q', pt_inv, 15)[0]
        self.assertEqual(inv_uid, inviter_uid)

    def test_18_build_recall_and_unblock_and_request_join_packets(self):
        """Kiểm tra cấu trúc nhị phân của Recall (CMD 204/114), Unblock (CMD 383), và Request Join (CMD 244)."""
        from protocol import (
            build_recall_message_packet,
            build_unblock_user_packet,
            build_request_join_group_packet,
            dekey,
            xor_decode_d3,
            CMD_RECALL_MSG_GROUP,
            SUB_RECALL_MSG_GROUP,
            CMD_RECALL_MSG_1TO1,
            SUB_RECALL_MSG_1TO1,
            CMD_UNBLOCK_USER_1TO1,
            CMD_REQUEST_JOIN_GROUP,
            SUB_REQUEST_JOIN_GROUP
        )

        # 1. Group Recall (CMD 204 SUB 2)
        c_msg = 1789304567890
        g_msg = 9876543210123
        pkt_rec_g = build_recall_message_packet(
            uid=self.uid,
            target_id=self.group_id,
            cli_msg_id=c_msg,
            global_msg_id=g_msg,
            is_group=True,
            seq=-80
        )
        hdr_rec_g = InnerPacketHeader.unpack(pkt_rec_g)
        self.assertEqual(hdr_rec_g.cmd, CMD_RECALL_MSG_GROUP)
        self.assertEqual(hdr_rec_g.sub, SUB_RECALL_MSG_GROUP)
        self.assertEqual(hdr_rec_g.bb, 0)
        self.assertEqual(hdr_rec_g.ty, 2)

        enc_rec = pkt_rec_g[18:]
        key_rec = dekey(len(enc_rec) + 23, self.uid)
        pt_rec = bytes(enc_rec[i] ^ key_rec[i % 32] for i in range(len(enc_rec)))
        self.assertEqual(len(pt_rec), 41)
        tgt_id, t_type, c_counter, magic = struct.unpack_from('<IBII', pt_rec, 0)
        self.assertEqual(tgt_id, self.group_id)
        self.assertEqual(t_type, 4)
        self.assertEqual(magic, 416)
        
        d3_plain = xor_decode_d3(pt_rec[13:], self.uid)
        tgt, cmi, gmi, mtype, owner = struct.unpack('<IqqII', d3_plain)
        self.assertEqual(tgt, self.group_id)
        self.assertEqual(gmi, g_msg)
        self.assertEqual(cmi, c_msg)
        self.assertEqual(mtype, 1)
        self.assertEqual(owner, self.uid)

        # 2. 1-1 Recall (CMD 114 SUB 2)
        target_friend = 555666777
        pkt_rec_1 = build_recall_message_packet(
            uid=self.uid,
            target_id=target_friend,
            cli_msg_id=c_msg,
            global_msg_id=g_msg,
            is_group=False,
            seq=-81
        )
        hdr_rec_1 = InnerPacketHeader.unpack(pkt_rec_1)
        self.assertEqual(hdr_rec_1.cmd, CMD_RECALL_MSG_1TO1)
        self.assertEqual(hdr_rec_1.sub, SUB_RECALL_MSG_1TO1)

        # 3. Unblock User (CMD 383 SUB 0)
        pkt_unblk = build_unblock_user_packet(uid=self.uid, target_uid=target_friend, seq=-82)
        hdr_unblk = InnerPacketHeader.unpack(pkt_unblk)
        self.assertEqual(hdr_unblk.cmd, CMD_UNBLOCK_USER_1TO1)
        self.assertEqual(hdr_unblk.sub, 0)
        self.assertEqual(hdr_unblk.bb, 0)
        self.assertEqual(hdr_unblk.ty, 1)

        enc_unblk = pkt_unblk[18:]
        key_unblk = dekey(len(enc_unblk) + 23, self.uid)
        pt_unblk = bytes(enc_unblk[i] ^ key_unblk[i % 32] for i in range(len(enc_unblk)))
        self.assertEqual(pt_unblk[0], 0x01)
        u_unblk = struct.unpack_from('<I', pt_unblk, 5)[0]
        self.assertEqual(u_unblk, target_friend)

        # 4. Request Join Group via Link (CMD 244 SUB 4)
        link_str = "krgx195dxdbjx1bm2fbd"
        pkt_req_j = build_request_join_group_packet(
            uid=self.uid,
            group_id=0,
            link_url=link_str,
            msg="Xin vao nhom",
            source=1,
            seq=-83
        )
        hdr_req_j = InnerPacketHeader.unpack(pkt_req_j)
        self.assertEqual(hdr_req_j.cmd, CMD_REQUEST_JOIN_GROUP)
        self.assertEqual(hdr_req_j.sub, SUB_REQUEST_JOIN_GROUP)

        enc_req_j = pkt_req_j[18:]
        key_req_j = dekey(len(enc_req_j) + 23, self.uid)
        pt_j = bytes(enc_req_j[i] ^ key_req_j[i % 32] for i in range(len(enc_req_j)))
        self.assertEqual(pt_j[0], 0x01)
        self.assertEqual(struct.unpack_from('<I', pt_j, 1)[0], 260802903)
        self.assertEqual(struct.unpack_from('<I', pt_j, 11)[0], 0)
        m_len = struct.unpack_from('<I', pt_j, 15)[0]
        self.assertEqual(m_len, len("Xin vao nhom"))
        self.assertEqual(pt_j[19:19+m_len].decode(), "Xin vao nhom")
        off = 19 + m_len
        self.assertEqual(struct.unpack_from('<I', pt_j, off)[0], 1)
        self.assertEqual(pt_j[off+4], 0)
        l_len = struct.unpack_from('<I', pt_j, off+5)[0]
        self.assertEqual(l_len, len(link_str))
        self.assertEqual(pt_j[off+9:off+9+l_len].decode(), link_str)


if __name__ == '__main__':
    unittest.main(verbosity=2)

