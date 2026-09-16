#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/socket/protocol.py — Module Giao thức Nhị phân (Binary Protocol Engine) cho Zalo TCP Socket.
Hỗ trợ đầy đủ:
- Outer Frame Format: [uint32 total_len][uint8 ftype][body]
- Inner Packet Header Format (18 bytes): struct '<IBBiIBHB'
- D3 Message Encoder & Decoder (Group, 1-1, RTF styling, Quote, Mentions, TTL)
- Checksum Calculation (CKSUM_MAGIC = 0x6CE7DAA0)
- Packet Builders: Ping, Typing, Group Msg, 1-1 Msg, Reaction, Pin Topic, Unpin Topic, Disband (CMD 1705)
- Incoming Packet Parsers (Frame Type 3 & 4, CMD 101, 201, 1865, 1867, 202)
"""

import base64
import gzip
import json
import logging
import os
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, Any, List

try:
    from .crypto import (
        encrypt_aes_gcm, decrypt_aes_gcm,
        encrypt_e2ee_cbc, decrypt_e2ee_cbc,
        DEFAULT_XK
    )
except (ImportError, ValueError):
    from crypto import (
        encrypt_aes_gcm, decrypt_aes_gcm,
        encrypt_e2ee_cbc, decrypt_e2ee_cbc,
        DEFAULT_XK
    )

logger = logging.getLogger("core.socket.protocol")

# ---------------------------------------------------------------------------
# 1. Hằng số Giao thức (Protocol Constants)
# ---------------------------------------------------------------------------

CKSUM_MAGIC = 0x6CE7DAA0
MAGIC_CHECKSUM_XOR = 0x6CE7DAA0
XK = DEFAULT_XK

# Outer Frame Types
FRAME_TYPE_CONTROL = 3
FRAME_TYPE_DATA = 4
FRAME_TYPE_KEY_EXCHANGE = 6
FRAME_TYPE_HANDSHAKE = 8

# Inner Command Codes & Sub Codes
CMD_PING = 1971
SUB_PING = 0

CMD_GROUP_MSG = 207
SUB_GROUP_MSG = 1

CMD_1TO1_MSG = 113
SUB_1TO1_MSG = 41

CMD_GROUP_TYPING = 206
SUB_GROUP_TYPING = 1

CMD_1TO1_TYPING = 106
SUB_1TO1_TYPING = 1

CMD_GROUP_PREPARE = 203
SUB_GROUP_PREPARE = 4

CMD_GROUP_SYNC_BROADCAST = 1867
SUB_GROUP_SYNC = 0

CMD_DELIVERY_RECEIPT = 202
SUB_DELIVERY_RECEIPT = 3

CMD_1TO1_INCOMING = 101

CMD_REMOVE_MEMBER = 228
SUB_REMOVE_MEMBER = 0

CMD_KICK_MEMBER = 234
SUB_KICK_MEMBER = 0

CMD_DISBAND_GROUP = 242
SUB_DISBAND_GROUP = 0

CMD_BLOCK_GROUP_MEMBER = 238
SUB_BLOCK_GROUP_MEMBER = 4

CMD_BLOCK_USER = 821
SUB_BLOCK_USER = 3

CMD_ADD_MEMBER = 235
SUB_ADD_MEMBER = 0

CMD_LEAVE_GROUP = 239
SUB_LEAVE_GROUP = 1
CMD_LEAVE_GROUP_225 = 225
SUB_LEAVE_GROUP_225 = 3
CMD_LEAVE_GROUP_239 = 239
SUB_LEAVE_GROUP_239 = 1

CMD_JOIN_GROUP = 246
SUB_JOIN_GROUP = 3

CMD_JOIN_GROUP_INVITE = 250
SUB_JOIN_GROUP_INVITE = 1

CMD_REQUEST_JOIN_GROUP = 244
SUB_REQUEST_JOIN_GROUP = 4
CMD_GROUP_LINK_INFO = 244
SUB_GROUP_LINK_INFO = 4

# CMD 2000 SUB 3: Join group via link (du/b.smali method h, g:S=0x7d0)
CMD_JOIN_GROUP_BY_LINK = 2000
SUB_JOIN_GROUP_BY_LINK = 3

CMD_PIN_TOPIC = 1752
SUB_PIN_TOPIC = 2

CMD_UNPIN_TOPIC = 1708
SUB_UNPIN_TOPIC = 0

CMD_CREATE_POLL = 1640
SUB_CREATE_POLL = 3

CMD_RECALL_MSG_GROUP = 204
SUB_RECALL_MSG_GROUP = 2

CMD_RECALL_MSG_1TO1 = 114
SUB_RECALL_MSG_1TO1 = 2

CMD_DELETE_MSG = 205
SUB_DELETE_MSG = 3

CMD_BLOCK_USER_1TO1 = 382
SUB_BLOCK_USER_1TO1 = 0

CMD_UNBLOCK_USER_1TO1 = 383
SUB_UNBLOCK_USER_1TO1 = 0

# Struct format Header 18 bytes:
INNER_HEADER_FORMAT = '<IBBiIBHB'  # uint32 ck, uint8 bb, uint8 ty, int32 seq, uint32 uid, uint8 ver, uint16 cmd, uint8 sub
INNER_HEADER_SIZE = 18


# ---------------------------------------------------------------------------
# 2. Data Structures
# ---------------------------------------------------------------------------

@dataclass
class InnerPacketHeader:
    ck: int      # uint32: Clock counter / Checksum
    bb: int      # uint8 : Broadcast flag (0 hoặc 1)
    ty: int      # uint8 : Clock domain type (1: system/ping, 2: message)
    seq: int     # int32 : Sequence number (âm đối với C2S, 0 đối với S2C)
    uid: int     # uint32: User ID
    ver: int     # uint8 : Protocol version (mặc định: 3)
    cmd: int     # uint16: Command code
    sub: int     # uint8 : Sub command code

    def pack(self) -> bytes:
        return struct.pack(
            INNER_HEADER_FORMAT,
            self.ck & 0xFFFFFFFF,
            self.bb & 0xFF,
            self.ty & 0xFF,
            self.seq,
            self.uid & 0xFFFFFFFF,
            self.ver & 0xFF,
            self.cmd & 0xFFFF,
            self.sub & 0xFF
        )

    @classmethod
    def unpack(cls, data: bytes) -> 'InnerPacketHeader':
        if len(data) < INNER_HEADER_SIZE:
            raise ValueError(f"Dữ liệu không đủ {INNER_HEADER_SIZE} bytes để đọc Header (nhận {len(data)} bytes).")
        ck, bb, ty, seq, uid, ver, cmd, sub = struct.unpack_from(INNER_HEADER_FORMAT, data, 0)
        return cls(ck=ck, bb=bb, ty=ty, seq=seq, uid=uid, ver=ver, cmd=cmd, sub=sub)


@dataclass
class OuterFrame:
    total_len: int  # uint32 LE (bao gồm 4 bytes len + 1 byte type + body)
    ftype: int      # uint8
    body: bytes     # Raw payload hoặc Ciphertext (AES-256-GCM)

    def pack(self) -> bytes:
        return struct.pack('<IB', len(self.body) + 5, self.ftype) + self.body

    @classmethod
    def unpack_from_buffer(cls, buf: bytes) -> Optional[Tuple['OuterFrame', int]]:
        """
        Bóc tách một Outer Frame hoàn chỉnh từ stream buffer.
        Trả về (OuterFrame, bytes_consumed) hoặc None nếu buffer chưa nhận đủ dữ liệu.
        """
        if len(buf) < 5:
            return None
        total_len = struct.unpack_from('<I', buf, 0)[0]
        if total_len < 5:
            raise ValueError(f"Outer frame total_len không hợp lệ: {total_len}")
        if len(buf) < total_len:
            return None

        ftype = buf[4]
        body = buf[5:total_len]
        return cls(total_len=total_len, ftype=ftype, body=body), total_len


# ---------------------------------------------------------------------------
# 3. Checksum & D3 XOR Encoders
# ---------------------------------------------------------------------------

def compute_checksum(
    cmd: int, sub: int, seq: int, uid: int,
    target: int = 0, target_type: int = 0, cmsg: int = 0,
    bb: int = 1, ty: int = 2, ver: int = 3
) -> int:
    """
    Tính Checksum ck_val:
    ck_val = (bb + ty + seq + uid + ver + cmd + sub + target + target_type + cmsg) mod 2^32 XOR 0x6ce7daa0
    """
    total = (bb + ty + seq + uid + ver + cmd + sub + target + target_type + cmsg) & 0xFFFFFFFF
    return total ^ MAGIC_CHECKSUM_XOR


def xor_encode_d3(plain: bytes, uid: int, xk: bytes = XK) -> bytes:
    """
    Mã hóa XOR 2 lớp cho payload D3 dựa trên chiều dài payload và UID.
    """
    a4 = len(plain) + 36
    le4 = struct.pack('<I', a4)
    ule = struct.pack('<I', uid & 0xFFFFFFFF)
    k = bytes(xk[i % 32] ^ le4[i % 4] ^ ule[i % 4] for i in range(32))
    return bytes(plain[i] ^ k[i % 32] for i in range(len(plain)))


def xor_decode_d3(cipher: bytes, uid: int, xk: bytes = XK) -> bytes:
    """
    Giải mã XOR D3 (phép toán đối xứng).
    """
    return xor_encode_d3(cipher, uid, xk)


def dekey(a4: int, uid: int) -> bytes:
    """doEncryptData keystream: XK ^ le32(a4) ^ le32(uid), cyclic-32"""
    ule = struct.pack('<I', uid & 0xFFFFFFFF)
    k1 = bytes(XK[i % 32] ^ struct.pack('<I', a4)[i % 4] for i in range(32))
    return bytes(k1[i % 32] ^ ule[i % 4] for i in range(32))


def xor_enc(pt: bytes, uid: int) -> bytes:
    """encode plaintext params (a4 = len + 23)"""
    key = dekey(len(pt) + 23, uid)
    return bytes(pt[i] ^ key[i % 32] for i in range(len(pt)))


# ---------------------------------------------------------------------------
# 4. Message Builders (Xây dựng Gói tin D3)
# ---------------------------------------------------------------------------

def build_d3_payload_group(
    text: str,
    ttl_ms: int = 0,
    quote_data: Optional[Dict[str, Any]] = None,
    mentions: Optional[List[Dict[str, Any]]] = None,
    style_id: Optional[int] = None,
    size: Optional[int] = None,
    color: Optional[str] = None,
    bold: bool = False,
    italic: bool = False,
    underline: bool = False,
    strike: bool = False,
    fontsize: Optional[int] = None,
    list_type: Optional[int] = None,
    rtf_mode: str = 'fwd'
) -> bytes:
    """
    Xây dựng cấu trúc nhị phân D3 cho tin nhắn nhóm (hỗ trợ Text thường, Quote trích dẫn, Mention, Style và TTL tự xóa).
    """
    ttl_ms = int(ttl_ms or 0)
    prop_obj = {
        'sSrcType': -1,
        'sSrcStr': '',
        'msg_warning_type': 0,
        'emoji': {'content': 0, 'num': 0, 'uniq': 0, 'first': '', 'last': '', 'most': '', 'text': 1}
    }
    if style_id is not None:
        prop_obj['decorInfo'] = {"decorType": 4, "typoId": int(style_id)}
    if mentions:
        prop_obj['mentions'] = mentions
    if ttl_ms > 0:
        prop_obj['ttl'] = ttl_ms

    # Zalo Native RichTextFormat (TextStyle Spans)
    style_tags = []
    if bold:
        style_tags.append("b")
    if italic:
        style_tags.append("i")
    if underline:
        style_tags.append("u")
    if strike:
        style_tags.append("s")
    if fontsize is not None:
        style_tags.append(f"f_{int(fontsize)}")
    if color:
        c_clean = str(color).lstrip('#').lower()
        style_tags.append(f"c_{c_clean}")
    if list_type:
        style_tags.append(f"lst_{int(list_type)}")

    if style_tags:
        u16_len = len(text.encode('utf-16-le')) // 2
        prop_obj["styles"] = [{"start": 0, "len": u16_len, "st": ",".join(style_tags)}]
        prop_obj["ver"] = 0

    prop_bytes = json.dumps(prop_obj, separators=(',', ':')).encode('utf-8')
    text_bytes = text.encode('utf-8')

    size_val = struct.pack('<i', size if size is not None else -1)
    if color:
        color_int = int(str(color).lstrip('#'), 16)
        color_val = struct.pack('<i', color_int if color_int < 2**31 else color_int - 2**32)
    else:
        color_val = struct.pack('<i', -1)
    
    type_v = -1
    if bold and italic:
        type_v = 3
    elif bold:
        type_v = 1
    elif italic:
        type_v = 2
    type_val = struct.pack('<i', type_v)
    style_hdr = size_val + color_val + type_val

    if quote_data:
        q_uid = int(quote_data.get('ownerId') or quote_data.get('uid') or 0)
        q_ts = int(quote_data.get('ts') or int(time.time() * 1000))
        q_gmi = int(quote_data.get('globalMsgId') or 0)
        q_cmi = int(quote_data.get('cliMsgId') or int(time.time() * 1000))
        q_typ = int(quote_data.get('cliMsgType') or 1)
        q_text_bytes = str(quote_data.get('msg') or '').encode('utf-8')
        q_attach_bytes = str(quote_data.get('attach') or '').encode('utf-8')
        q_ttl_ms = int(quote_data.get('ttl') or 0)

        mention_len = 0
        if quote_data.get('fromD'):
            tag = f"@{quote_data['fromD']}"
            if text.startswith(tag):
                mention_len = len(tag.encode('utf-16-le')) // 2
        if mention_len == 0 and quote_data.get('ownerId'):
            tag_uid = f"@{quote_data['ownerId']}"
            if text.startswith(tag_uid):
                mention_len = len(tag_uid.encode('utf-16-le')) // 2
        if mention_len == 0 and text.startswith('@'):
            parts = text.split(' ', 1)
            mention_len = len(parts[0].encode('utf-16-le')) // 2

        count_byte = 0x04 if ttl_ms > 0 else 0x03
        buf = bytearray()
        buf += bytes([0x01, 0x00, count_byte, 0x0b, 0x01])
        buf += struct.pack('<I', 0)                  # 4 bytes 0x00000000
        buf += struct.pack('<H', mention_len)        # 2 bytes độ dài mention tag
        buf += struct.pack('<I', q_uid)              # 4 bytes Quoted Owner UID
        buf += bytes([0x02])                         # 1 byte 0x02
        buf += struct.pack('<I', q_uid)              # 4 bytes Quoted Owner UID
        buf += struct.pack('<Q', q_ts)               # 8 bytes Quoted Timestamp ms
        buf += struct.pack('<Q', q_gmi)              # 8 bytes Quoted GlobalMsgId
        buf += struct.pack('<Q', q_cmi)              # 8 bytes Quoted CliMsgId
        buf += struct.pack('<H', q_typ)              # 2 bytes Quoted CliMsgType
        buf += struct.pack('<H', len(q_text_bytes)) + q_text_bytes     # Length-prefixed quoted text
        buf += struct.pack('<H', len(q_attach_bytes)) + q_attach_bytes # Length-prefixed quoted attach
        buf += struct.pack('<Q', q_ttl_ms)           # 8 bytes Quoted TTL ms (TTL của tin bị quote)
        buf += struct.pack('<H', 7)                  # 2 bytes 0x0007
        buf += style_hdr                             # 12 bytes style header (size, color, type_val)
        buf += struct.pack('<I', len(prop_bytes)) + prop_bytes         # Length-prefixed property JSON
        if ttl_ms > 0:
            buf += bytes([0x08]) + struct.pack('<I', ttl_ms) + bytes(4) # Block TTL của tin nhắn phản hồi (Bot)
        buf += text_bytes                            # Message text UTF-8
        return bytes(buf)

    if ttl_ms > 0:
        header = bytearray([0x01, 0x00, 0x02, 0x07, 0x00]) + style_hdr + struct.pack('<I', len(prop_bytes)) + prop_bytes
        ttl_block = bytes([0x08]) + struct.pack('<I', ttl_ms) + bytes(4)
        return header + ttl_block + text_bytes

    header = bytearray([0x01, 0x00, 0x01, 0x07, 0x00]) + style_hdr + struct.pack('<I', len(prop_bytes)) + prop_bytes
    return bytes(header + text_bytes)


def build_d3_json(style_id: Optional[int] = None) -> bytes:
    """JSON metadata cho D3 — style_id → thêm decorInfo (font/kiểu chữ)"""
    if style_id:
        obj = {
            "sSrcType": -1,
            "sSrcStr": "",
            "decorInfo": {"decorType": 4, "typoId": style_id},
            "msg_warning_type": 0,
            "emoji": {"content": 0, "num": 0, "uniq": 0, "first": "", "last": "", "most": "", "text": 1}
        }
        return json.dumps(obj, separators=(',', ':')).encode('utf-8')
    return b'{"sSrcType":-1,"sSrcStr":"","msg_warning_type":0,"emoji":{"content":0,"num":0,"uniq":0,"first":"","last":"","most":"","text":1}}'


def build_d3_payload_1to1(
    text: str,
    cryptkey: bytes,
    ttl_ms: int = 0,
    quote_data: Optional[Dict[str, Any]] = None
) -> bytes:
    """
    Xây dựng cấu trúc nhị phân D3 cho tin nhắn 1-1 (mã hóa E2EE bằng AES-128-CBC với CryptKey).
    """
    ttl_ms = int(ttl_ms or 0)
    ct, iv = encrypt_e2ee_cbc(text.encode('utf-8'), cryptkey)
    text_block = bytes([0x01]) + iv + struct.pack('<H', len(ct)) + ct

    prop_obj = {
        'sSrcType': -1,
        'sSrcStr': '',
        'msg_warning_type': 0,
        'emoji': {'content': 0, 'num': 0, 'uniq': 0, 'first': '', 'last': '', 'most': '', 'text': 1}
    }
    if ttl_ms > 0:
        prop_obj['ttl'] = ttl_ms
    prop_bytes = json.dumps(prop_obj, separators=(',', ':')).encode('utf-8')

    if not quote_data:
        if ttl_ms > 0:
            ttl_block = bytes([0x08]) + struct.pack('<I', ttl_ms) + bytes(4)
            prop_header = bytes([0x29, 0x00, 0x02, 0x07, 0x00]) + (b'\xff' * 12) + struct.pack('<I', len(prop_bytes)) + prop_bytes
            return prop_header + ttl_block + text_block

        prop_header = bytes([0x29, 0x00, 0x01, 0x07, 0x00]) + (b'\xff' * 12) + struct.pack('<I', len(prop_bytes)) + prop_bytes
        return prop_header + text_block

    q_uid = int(quote_data.get('ownerId') or quote_data.get('uid') or 0)
    q_ts = int(quote_data.get('ts') or int(time.time() * 1000))
    q_gmi = int(quote_data.get('globalMsgId') or 0)
    q_cmi = int(quote_data.get('cliMsgId') or int(time.time() * 1000))
    q_typ = int(quote_data.get('cliMsgType') or 1)
    q_text_bytes = str(quote_data.get('msg') or '').encode('utf-8')
    q_attach_bytes = str(quote_data.get('attach') or '').encode('utf-8')
    q_ttl_ms = int(quote_data.get('ttl') or 0)

    mention_len = 0
    if quote_data.get('fromD'):
        tag = f"@{quote_data['fromD']}"
        if text.startswith(tag):
            mention_len = len(tag.encode('utf-16-le')) // 2
    if mention_len == 0 and quote_data.get('ownerId'):
        tag_uid = f"@{quote_data['ownerId']}"
        if text.startswith(tag_uid):
            mention_len = len(tag_uid.encode('utf-16-le')) // 2
    if mention_len == 0 and text.startswith('@'):
        parts = text.split(' ', 1)
        mention_len = len(parts[0].encode('utf-16-le')) // 2

    count_byte = 0x04 if ttl_ms > 0 else 0x03
    buf = bytearray()
    buf += bytes([0x29, 0x00, count_byte, 0x0b, 0x01])
    buf += struct.pack('<I', 0)
    buf += struct.pack('<H', mention_len)
    buf += struct.pack('<I', q_uid)
    buf += bytes([0x02])
    buf += struct.pack('<I', q_uid)
    buf += struct.pack('<Q', q_ts)
    buf += struct.pack('<Q', q_gmi)
    buf += struct.pack('<Q', q_cmi)
    buf += struct.pack('<H', q_typ)
    buf += struct.pack('<H', len(q_text_bytes)) + q_text_bytes
    buf += struct.pack('<H', len(q_attach_bytes)) + q_attach_bytes
    buf += struct.pack('<Q', q_ttl_ms)           # 8 bytes Quoted TTL ms (0 nếu không có)
    buf += struct.pack('<H', 7)
    buf += b'\xff' * 12
    buf += struct.pack('<I', len(prop_bytes)) + prop_bytes
    if ttl_ms > 0:
        buf += bytes([0x08]) + struct.pack('<I', ttl_ms) + bytes(4) # Block TTL của tin nhắn phản hồi
    buf += text_block
    return bytes(buf)


def build_d3_payload_1to1_styled(
    text: str,
    cryptkey: bytes,
    style_id: Optional[int] = None,
    size: Optional[int] = None,
    color: Optional[str] = None,
    bold: bool = False,
    italic: bool = False,
    ttl_ms: int = 0
) -> bytes:
    """
    Xây dựng D3 payload cho tin nhắn 1-1 có style (kiểu chữ typoId, kích thước, màu sắc, bold/italic).
    """
    ct, iv = encrypt_e2ee_cbc(text.encode('utf-8'), cryptkey)
    js = build_d3_json(style_id)
    
    size_val = struct.pack('<i', size if size is not None else -1)
    if color:
        color_int = int(color.lstrip('#'), 16)
        color_val = struct.pack('<i', color_int if color_int < 2**31 else color_int - 2**32)
    else:
        color_val = struct.pack('<i', -1)
    
    type_v = -1
    if bold and italic:
        type_v = 3
    elif bold:
        type_v = 1
    elif italic:
        type_v = 2
    type_val = struct.pack('<i', type_v)

    if ttl_ms > 0:
        ttl_field = bytes([0x08]) + struct.pack('<I', ttl_ms) + b'\x00\x00\x00\x00'
        head_ttl = (bytes([41, 0x00, 0x02, 0x07, 0x00]) + size_val + color_val + type_val
                    + struct.pack('<I', len(js)) + js)
        return head_ttl + ttl_field + bytes([0x01]) + iv + struct.pack('<H', len(ct)) + ct

    head = (bytes([41, 0x00, 0x01, 0x07, 0x00]) + size_val + color_val + type_val
            + struct.pack('<I', len(js)) + js)
    return head + bytes([0x01]) + iv + struct.pack('<H', len(ct)) + ct


def build_d3_payload_1to1_rtf(
    text: str,
    cryptkey: bytes,
    styles: List[Dict[str, Any]],
    rtf_mode: str = 'fwd',
    list_type: Optional[int] = None
) -> bytes:
    """
    Xây dựng D3 payload cho tin nhắn 1-1 Rich Text Formatting (RTF Spans).
    """
    import gzip, secrets
    ct, iv = encrypt_e2ee_cbc(text.encode('utf-8'), cryptkey)
    
    applied_styles = list(styles)
    if list_type:
        lines = text.split('\n')
        off = 0
        for ln in lines:
            applied_styles.append({"start": off, "len": len(ln) or 1, "st": f"lst_{list_type}"})
            off += len(ln) + 1

    styles_js = json.dumps({"styles": applied_styles, "ver": 0}, separators=(',', ':')).encode('utf-8')
    prop_js = b'{"sSrcType":-1,"sSrcStr":"","msg_warning_type":0}'

    if rtf_mode == 'fwd':
        ts = int(time.time() * 1000)
        mid = secrets.token_hex(16)
        root_ts = ts - 30000
        root_id = secrets.token_hex(16)
        fw_meta = json.dumps({"ts": ts, "id": mid, "cl": -1, "logSrcType": 1,
                              "rootMsgRef": {"ts": root_ts, "id": root_id, "logSrcType": 1},
                              "fwLvl": 2}, separators=(',', ':')).encode('utf-8')
        fw_info = json.dumps({"s": 0, "ds": -1, "ld": {"lat": 0, "lon": 0}, "v": {"ic": 0},
                              "ph": {"st": 0},
                              "fw": {"pmsg": {"st": 1, "ts": ts, "id": mid},
                                     "rmsg": {"st": 1, "ts": root_ts, "id": root_id}},
                              }, separators=(',', ':')).encode('utf-8')
        fw_gz = gzip.compress(fw_info)
        return (bytes([41, 0x00, 0x04, 0x05, 0x03, 0x00, 0x00, 0x00])
                + struct.pack('<I', len(fw_meta)) + fw_meta
                + bytes([0x06]) + struct.pack('<I', len(fw_gz)) + fw_gz
                + bytes([0x07, 0x00]) + struct.pack('<i', -1) + struct.pack('<I', 0x80000000)
                + struct.pack('<i', -1) + struct.pack('<I', len(prop_js)) + prop_js
                + bytes([0x0f]) + struct.pack('<I', len(styles_js)) + styles_js
                + bytes([0x01]) + iv + struct.pack('<H', len(ct)) + ct)
    elif rtf_mode == 'nofwd':
        js = build_d3_json(None)
        return (bytes([41, 0x00, 0x02, 0x07, 0x00])
                + struct.pack('<i', -1) + struct.pack('<i', -1) + struct.pack('<i', -1)
                + struct.pack('<I', len(js)) + js
                + bytes([0x0f]) + struct.pack('<I', len(styles_js)) + styles_js
                + bytes([0x01]) + iv + struct.pack('<H', len(ct)) + ct)
    else:
        return (bytes([41, 0x00, 0x02, 0x05, 0x03, 0x00, 0x00, 0x00])
                + bytes([0x07, 0x00]) + struct.pack('<i', -1) + struct.pack('<I', 0x80000000)
                + struct.pack('<i', -1) + struct.pack('<I', len(prop_js)) + prop_js
                + bytes([0x0f]) + struct.pack('<I', len(styles_js)) + styles_js
                + bytes([0x01]) + iv + struct.pack('<H', len(ct)) + ct)


# ---------------------------------------------------------------------------
# 5. Packet Builders (Tạo gói tin Inner Packet)
# ---------------------------------------------------------------------------

def build_ping_packet(uid: int, seq: int, ck_val: int = 0, dest: int = 335694418) -> bytes:
    """Tạo Inner Packet Heartbeat Keepalive (CMD 1971 SUB 0)."""
    if ck_val == 0:
        ck_val = compute_checksum(CMD_PING, SUB_PING, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=CMD_PING, sub=SUB_PING)
    pt = b'\x01' + struct.pack('<I', dest & 0xFFFFFFFF)
    params = xor_enc(pt, uid)
    return hdr.pack() + params


def build_typing_packet(
    uid: int, target_id: int, is_group: bool,
    seq: int, ck_val: int, cmsg_id: int
) -> bytes:
    """Tạo Inner Packet Typing notification (CMD 206 / CMD 106)."""
    cmd = CMD_GROUP_TYPING if is_group else CMD_1TO1_TYPING
    hdr = InnerPacketHeader(ck=ck_val, bb=1, ty=2, seq=seq, uid=uid, ver=3, cmd=cmd, sub=SUB_GROUP_TYPING)
    params = struct.pack('<IBII', target_id & 0xFFFFFFFF, 3, cmsg_id & 0xFFFFFFFF, 416)
    return hdr.pack() + params


def build_group_message_packet(
    uid: int, group_id: int, text: str,
    seq: int, ck_val: int, cmsg_id: int,
    ttl_ms: int = 0, quote_data: Optional[dict] = None,
    mentions: Optional[list] = None,
    style_id: Optional[int] = None,
    size: Optional[int] = None,
    color: Optional[str] = None,
    bold: bool = False,
    italic: bool = False,
    underline: bool = False,
    strike: bool = False,
    fontsize: Optional[int] = None,
    list_type: Optional[int] = None,
    rtf_mode: str = 'fwd'
) -> bytes:
    """Tạo Inner Packet gửi tin nhắn nhóm (CMD 207 SUB 1)."""
    hdr = InnerPacketHeader(ck=ck_val, bb=1, ty=2, seq=seq, uid=uid, ver=3, cmd=CMD_GROUP_MSG, sub=SUB_GROUP_MSG)
    d3_plain = build_d3_payload_group(
        text, ttl_ms=ttl_ms, quote_data=quote_data, mentions=mentions,
        style_id=style_id, size=size, color=color, bold=bold, italic=italic,
        underline=underline, strike=strike, fontsize=fontsize, list_type=list_type,
        rtf_mode=rtf_mode
    )
    d3_xor = xor_encode_d3(d3_plain, uid)
    params_prefix = struct.pack('<IBII', group_id & 0xFFFFFFFF, 4, cmsg_id & 0xFFFFFFFF, 416)
    return hdr.pack() + params_prefix + d3_xor


def build_1to1_message_packet(
    uid: int, target_uid: int, text: str, cryptkey: bytes,
    seq: int, ck_val: int, cmsg_id: int,
    ttl_ms: int = 0, quote_data: Optional[dict] = None,
    style_id: Optional[int] = None, size: Optional[int] = None,
    color: Optional[str] = None, bold: bool = False, italic: bool = False,
    underline: bool = False, strike: bool = False, fontsize: Optional[int] = None,
    list_type: Optional[int] = None, rtf_mode: str = 'fwd'
) -> bytes:
    """Tạo Inner Packet gửi tin nhắn 1-1 (CMD 113 SUB 41) hỗ trợ Plaintext, Style, RTF và TTL."""
    hdr = InnerPacketHeader(ck=ck_val, bb=1, ty=2, seq=seq, uid=uid, ver=3, cmd=CMD_1TO1_MSG, sub=SUB_1TO1_MSG)
    
    if color or bold or italic or fontsize or underline or strike or list_type:
        styles = []
        if fontsize: styles.append({"start": 0, "len": len(text), "st": f"f_{fontsize}"})
        if color: styles.append({"start": 0, "len": len(text), "st": f"c_{color.lstrip('#')}"})
        if bold: styles.append({"start": 0, "len": len(text), "st": "b"})
        if italic: styles.append({"start": 0, "len": len(text), "st": "i"})
        if underline: styles.append({"start": 0, "len": len(text), "st": "u"})
        if strike: styles.append({"start": 0, "len": len(text), "st": "s"})
        d3_plain = build_d3_payload_1to1_rtf(text, cryptkey=cryptkey, styles=styles, rtf_mode=rtf_mode, list_type=list_type)
    elif style_id or size is not None or (ttl_ms > 0 and not quote_data):
        d3_plain = build_d3_payload_1to1_styled(
            text, cryptkey=cryptkey, style_id=style_id, size=size,
            color=color, bold=bold, italic=italic, ttl_ms=ttl_ms
        )
    else:
        d3_plain = build_d3_payload_1to1(text, cryptkey=cryptkey, ttl_ms=ttl_ms, quote_data=quote_data)

    d3_xor = xor_encode_d3(d3_plain, uid)
    params_prefix = struct.pack('<IBII', target_uid & 0xFFFFFFFF, 3, cmsg_id & 0xFFFFFFFF, 416)
    return hdr.pack() + params_prefix + d3_xor


def build_reaction_packet(
    uid: int,
    target_id: int,
    cli_msg_id: int,
    global_msg_id: int = 0,
    icon: str = "❤️",
    is_group: bool = True,
    seq: int = -100,
    ck_val: int = 0,
    cmsg_id: Optional[int] = None
) -> bytes:
    """Tạo Inner Packet gửi reaction vào tin nhắn (CMD 1785 / CMD 1780)."""
    cmd = 1785 if is_group else 1780
    sub = 0
    now_ms = int(time.time() * 1000)
    cmsg = cmsg_id if cmsg_id is not None else (now_ms & 0xFFFFFFFF)
    
    try:
        from core.models.enums import ReactionIcon
        r_type, r_icon, _ = ReactionIcon.resolve(icon)
    except Exception:
        r_type, r_icon = (5, "/-heart") if icon in ("❤️", "heart") else (75, icon)
    
    r_data = {
        "rType": r_type,
        "rIcon": r_icon,
        "msgSender": str(uid),
        "rMsg": [{
            "cMsgID": int(cli_msg_id or now_ms),
            "gMsgID": int(global_msg_id or 0),
            "msgType": 1
        }],
        "source": 0
    }
    
    json_bytes = json.dumps(r_data, separators=(',', ':')).encode('utf-8')
    d3_plain = b'7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + struct.pack('<H', len(json_bytes)) + json_bytes
    d3_xor = xor_encode_d3(d3_plain, uid)
    
    target_type = 4 if is_group else 3
    params_prefix = struct.pack('<IBII', target_id & 0xFFFFFFFF, target_type, cmsg & 0xFFFFFFFF, 416)
    params = params_prefix + d3_xor
    
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, target=target_id, target_type=target_type, cmsg=cmsg, bb=1, ty=2, ver=3)
        
    hdr = InnerPacketHeader(ck=ck_val, bb=1, ty=2, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + params


def build_pin_topic_packet(
    uid: int,
    group_id: int,
    title: str = "",
    cli_msg_id: int = 0,
    global_msg_id: int = 0,
    sender_name: str = "Member",
    seq: int = -100,
    ck_val: int = 0,
    vercode: int = 260802903
) -> bytes:
    """
    Tạo Inner Packet Ghim tin nhắn / Tạo Topic Ghim vào nhóm (CMD 1752 SUB 2).
    Chuẩn Zalo Android (Reverse từ PCAP thực tế).
    """
    cmd = CMD_PIN_TOPIC
    sub = SUB_PIN_TOPIC
    
    buf = bytearray()
    buf.append(0x01)
    buf.extend(struct.pack('<I', vercode))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<H', 0))
    buf.extend(struct.pack('<I', int(group_id) & 0xFFFFFFFF))
    
    buf.extend(b'\x04\x05')
    s1 = b'{"needPin":1}'
    buf.extend(struct.pack('<I', len(s1)) + s1)
    
    buf.extend(b'\x04\x10\x00\x00\x00')
    s2 = '{"emoji":"📌"}'.encode('utf-8')
    buf.extend(s2)
    buf.append(0x00)
    
    topic_dict = {
        "title": str(title or "Bài ghim nhóm"),
        "msg_type": 1,
        "client_msg_id": str(cli_msg_id or int(time.time() * 1000)),
        "global_msg_id": str(global_msg_id or 0),
        "extra": json.dumps({"mentions": []}),
        "senderName": str(sender_name or "Member"),
        "senderUid": str(uid)
    }
    s3 = json.dumps(topic_dict, separators=(',', ':')).encode('utf-8')
    buf.extend(struct.pack('<I', len(s3)) + s3)
    
    buf.append(0x06)
    s4 = b'{"topicType":2}'
    buf.extend(struct.pack('<I', len(s4)) + s4)
    
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
        
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


def build_unpin_topic_packet(
    uid: int,
    group_id: int,
    topic_id: int = 0,
    global_msg_id: int = 0,
    cli_msg_id: int = 0,
    seq: int = -100,
    ck_val: int = 0,
    vercode: int = 260802903
) -> bytes:
    """
    Tạo Inner Packet Bỏ ghim tin nhắn / Topic khỏi nhóm (CMD 1708 SUB 0).
    Reverse từ Smali pn/g0.smali (method q1).
    """
    cmd = CMD_UNPIN_TOPIC
    sub = SUB_UNPIN_TOPIC
    tid = topic_id or global_msg_id or 0
    
    buf = bytearray()
    buf.append(0x01)
    buf.extend(struct.pack('<I', vercode))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<H', 0))
    buf.extend(struct.pack('<I', int(group_id) & 0xFFFFFFFF))
    buf.extend(struct.pack('<q', int(tid)))
    
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
        
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


def build_fetch_pinned_topics_packet(
    uid: int,
    group_id: int,
    from_time: int = 0,
    seq: int = -100,
    ck_val: int = 0,
    vercode: int = 260802903
) -> bytes:
    """Tạo Inner Packet lấy danh sách bài ghim / Topic trong nhóm (CMD 1703 SUB 0)."""
    cmd = 1703
    sub = 0
    prefix = bytes([0x01]) + struct.pack('<I', vercode) + struct.pack('<I', 0) + struct.pack('<H', 0)
    pt_params = prefix + struct.pack('<Iq', int(group_id) & 0xFFFFFFFF, int(from_time or 0))
    enc_params = xor_enc(pt_params, uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


def build_cmd_1705_packet(
    uid: int,
    group_id: int,
    field_8byte: int = 0,
    prefix_data: bytes = b'\x01\x0f\x8b\x89\x57\x00\x00\x00\x00\x00\x00',
    seq: int = -100,
    ck_val: int = 0
) -> bytes:
    """Tạo Inner Packet Giải tán nhóm / Rời nhóm & Chuyển quyền (CMD 1705 SUB 0)."""
    cmd = 1705
    sub = 0
    prefix = prefix_data if prefix_data else (bytes([0x01]) + struct.pack('<I', 260802903) + struct.pack('<I', 0) + struct.pack('<H', 0))
    
    def _l3(s: str) -> bytes:
        b = s.encode('utf-8')
        return struct.pack('<I', len(b)) + b
        
    extra_list = (
        bytes([4]) + _l3('{"needPin":0}')
        + bytes([4]) + _l3('{"emoji":""}')
        + bytes([0]) + _l3('{}')
        + bytes([6]) + _l3('{"topicType":0}')
    )
    pt_params = prefix + struct.pack('<IQ', int(group_id) & 0xFFFFFFFF, int(field_8byte or 0)) + extra_list
    enc_params = xor_enc(pt_params, uid)
    
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
        
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_disband_242_packet(
    uid: int,
    group_id: int,
    seq: int = -100,
    ck_val: int = 0,
    vercode: int = 260802903
) -> bytes:
    """
    Giải tán nhóm thật (CMD 242 SUB 0, pn/g0.h2).
    Smali ManageGroupView + pcap C2S 242 (9B: 01 ver gid).
      - 0x01 (1B)
      - vercode: 4B LE
      - groupId: 4B LE
    Payload gửi trực tiếp dưới dạng Plaintext trong Outer Frame AES-GCM.
    """
    cmd = CMD_DISBAND_GROUP
    sub = SUB_DISBAND_GROUP
    buf = bytes([0x01]) + struct.pack('<I', vercode) + struct.pack('<I', int(group_id) & 0xFFFFFFFF)
    enc_params = xor_enc(buf, uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


build_disband_group_packet = build_disband_242_packet
build_disband_test_frame = build_cmd_1705_packet


def build_remove_member_packet(
    uid: int,
    group_id: int,
    member_uids: List[int],
    seq: int = -100,
    ck_val: int = 0
) -> bytes:
    """
    Xoá khỏi nhóm KHÔNG block (CMD 228 SUB 0, du/b.r).
    Smali du/b.r + pcap C2S 228 (8B: gid + uid).
      - groupId: 4B LE
      - memberUids: 4B LE mỗi người (không count, không flag)
    """
    cmd = CMD_REMOVE_MEMBER
    sub = SUB_REMOVE_MEMBER
    buf = bytearray()
    buf.extend(struct.pack('<I', int(group_id) & 0xFFFFFFFF))
    for m_uid in member_uids:
        buf.extend(struct.pack('<I', int(m_uid) & 0xFFFFFFFF))
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


def build_kick_member_packet(
    uid: int,
    group_id: int,
    member_uids: List[int],
    is_block: bool = False,
    seq: int = -100,
    ck_val: int = 0
) -> bytes:
    """
    Tạo Inner Packet xóa/kick/ban thành viên khỏi nhóm (CMD 234 SUB 0, bb=0, ty=1).
    Chuẩn Zalo Android (Reverse từ PCAP thực tế & Smali pn/g0.smali method k):
      - groupId: 4B LE
      - isBlock/flag: 1B (0x01 nếu block/ban, 0x00 nếu kick)
      - memberCount: 4B LE
      - memberUids: 4B LE cho từng thành viên
    """
    cmd = CMD_KICK_MEMBER
    sub = SUB_KICK_MEMBER
    
    buf = bytearray()
    buf.extend(struct.pack('<I', int(group_id) & 0xFFFFFFFF))
    buf.append(1 if is_block else 0)
    buf.extend(struct.pack('<I', len(member_uids)))
    for m_uid in member_uids:
        buf.extend(struct.pack('<I', int(m_uid) & 0xFFFFFFFF))
        
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
        
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


def build_block_group_member_packet(
    uid: int,
    group_id: int,
    member_uids: List[int],
    seq: int = -100,
    ck_val: int = 0,
    vercode: int = 260802903
) -> bytes:
    """
    Tạo Inner Packet Chặn / Ban thành viên khỏi nhóm (CMD 234 SUB 0 với is_block=True).
    Chuẩn Zalo Android (Smali pn/g0.smali method k).
    """
    return build_kick_member_packet(
        uid=uid,
        group_id=group_id,
        member_uids=member_uids,
        is_block=True,
        seq=seq,
        ck_val=ck_val
    )


def build_block_user_packet(
    uid: int,
    target_uid: int,
    is_block: bool = True,
    seq: int = -100,
    ck_val: int = 0,
    vercode: int = 260802903
) -> bytes:
    """
    Tạo Inner Packet Chặn / Bỏ chặn người dùng 1-1 (CMD 382 SUB 0 / CMD 383 SUB 0).
    Reverse từ Smali pn/g0.smali (method f và method e2):
      - Block (CMD 382 SUB 0): [0x01][vercode: 4B LE][count: 2B LE (1)][target_uid: 4B LE][source: 2B LE (0)]
      - Unblock (CMD 383 SUB 0): [0x01][vercode: 4B LE][target_uid: 4B LE][source: 2B LE (0)]
    """
    cmd = CMD_BLOCK_USER_1TO1 if is_block else CMD_UNBLOCK_USER_1TO1
    sub = 0
    buf = bytearray()
    buf.append(0x01)
    buf.extend(struct.pack('<I', vercode))
    if is_block:
        buf.extend(struct.pack('<H', 1))  # ArrayList count = 1
        buf.extend(struct.pack('<I', int(target_uid) & 0xFFFFFFFF))
        buf.extend(struct.pack('<H', 0))  # source = 0
    else:
        buf.extend(struct.pack('<I', int(target_uid) & 0xFFFFFFFF))
        buf.extend(struct.pack('<H', 0))  # source = 0

    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
        
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


def build_unblock_user_packet(
    uid: int,
    target_uid: int,
    seq: int = -100,
    ck_val: int = 0,
    vercode: int = 260802903
) -> bytes:
    """Tạo Inner Packet Bỏ chặn người dùng 1-1 (CMD 383 SUB 0)."""
    return build_block_user_packet(uid, target_uid, is_block=False, seq=seq, ck_val=ck_val, vercode=vercode)


def build_leave_group_packet(
    uid: int,
    group_id: int,
    new_owner_id: int = 0,
    is_silent: bool = False,
    is_block_readd: bool = False,
    seq: int = -100,
    ck_val: int = 0,
    vercode: int = 260802903,
    lang: int = 0
) -> bytes:
    """
    Tạo Inner Packet Rời / Thoát khỏi nhóm chat (CMD 239 SUB 1).
    Chuẩn Zalo Android (Reverse từ au/o.smali lines 538-840 & PCAP Frame 412/440):
      - 0x01 (1 byte ver)
      - vercode: uint32 LE (260802903)
      - json_str: 4B LE len + UTF-8 bytes (ví dụ: '{"srcType":3}' nếu không chuyển owner, '{"srcType":2}' nếu có new_owner)
      - lang: uint16 LE (0x0000)
      - groupId: uint32 LE
      - newOwnerId: uint32 LE (0 nếu không chọn chủ nhóm mới)
      - is_silent: uint8 (1 nếu rời trong im lặng, 0 nếu thông báo)
      - is_block_readd: uint8 (1 nếu chặn mời lại vào nhóm, 0 nếu không)
    """
    cmd = CMD_LEAVE_GROUP  # 239
    sub = SUB_LEAVE_GROUP  # 1
    
    buf = bytearray()
    buf.append(0x01)
    buf.extend(struct.pack('<I', vercode))
    
    # JSON options
    src_type = 2 if new_owner_id else 3
    json_bytes = json.dumps({"srcType": src_type}, separators=(',', ':')).encode('utf-8')
    buf.extend(struct.pack('<I', len(json_bytes)))
    buf.extend(json_bytes)
    
    buf.extend(struct.pack('<H', lang))  # 2B LE lang code (0)
    buf.extend(struct.pack('<I', int(group_id) & 0xFFFFFFFF))
    buf.extend(struct.pack('<I', int(new_owner_id) & 0xFFFFFFFF if new_owner_id else 0))
    buf.append(1 if is_silent else 0)
    buf.append(1 if is_block_readd else 0)
    
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
        
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


def build_leave_group_225_packet(
    uid: int,
    group_id: int,
    seq: int = -100,
    ck_val: int = 0,
    vercode: int = 260802903,
    lang: int = 0
) -> bytes:
    """
    Tạo Inner Packet Rời khỏi nhóm chat trực tiếp qua Socket (CMD 225 SUB 3).
    Chuẩn PCAP Frame 438 & du/b.smali method N0:
      - 0x01 (1 byte)
      - vercode: uint32 LE (260802903)
      - empty_str: 4B LE (0x00000000)
      - lang: uint16 LE (0x0000)
      - groupId: uint32 LE
      - flag: uint32 LE (0x000000A0 = 160)
    """
    cmd = CMD_LEAVE_GROUP_225  # 225
    sub = SUB_LEAVE_GROUP_225  # 3
    
    buf = bytearray()
    buf.append(0x01)
    buf.extend(struct.pack('<I', vercode))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<H', lang))
    buf.extend(struct.pack('<I', int(group_id) & 0xFFFFFFFF))
    buf.extend(struct.pack('<I', 0x000000A0))
    
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
        
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


build_leave_group_239_packet = build_leave_group_packet


def build_create_poll_packet(
    uid: int,
    group_id: int,
    question: str,
    options: List[str],
    seq: int = -100,
    ck_val: int = 0,
    vercode: int = 260802903
) -> bytes:
    """
    Tạo Inner Packet Tạo cuộc bình chọn / Poll trong nhóm (CMD 1640 SUB 3).
    Chuẩn Zalo Android (Reverse từ PCAP thực tế).
    """
    cmd = CMD_CREATE_POLL
    sub = SUB_CREATE_POLL
    
    buf = bytearray()
    buf.append(0x01)
    buf.extend(struct.pack('<I', vercode))
    src_str = b'{"srcType":3}'
    buf.extend(struct.pack('<I', len(src_str)) + src_str)
    buf.extend(b'\x00\x00')
    buf.extend(struct.pack('<I', int(group_id) & 0xFFFFFFFF))
    
    q_bytes = question.encode('utf-8')
    buf.extend(struct.pack('<I', len(q_bytes)) + q_bytes)
    buf.extend(b'\x01\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    
    buf.extend(struct.pack('<I', len(options)))
    for opt in options:
        opt_b = opt.encode('utf-8')
        buf.extend(struct.pack('<I', len(opt_b)) + opt_b)
        
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
        
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


def build_preview_link_901_packet(
    uid: int,
    link_url: str,
    seq: int = -100,
    ck_val: int = 0,
    vercode: int = 260802903,
    source: int = 6,
    sub_type: int = 1001
) -> bytes:
    """
    Tạo Inner Packet xem trước & phân giải Link nhóm (CMD 901 SUB 3, chuẩn PCAP Frame 419).
    Server trả về Group ID thật của nhóm thông qua Link preview này.
    """
    cmd = 901
    sub = 3
    url_b = link_url.strip().encode('utf-8') if isinstance(link_url, str) else bytes(link_url)
    buf = (
        bytes([0x01]) +
        struct.pack('<I', vercode) +
        struct.pack('<I', len(url_b)) +
        url_b +
        struct.pack('<I', source) +
        struct.pack('<I', sub_type) +
        bytes([0x00]) +
        struct.pack('<I', int(time.time()) & 0xFFFFFFFF)
    )
    enc_params = xor_enc(buf, uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


def build_query_group_906_packet(
    uid: int,
    group_id: int,
    seq: int = -100,
    ck_val: int = 0
) -> bytes:
    """
    Tạo Inner Packet truy vấn thông tin nhóm theo GID (CMD 906 SUB 0, chuẩn PCAP Frame 421).
    """
    cmd = 906
    sub = 0
    buf = (
        struct.pack('<I', 0) +
        struct.pack('<I', 50) +
        struct.pack('<I', int(group_id) & 0xFFFFFFFF)
    )
    enc_params = xor_enc(buf, uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


def build_recall_message_packet(
    uid: int,
    target_id: int,
    cli_msg_id: Union[int, str],
    global_msg_id: Union[int, str] = 0,
    msg_type: int = 1,
    owner_id: Optional[Union[int, str]] = None,
    is_group: bool = True,
    cmsg_counter: int = 0,
    seq: int = -100,
    ck_val: int = 0
) -> bytes:
    """
    Tạo Inner Packet Thu hồi tin nhắn toàn nhóm / 1-1 cho tất cả mọi người (CMD 204 SUB 2 / CMD 114 SUB 2).
    Chuẩn Zalo Android (Reverse từ PCAP Frame 2433 & Smali pn/g0.smali method b3):
      - D3 plain (28 bytes):
        [target_id: 4B LE][cliMsgId: 8B LE][globalMsgId: 8B LE][msgType: 4B LE][ownerId: 4B LE]
      - D3 enc: xor_encode_d3(d3_plain, uid)
      - Framing prefix (13 bytes):
        [target_id: 4B LE][0x04 if is_group else 0x03][cmsg_id: 4B LE][416: 4B LE]
      - Params payload (41 bytes total):
        prefix + d3_enc -> xor_enc(payload, uid)
      - Header: ck, bb=0, ty=2, seq, uid, ver=3, cmd=(204 if is_group else 114), sub=2.
    """
    cmd = CMD_RECALL_MSG_GROUP if is_group else CMD_RECALL_MSG_1TO1
    sub = SUB_RECALL_MSG_GROUP if is_group else SUB_RECALL_MSG_1TO1
    t_type = 4 if is_group else 3
    
    owner = int(owner_id) if owner_id else int(uid)
    g_id = int(global_msg_id) if global_msg_id else 0
    c_id = int(cli_msg_id) if cli_msg_id else int(time.time() * 1000)
    c_counter = int(cmsg_counter) if cmsg_counter else (c_id & 0xFFFFFFFF)
    
    d3_plain = (
        struct.pack('<I', int(target_id) & 0xFFFFFFFF)
        + struct.pack('<q', c_id)
        + struct.pack('<q', g_id)
        + struct.pack('<I', int(msg_type) & 0xFFFFFFFF)
        + struct.pack('<I', int(owner) & 0xFFFFFFFF)
    )
    d3_enc = xor_encode_d3(d3_plain, uid)
    prefix = struct.pack('<I', int(target_id) & 0xFFFFFFFF) + bytes([t_type]) + struct.pack('<I', c_counter & 0xFFFFFFFF) + struct.pack('<I', 416)
    plain_payload = prefix + d3_enc
    enc_params = xor_enc(plain_payload, uid)
    
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, target=int(target_id), target_type=t_type, cmsg=c_counter, bb=0, ty=2, ver=3)
        
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=2, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


def build_delete_message_packet(
    uid: int,
    group_id: int,
    cli_msg_id: Union[int, str],
    global_msg_id: Union[int, str] = "",
    is_group: bool = True,
    only_me: bool = False,
    seq: int = -100,
    ck_val: int = 0
) -> bytes:
    """
    Tạo Inner Packet Xóa tin nhắn (CMD 205 SUB 3, bb=0, ty=1).
    Chuẩn Zalo Android (Reverse từ PCAP thực tế):
      - only_me=True  -> il = 1 (chỉ xóa ở phía cá nhân)
      - only_me=False -> il = 2 (xóa ở phía tất cả mọi người trong cuộc trò chuyện)
    """
    cmd = CMD_DELETE_MSG
    sub = SUB_DELETE_MSG
    now_cmi = int(time.time() * 1000)
    t_type = 3 if is_group else 1
    il_val = 1 if only_me else 2
    data_json = json.dumps({
        "cmi": now_cmi,
        "il": il_val,
        "data": [{
            "t": t_type,
            "ti": int(group_id),
            "si": int(uid),
            "di": int(group_id),
            "cmi": str(cli_msg_id),
            "gmi": str(global_msg_id or ""),
            "mt": 1
        }]
    }, separators=(',', ':')).encode('utf-8')
    
    enc_params = xor_enc(data_json, uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
        
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


def build_add_member_packet(
    uid: int,
    group_id: int,
    member_uids: List[int],
    is_invite: bool = False,
    seq: int = -100,
    ck_val: int = 0
) -> bytes:
    """
    Tạo Inner Packet thêm thành viên vào nhóm (CMD 235 SUB 0, bb=0, ty=1).
    Payload nhị phân:
      - groupId: int32 LE
      - isInvite: uint8 (1: Mời tham gia, 0: Thêm trực tiếp)
      - memberCount: int32 LE
      - memberUids: int32 LE cho từng thành viên
    """
    cmd = CMD_ADD_MEMBER
    sub = SUB_ADD_MEMBER
    
    buf = bytearray()
    buf.extend(struct.pack('<I', int(group_id) & 0xFFFFFFFF))
    buf.append(1 if is_invite else 0)
    buf.extend(struct.pack('<I', len(member_uids)))
    for m_uid in member_uids:
        buf.extend(struct.pack('<I', int(m_uid) & 0xFFFFFFFF))
        
    enc_params = xor_enc(bytes(buf), uid)
    
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
        
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


def build_join_group_packet(
    uid: int,
    group_id: int,
    source: int = 0,
    seq: int = -100,
    ck_val: int = 0,
    vercode: int = 260802903,
    ts_ms: Optional[int] = None
) -> bytes:
    """
    Tạo Inner Packet yêu cầu tham gia nhóm qua Socket (CMD 246 SUB 3).
    Nguồn: Reverse engineering từ smali pn/g0.smali (method z).
    Binary payload:
      - [0x01] (1 byte ver)
      - [vercode: 4B LE]
      - [0x00000000: 4B LE (empty string len)]
      - [0x0000: 2B LE lang]
      - [groupId: 4B LE]
      - [source: 4B LE]
      - [ts: 8B LE]
    Mã hóa XOR với xor_enc(payload, uid).
    Header: ck, bb=0, ty=1, seq, uid, ver=3, cmd=246, sub=3.
    """
    cmd = CMD_JOIN_GROUP
    sub = SUB_JOIN_GROUP
    if ts_ms is None:
        ts_ms = int(time.time() * 1000)
        
    prefix = bytes([0x01]) + struct.pack('<I', vercode) + struct.pack('<I', 0) + struct.pack('<H', 0)
    pt_params = prefix + struct.pack('<IIq', int(group_id) & 0xFFFFFFFF, int(source) & 0xFFFFFFFF, int(ts_ms))
    enc_params = xor_enc(pt_params, uid)
    
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
        
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


def build_join_group_invite_packet(
    uid: int,
    group_id: int,
    inviter_uid: int = 0,
    seq: int = -100,
    ck_val: int = 0,
    vercode: int = 260802903
) -> bytes:
    """
    Tạo Inner Packet chấp nhận lời mời tham gia nhóm qua Socket (CMD 250 SUB 1).
    Nguồn: Reverse engineering từ smali pn/g0.smali (method H2).
    Binary payload:
      - [0x01] (1 byte ver)
      - [vercode: 4B LE]
      - [0x00000000: 4B LE]
      - [0x0000: 2B LE lang]
      - [groupId: 4B LE]
      - [inviterUid: 8B LE]
    Mã hóa XOR với xor_enc(payload, uid).
    Header: ck, bb=0, ty=1, seq, uid, ver=3, cmd=250, sub=1.
    """
    cmd = CMD_JOIN_GROUP_INVITE
    sub = SUB_JOIN_GROUP_INVITE
    prefix = bytes([0x01]) + struct.pack('<I', vercode) + struct.pack('<I', 0) + struct.pack('<H', 0)
    pt_params = prefix + struct.pack('<Iq', int(group_id) & 0xFFFFFFFF, int(inviter_uid))
    enc_params = xor_enc(pt_params, uid)
    
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
        
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


def build_request_join_group_packet(
    uid: int,
    group_id: int = 0,
    msg: str = "",
    link_url: str = "",
    source: int = 1,
    sub_source: int = 0,
    seq: int = -100,
    ck_val: int = 0,
    vercode: int = 260802903
) -> bytes:
    """
    Tạo Inner Packet gửi yêu cầu tham gia nhóm qua liên kết / Code (CMD 244 SUB 4).
    Chuẩn PCAP Frame 422 & Smali pn/g0.smali method n2:
      - 0x01 (1 byte ver)
      - vercode: 4B LE
      - str1 (msg/inviter): 4B LE len + UTF-8 bytes
      - lang: 2B LE (0)
      - groupId: 4B LE
      - str2 (note/extra): 4B LE len + UTF-8 bytes
      - source: 4B LE (1)
      - sub_source: 1B (0)
      - str3 (full link_url): 4B LE len + UTF-8 bytes
    """
    cmd = CMD_REQUEST_JOIN_GROUP  # 244
    sub = SUB_REQUEST_JOIN_GROUP  # 4
    
    buf = bytearray()
    buf.append(0x01)
    buf.extend(struct.pack('<I', vercode))
    buf.extend(struct.pack('<I', 0))  # str1 len 0
    buf.extend(struct.pack('<H', 0))  # lang 0
    buf.extend(struct.pack('<I', int(group_id) & 0xFFFFFFFF))
    
    if msg:
        msg_bytes = msg.encode('utf-8')
        buf.extend(struct.pack('<I', len(msg_bytes)))
        buf.extend(msg_bytes)
    else:
        buf.extend(struct.pack('<I', 0))

    src_val = int(source) if source is not None else 1
    buf.extend(struct.pack('<I', src_val & 0xFFFFFFFF))
    buf.append(int(sub_source) & 0xFF)

    if link_url:
        link_clean = link_url.strip()
        link_bytes = link_clean.encode('utf-8')
        buf.extend(struct.pack('<I', len(link_bytes)))
        buf.extend(link_bytes)
    else:
        buf.extend(struct.pack('<I', 0))
        
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
        
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


def build_group_link_info_packet(
    uid: int,
    link_url: str,
    source: int = 1,
    sub_source: int = 0,
    seq: int = -100,
    ck_val: int = 0,
    vercode: int = 260802903
) -> bytes:
    """Tạo Inner Packet phân giải thông tin nhóm từ Liên kết nhóm (CMD 244 SUB 4)."""
    return build_request_join_group_packet(
        uid=uid,
        group_id=0,
        msg="",
        link_url=link_url,
        source=source,
        sub_source=sub_source,
        seq=seq,
        ck_val=ck_val,
        vercode=vercode
    )


def build_join_group_by_link_packet(
    uid: int,
    link_code: str,
    group_id: int = 0,
    flag_byte: int = 0,
    seq: int = -100,
    ck_val: int = 0,
    vercode: int = 260802903
) -> bytes:
    """
    Tạo Inner Packet tham gia nhóm qua Link (CMD 2000 SUB 3).
    Nguồn: Reverse engineering từ smali du/b.smali method h(String, byte, cu/h).
    """
    cmd = CMD_JOIN_GROUP_BY_LINK
    sub = SUB_JOIN_GROUP_BY_LINK

    buf = bytearray()
    buf.append(0x01)
    buf.extend(struct.pack('<I', vercode))
    link_bytes = link_code.encode('utf-8') if link_code else b''
    buf.extend(struct.pack('<I', len(link_bytes)))
    buf.extend(link_bytes)
    buf.extend(struct.pack('<H', 0))
    buf.extend(struct.pack('<I', int(group_id) & 0xFFFFFFFF))
    buf.append(int(flag_byte) & 0xFF)

    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)

    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


def build_join_group_2000_packet(
    uid: int,
    group_id: int,
    flag_byte: int = 0,
    seq: int = -100,
    ck_val: int = 0,
    vercode: int = 260802903
) -> bytes:
    """
    Tạo Inner Packet tham gia nhóm trực tiếp qua Group ID (CMD 2000 SUB 3).
    """
    cmd = CMD_JOIN_GROUP_BY_LINK
    sub = SUB_JOIN_GROUP_BY_LINK

    buf = bytearray()
    buf.append(0x01)
    buf.extend(struct.pack('<I', vercode))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<H', 0))
    buf.extend(struct.pack('<I', int(group_id) & 0xFFFFFFFF))
    buf.append(int(flag_byte) & 0xFF)

    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)

    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params


def build_outer_frame(inner_packet: bytes, dk: bytes) -> bytes:

    """Đóng gói Inner Packet thành Outer Frame AES-256-GCM (Type 4)."""
    encrypted_body = encrypt_aes_gcm(inner_packet, dk)
    frame = OuterFrame(total_len=len(encrypted_body) + 5, ftype=FRAME_TYPE_DATA, body=encrypted_body)
    return frame.pack()



# ---------------------------------------------------------------------------
# 6. Incoming Packet Parsers (Giải mã Phản hồi từ Máy chủ)
# ---------------------------------------------------------------------------

def parse_incoming_frame(
    frame: OuterFrame,
    dk: bytes,
    cryptkey: Optional[bytes] = None,
    my_uid: Optional[int] = None
) -> dict:
    """Bóc tách và giải mã một Outer Frame nhận được từ máy chủ."""
    res = {
        'ftype': frame.ftype,
        'total_len': frame.total_len,
        'is_error': False,
        'error_code': None,
        'cmd': None,
        'sub': None,
        'cmsg_id': 0,
        'parsed_data': None
    }

    if frame.ftype not in (3, 4):
        return res

    try:
        dec_inner = decrypt_aes_gcm(frame.body, dk)
    except Exception as ex:
        if frame.ftype == 3 and len(frame.body) >= 6:
            try:
                cmd, sub, code = struct.unpack_from('<HHi', frame.body, 0)[:3]
                res.update({'is_error': True, 'cmd': cmd, 'sub': sub, 'error_code': code})
                return res
            except Exception:
                pass
        res['decrypt_error'] = str(ex)
        return res

    if len(dec_inner) < INNER_HEADER_SIZE:
        res['error'] = "Inner packet quá ngắn"
        return res

    hdr = InnerPacketHeader.unpack(dec_inner)
    params_body = dec_inner[INNER_HEADER_SIZE:]

    res.update({
        'ck': hdr.ck,
        'bb': hdr.bb,
        'ty': hdr.ty,
        'seq': hdr.seq,
        'uid': hdr.uid,
        'ver': hdr.ver,
        'cmd': hdr.cmd,
        'sub': hdr.sub,
        'raw_params': params_body
    })

    if hdr.cmd in (101, 201, 1865, 1867):
        parsed_msgs, cmsg_id = parse_incoming_messages_payload(
            hdr.cmd, hdr.sub, hdr.uid, params_body,
            cryptkey=cryptkey, my_uid=my_uid
        )
        res['cmsg_id'] = cmsg_id
        res['parsed_data'] = {'messages': parsed_msgs}
    elif hdr.cmd == CMD_DELIVERY_RECEIPT and hdr.sub == SUB_DELIVERY_RECEIPT:
        res['parsed_data'] = parse_delivery_receipt_202(params_body)
    elif hdr.cmd == CMD_GROUP_MSG and hdr.sub == SUB_GROUP_MSG:
        if len(params_body) >= 4:
            res['ack_code'] = struct.unpack_from('<i', params_body, 0)[0]

    return res


def parse_incoming_messages_payload(
    cmd: int,
    sub: int,
    uid: int,
    params_bytes: bytes,
    cryptkey: Optional[bytes] = None,
    my_uid: Optional[int] = None
) -> Tuple[List[Dict[str, Any]], int]:
    """Phân tích và giải mã các bản tin tin nhắn đến (CMD 101, 201, 1865, 1867)."""
    cmsg_id = 0
    if len(params_bytes) >= 13:
        try:
            p_uid, p_type, cmsg_id, flags = struct.unpack('<IBII', params_bytes[:13])
        except Exception:
            pass

    decomp_json = None
    gz_idx = params_bytes.find(b'\x1f\x8b\x08')
    if gz_idx != -1:
        try:
            decomp = gzip.decompress(params_bytes[gz_idx:])
            decomp_json = json.loads(decomp.decode('utf-8', errors='ignore'))
        except Exception:
            pass

    if not decomp_json and cmd in (101, 201):
        payload_bytes = params_bytes[13:] if len(params_bytes) >= 13 else params_bytes
        for try_u in (uid, my_uid):
            if not try_u:
                continue
            try:
                d3_dec = xor_decode_d3(payload_bytes, try_u)
                gz_idx2 = d3_dec.find(b'\x1f\x8b\x08')
                if gz_idx2 != -1:
                    decomp = gzip.decompress(d3_dec[gz_idx2:])
                else:
                    decomp = gzip.decompress(d3_dec)
                decomp_json = json.loads(decomp.decode('utf-8', errors='ignore'))
                if decomp_json:
                    break
            except Exception:
                pass

    if not decomp_json:
        try:
            decomp_json = json.loads(params_bytes.decode('utf-8', errors='ignore'))
        except Exception:
            pass

    messages = []
    if decomp_json and isinstance(decomp_json, dict):
        msg_list = decomp_json.get('msg', [])
        if not isinstance(msg_list, list):
            msg_list = [msg_list] if msg_list else []

        for item in msg_list:
            if not isinstance(item, dict):
                continue
            txt_obj = item.get('text', {})
            ttype = txt_obj.get('type') or 'webchat'
            d = txt_obj.get('data', {})
            if not d and 'data' in item:
                d = item.get('data', {})

            raw_from_u = d.get('fromU')
            msg_id = d.get('id') or item.get('id')
            cmi_id = d.get('cliMsgId') or cmsg_id
            to_dest = d.get('to')

            is_group = (cmd in (201, 1867))
            if cmd == 1865:
                is_self = True
                from_u = my_uid or uid
                from_d = "Tôi"
            elif cmd == 101:
                is_self = False
                from_u = raw_from_u or uid
                from_d = d.get('fromD') or str(from_u)
            elif cmd in (201, 1867):
                is_self = (raw_from_u == my_uid) if (my_uid and raw_from_u is not None) else (raw_from_u == 0)
                from_u = raw_from_u or uid
                from_d = d.get('fromD') or str(from_u)
            else:
                is_self = (raw_from_u == my_uid) if my_uid else False
                from_u = raw_from_u or uid
                from_d = d.get('fromD') or str(from_u)

            msg_txt = d.get('msg', '')
            if d.get('mcrypt') == 1 and d.get('iv') and cryptkey:
                try:
                    iv_raw = base64.b64decode(d['iv'])
                    ct_raw = base64.b64decode(msg_txt)
                    pt_raw = decrypt_e2ee_cbc(ct_raw, cryptkey, iv_raw)
                    msg_txt = pt_raw.decode('utf-8', errors='replace')
                except Exception:
                    pass

            quote_data = d.get('quote') or d.get('q') or item.get('quote') or txt_obj.get('quote')
            if isinstance(quote_data, str) and quote_data.strip().startswith('{'):
                try: quote_data = json.loads(quote_data)
                except Exception: pass

            mentions_data = d.get('mentions')
            if isinstance(mentions_data, str) and mentions_data.startswith('['):
                try: mentions_data = json.loads(mentions_data)
                except Exception: mentions_data = []
            elif not isinstance(mentions_data, list):
                mentions_data = []

            messages.append({
                'cmd': cmd,
                'is_group': is_group,
                'is_self': is_self,
                'to_group': to_dest if is_group else None,
                'to_id': to_dest,
                'from_uid': from_u,
                'from_display': from_d,
                'from_name': from_d,
                'msg_id': msg_id,
                'cli_msg_id': cmi_id,
                'content': msg_txt,
                'text': msg_txt,
                'ttl': d.get('ttl', 0),
                'ts': d.get('ts') or int(time.time() * 1000),
                'attach': d.get('attach', ''),
                'mentions': mentions_data,
                'quote': quote_data,
                'type': ttype,
                'raw': d
            })

    return messages, cmsg_id


def parse_group_sync_1867(params_bytes: bytes) -> dict:
    messages, _ = parse_incoming_messages_payload(1867, 0, 0, params_bytes)
    return {'raw_json': None, 'messages': messages}


def parse_delivery_receipt_202(params_bytes: bytes) -> dict:
    out = {}
    if len(params_bytes) >= 16:
        try:
            gmi = struct.unpack_from('<Q', params_bytes, 0)[0]
            out['globalMsgId'] = gmi
        except Exception:
            pass
    return out


# Re-exports for Handshake & Init Session
try:
    from .handshake import build_prov_frame, build_init_frames, send_init_frames
except (ImportError, ValueError):
    try:
        from core.socket.handshake import build_prov_frame, build_init_frames, send_init_frames
    except (ImportError, ValueError):
        from handshake import build_prov_frame, build_init_frames, send_init_frames

