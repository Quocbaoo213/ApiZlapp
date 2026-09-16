#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zalo_chat.py — Zalo Realtime Full-Duplex Socket Client & Smart Quoting Bot (1-1 & Group)

Tính năng vượt trội:
- Hỗ trợ Reply/Quote tin nhắn chuẩn theo giao thức Zalo (D3 sSrcStr + AES-GCM + E2EE AES-CBC).
- Tự động duy trì kết nối 24/7 (Heartbeat Ping CMD 1971 SUB 0 mỗi 10s + TCP Keep-Alive OS Level).
- Tự động Reconnect & Failover thông minh khi mạng gặp sự cố.
- Bộ lọc chống lặp vô hạn (Anti-Loop) và Rate Limiter chống spam.
- Log Console cực kỳ gọn gàng, tinh tế, loại bỏ log rác và debounce trạng thái typing.
- Hệ thống lệnh Bot thông minh (/ping, /time, /echo, /calc, /help, /info) cùng phản hồi từ khóa.
- Giao diện Interactive Console hỗ trợ gửi tin thường và gửi tin trích dẫn (quote).
"""

import argparse
import base64
import gzip
import json
import logging
import os
import re
import socket
import sqlite3
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta

TZ_VN = timezone(timedelta(hours=7))
from typing import Callable, Optional, Dict, Any, List, Tuple
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Khóa XOR d3 giải mã/mã hóa tin nhắn Zalo
XK = b'P1BL2G5I7NJD2H3JAUD554G7645PH54F'
DEFAULT_HOST = "49.213.95.86"
DEFAULT_PORT = 443

SERVERS_JSON_PATH = "/root/zalo/register_json/servers.json"

DEFAULT_SERVER_POOL = [
    {"host": "49.213.95.83", "port": 443, "desc": "Hà Nội VIP 1"},
    {"host": "49.213.95.92", "port": 443, "desc": "Hà Nội VIP 2"},
    {"host": "49.213.95.84", "port": 443, "desc": "Hà Nội Cluster A"},
    {"host": "49.213.95.94", "port": 443, "desc": "Hà Nội Cluster B"},
    {"host": "49.213.95.74", "port": 443, "desc": "TP.HCM VIP 1"},
    {"host": "49.213.95.77", "port": 443, "desc": "TP.HCM VIP 2"},
    {"host": "49.213.95.73", "port": 443, "desc": "TP.HCM Cluster A"},
    {"host": "49.213.95.81", "port": 443, "desc": "TP.HCM Cluster B"},
    {"host": "49.213.95.88", "port": 443, "desc": "VNG DataCenter 1"},
    {"host": "49.213.95.85", "port": 443, "desc": "VNG DataCenter 2"},
    {"host": "49.213.95.78", "port": 443, "desc": "VNG Core 1"},
    {"host": "49.213.95.86", "port": 443, "desc": "VNG Core 2"},
    {"host": "49.213.95.87", "port": 443, "desc": "VNG Core 3"},
    {"host": "49.213.95.96", "port": 443, "desc": "VNG Core 4"},
    {"host": "49.213.95.89", "port": 443, "desc": "VNG Edge 1"},
    {"host": "49.213.95.90", "port": 443, "desc": "VNG Edge 2"},
    {"host": "49.213.95.79", "port": 443, "desc": "VNG Edge 3"},
    {"host": "49.213.95.95", "port": 443, "desc": "VNG Edge 4"},
    {"host": "49.213.95.76", "port": 443, "desc": "VNG Backup 1"},
    {"host": "49.213.95.80", "port": 443, "desc": "VNG Backup 2"},
    {"host": "49.213.95.93", "port": 443, "desc": "VNG Backup 3"},
    {"host": "49.213.95.75", "port": 443, "desc": "VNG Backup 4"},
    {"host": "49.213.95.91", "port": 443, "desc": "VNG Backup 5"},
]

def load_server_pool(json_path: str = SERVERS_JSON_PATH) -> List[Dict[str, Any]]:
    servers = []
    if os.path.isfile(json_path):
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                s_list = data.get('socketServers') or []
                for s in s_list:
                    h = s.get('host', '')
                    p = s.get('port', 443)
                    # Chỉ chọn IPv4 Port 443 tương thích với Session Ticket của Frame 0
                    if h and ':' not in h and p == 443:
                        servers.append({'host': h, 'port': 443, 'desc': f'Zalo-Srv {h}:443'})
        except Exception:
            pass
    return servers if servers else DEFAULT_SERVER_POOL

def test_server_speed(host: str, port: int, timeout: float = 1.8) -> Tuple[str, int, float, bool]:
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        if port == 443:
            req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode('latin1')
            s.sendall(req)
            resp = s.recv(256)
            s.close()
            if b"HTTP/1." in resp:
                lat = (time.time() - t0) * 1000
                return (host, port, lat, True)
        else:
            s.close()
            lat = (time.time() - t0) * 1000
            return (host, port, lat, True)
    except Exception:
        pass
    return (host, port, 9999.0, False)

def find_best_socket_server(pool: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    target_pool = pool or load_server_pool()
    valid_results = []
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(test_server_speed, s['host'], s['port']) for s in target_pool]
        for f in as_completed(futures):
            host, port, lat, ok = f.result()
            if ok and lat < 500:
                valid_results.append({'host': host, 'port': port, 'latency': lat})

    if not valid_results:
        return {"host": DEFAULT_HOST, "port": DEFAULT_PORT, "latency": 55.0}

    valid_results.sort(key=lambda x: x['latency'])
    return valid_results[0]

def setup_logger(log_file="/root/zalo/chat.log"):
    logger = logging.getLogger("zalo_chat")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        fh = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        formatter = logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    return logger

LOGGER = setup_logger()

def parse_zaloprefs(path="/root/zalo/zaloprefs"):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Không tìm thấy file zaloprefs: {path}")
    db = sqlite3.connect(path)
    cur = db.cursor()
    rows = cur.execute("SELECT key, value FROM prefs_v2").fetchall()
    db.close()

    users = {}
    current_uid = None
    for k, v in rows:
        if k == 'currentUserUid':
            current_uid = str(v).strip()
            continue
        m_ks = re.match(r'KEY_STRING_SOCKET_PRO_V1_KEY_SET_(ID|VALUE)_(\d+)', k)
        if m_ks:
            kind, uid = m_ks.group(1), m_ks.group(2)
            users.setdefault(uid, {})[kind] = str(v)
            continue
        m_ck = re.match(r'CryptKey(\d+)', k)
        if m_ck:
            uid = m_ck.group(1)
            users.setdefault(uid, {})['CryptKey'] = str(v)
            continue
        if k == 'sessionKey':
            users.setdefault('_global', {})['sessionKey'] = str(v)
        elif k == 'token':
            users.setdefault('_global', {})['token'] = str(v)

    parsed_users = {}
    for uid, data in users.items():
        if uid == '_global':
            continue
        dk_bytes = None
        if 'VALUE' in data:
            try:
                dk_bytes = base64.b64decode(data['VALUE'])
            except Exception:
                pass
        ck_bytes = None
        if 'CryptKey' in data:
            try:
                ck_bytes = base64.b64decode(data['CryptKey'])
            except Exception:
                pass
        parsed_users[uid] = {
            'uid': int(uid),
            'keySetId': data.get('ID', ''),
            'dk': dk_bytes,
            'dk_b64': data.get('VALUE', ''),
            'cryptkey': ck_bytes,
            'cryptkey_b64': data.get('CryptKey', '')
        }

    return {
        'current_uid': current_uid,
        'users': parsed_users,
        'global': users.get('_global', {})
    }

def load_contacts(contacts_path="/root/zalo/contacts.json") -> Dict[int, str]:
    contact_map = {}
    if os.path.isfile(contacts_path):
        try:
            with open(contacts_path, 'r', encoding='utf-8') as f:
                clist = json.load(f)
                for item in clist:
                    if isinstance(item, dict) and 'uid' in item:
                        contact_map[item['uid']] = item.get('phone') or item.get('name') or str(item['uid'])
        except Exception:
            pass
    return contact_map

CONTACTS = load_contacts()

def get_name(uid: int, fallback: str = None) -> str:
    if fallback and fallback.strip() and fallback != 'null':
        return fallback
    if uid in CONTACTS:
        return f"{CONTACTS[uid]} ({uid})"
    return str(uid)

def compute_checksum(cmd: int, sub: int, seq: int, uid: int, target: int = 0, target_type: int = 0, cmsg: int = 0, bb: int = 1, ty: int = 2, ver: int = 3) -> int:
    """Tính Checksum (ck_val) chuẩn theo libznetwork.so."""
    total = (bb + ty + seq + uid + ver + cmd + sub + target + target_type + cmsg) & 0xFFFFFFFF
    return total ^ 0x6ce7daa0

def xor_encode_d3(plain: bytes, uid: int) -> bytes:
    a4 = len(plain) + 36
    le4 = struct.pack('<I', a4)
    ule = struct.pack('<I', uid)
    k = bytes(XK[i % 32] ^ le4[i % 4] ^ ule[i % 4] for i in range(32))
    return bytes(plain[i] ^ k[i % 32] for i in range(len(plain)))

def xor_decode_d3(enc: bytes, uid: int) -> bytes:
    a4 = len(enc) + 36
    le4 = struct.pack('<I', a4)
    ule = struct.pack('<I', uid)
    k = bytes(XK[i % 32] ^ le4[i % 4] ^ ule[i % 4] for i in range(32))
    return bytes(enc[i] ^ k[i % 32] for i in range(len(enc)))

def utf16_len(s: str) -> int:
    """Tính độ dài chuỗi theo đơn vị UTF-16 code units (chuẩn Zalo mentions)."""
    return len(s.encode('utf-16-le')) // 2

def build_mention_attach(mentions_list: List[Dict[str, Any]]) -> str:
    """Tạo chuỗi JSON attach chứa mảng mentions chuẩn Zalo."""
    if not mentions_list:
        return ""
    m_array = []
    for m in mentions_list:
        if isinstance(m, dict) and 'uid' in m:
            m_array.append({
                'uid': int(m['uid']),
                'pos': int(m.get('pos', 0)),
                'len': int(m.get('len', 0)),
                'type': int(m.get('type', 0)),
                'ignoreNickname': int(m.get('ignoreNickname', 0))
            })
    if not m_array:
        return ""
    attach_obj = {
        'title': '',
        'description': '',
        'href': '',
        'thumb': '',
        'childnumber': '0',
        'action': '',
        'mentions': m_array,
        'params': ''
    }
    return json.dumps(attach_obj, separators=(',', ':'))

def clean_message_text(raw_text: str, mentions: Optional[List[Dict[str, Any]]] = None, bot_uid: Optional[int] = None) -> Tuple[str, bool, List[int]]:
    """
    Tách bỏ các vùng text bị chiếm bởi Mention dựa trên pos & len (UTF-16 code units).
    Trả về: (clean_text, is_bot_mentioned, all_mentioned_uids)
    """
    if not raw_text:
        return ('', False, [])

    # Chuyển raw_text thành danh sách các UTF-16 code units (mỗi unit 2 bytes)
    utf16_bytes = raw_text.encode('utf-16-le')
    units = [utf16_bytes[i:i+2] for i in range(0, len(utf16_bytes), 2)]

    is_bot_mentioned = False
    all_uids = []
    mask = [True] * len(units)

    if mentions and isinstance(mentions, list):
        for m in mentions:
            if not isinstance(m, dict):
                continue
            uid = m.get('uid')
            if uid:
                all_uids.append(int(uid))
                if bot_uid and int(uid) == int(bot_uid):
                    is_bot_mentioned = True
            pos = int(m.get('pos', 0))
            mlen = int(m.get('len', 0))
            for idx in range(pos, min(pos + mlen, len(units))):
                mask[idx] = False

        clean_units = [units[i] for i in range(len(units)) if mask[i]]
        clean_str = b''.join(clean_units).decode('utf-16-le', errors='ignore').strip()
    else:
        clean_str = raw_text.strip()

    # Xóa các @tag text thuần ở đầu câu nếu còn sót
    clean_str = re.sub(r'^@[^\s/]+\s*', '', clean_str).strip()

    return (clean_str, is_bot_mentioned, all_uids)

def parse_ttl_duration(val: str) -> int:
    """Chuyển đổi chuỗi thời gian người dùng nhập thành số giây TTL chuẩn Zalo."""
    val = val.lower().strip()
    if val in ("0", "off", "tat", "tắt", "none", "disable", "no"):
        return 0
    if val.endswith("d") or val.endswith("ngày") or val.endswith("ngay"):
        num = re.sub(r'[^\d]', '', val)
        return int(num) * 86400 if num else 86400
    if val.endswith("h") or val.endswith("giờ") or val.endswith("gio"):
        num = re.sub(r'[^\d]', '', val)
        return int(num) * 3600 if num else 3600
    if val.endswith("m") or val.endswith("phút") or val.endswith("phut"):
        num = re.sub(r'[^\d]', '', val)
        return int(num) * 60 if num else 60
    if val.endswith("s") or val.endswith("giây") or val.endswith("giay"):
        num = re.sub(r'[^\d]', '', val)
        return int(num) if num else 0
    try:
        return int(val)
    except Exception:
        return 0


def build_quote_object(
    msg_id: int,
    cli_msg_id: int,
    owner_uid: int,
    owner_name: str,
    msg_text: str,
    group_id: Optional[int] = None,
    msg_type: int = 1,
    ts: Optional[int] = None,
    attach: str = ""
) -> Dict[str, Any]:
    """Tạo Quote Object chứa đầy đủ metadata nhị phân để đóng gói vào D3 Frame."""
    clean_name = (owner_name or "").strip()
    if clean_name.endswith(')') and ' (' in clean_name:
        clean_name = clean_name.split(' (')[0].strip()
    if not clean_name or clean_name.lower() in ("null", "none"):
        clean_name = str(owner_uid)

    return {
        "cliMsgType": int(msg_type) if msg_type else 1,
        "cliMsgId": int(cli_msg_id) if cli_msg_id else int(time.time() * 1000),
        "globalMsgId": int(msg_id) if msg_id else 0,
        "ownerId": int(owner_uid),
        "gOwnerId": int(group_id) if group_id else None,
        "fromD": clean_name,
        "ts": int(ts) if ts else int(time.time() * 1000),
        "msg": str(msg_text) if msg_text else "",
        "attach": str(attach) if attach else "",
        "ttl": 0
    }

def build_quote_from_event(ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Tự động chuyển đổi sự kiện tin nhắn đến thành Quote Object."""
    if not ev:
        return None
    from_u = ev.get('from_uid') or 0
    raw = ev.get('raw', {})
    from_name = raw.get('fromD') or ev.get('from_name') or CONTACTS.get(from_u) or str(from_u)

    msg_id = ev.get('msg_id') or 0
    cmi = ev.get('cli_msg_id') or 0
    msg_txt = ev.get('text') or ''
    gid = ev.get('to_id') if ev.get('is_group') else None
    ts = ev.get('ts') or int(time.time() * 1000)
    attach_str = ""
    if isinstance(raw.get('attach'), (dict, list)):
        try: attach_str = json.dumps(raw['attach'], separators=(',', ':'))
        except Exception: attach_str = ""
    elif isinstance(raw.get('attach'), str):
        attach_str = raw['attach']

    # Nếu chưa có attach nhưng có mentions trong tdata thì tự sinh attach mentions
    if not attach_str and raw.get('mentions'):
        m_list = raw.get('mentions')
        if isinstance(m_list, list) and len(m_list) > 0:
            attach_str = build_mention_attach(m_list)

    # Map message type to cliMsgType integer
    ttype = ev.get('msg_type', 'webchat')
    type_code = 1
    if ttype == 'chat.photo':
        type_code = 2
        if not msg_txt: msg_txt = "[Hình ảnh]"
    elif ttype == 'chat.sticker':
        type_code = 6
        if not msg_txt: msg_txt = "[Sticker]"
    elif ttype == 'chat.voice':
        type_code = 4
        if not msg_txt: msg_txt = "[Tin nhắn thoại]"
    elif ttype == 'chat.video':
        type_code = 3
        if not msg_txt: msg_txt = "[Video]"
    elif not msg_txt:
        msg_txt = "[Tin nhắn]"

    return build_quote_object(
        msg_id=msg_id,
        cli_msg_id=cmi,
        owner_uid=from_u,
        owner_name=from_name,
        msg_text=msg_txt,
        group_id=gid,
        msg_type=type_code,
        ts=ts,
        attach=attach_str
    )

def build_d3_message_group(text: str, quote: Optional[Dict[str, Any]] = None, ttl: int = 0) -> bytes:
    """Đóng gói tin nhắn Nhóm chuẩn nhị phân D3 (hỗ trợ Quote và TTL tự xóa tin nhắn)."""
    ttl_ms = int(ttl * 1000) if (ttl > 0 and ttl < 1000000) else int(ttl)
    prop_obj = {
        'sSrcType': -1,
        'sSrcStr': '',
        'msg_warning_type': 0,
        'emoji': {'content': 0, 'num': 0, 'uniq': 0, 'first': '', 'last': '', 'most': '', 'text': 1}
    }
    prop_bytes = json.dumps(prop_obj, separators=(',', ':')).encode('utf-8')
    text_bytes = text.encode('utf-8')

    if not quote:
        # Tin nhắn thường không Quote (có hoặc không có TTL)
        if ttl_ms > 0:
            prop_header = bytearray([0x01, 0x00, 0x02, 0x07, 0x00]) + (b'\xff' * 12) + struct.pack('<I', len(prop_bytes)) + prop_bytes
            ttl_block = bytes([0x08]) + struct.pack('<I', ttl_ms) + bytes(4)
            return bytes(prop_header + ttl_block + text_bytes)
        return bytearray([0x01, 0x00, 0x01, 0x07, 0x00]) + (b'\xff' * 12) + struct.pack('<I', len(prop_bytes)) + prop_bytes + text_bytes

    # Tin nhắn CÓ Quote theo cấu trúc nhị phân chuẩn Zalo D3
    q_uid = int(quote.get('ownerId') or 0)
    q_ts = int(quote.get('ts') or int(time.time() * 1000))
    q_gmi = int(quote.get('globalMsgId') or 0)
    q_cmi = int(quote.get('cliMsgId') or int(time.time() * 1000))
    q_typ = int(quote.get('cliMsgType') or 1)
    q_msg = str(quote.get('msg') or '')
    q_att = str(quote.get('attach') or '')

    # Tính toán chính xác độ dài mention tag nếu có
    mention_len = 0
    if quote and quote.get('fromD'):
        tag = f"@{quote['fromD']}"
        if text.startswith(tag):
            mention_len = len(tag.encode('utf-16-le')) // 2
    if mention_len == 0 and quote and quote.get('ownerId'):
        tag_uid = f"@{quote['ownerId']}"
        if text.startswith(tag_uid):
            mention_len = len(tag_uid.encode('utf-16-le')) // 2
    if mention_len == 0 and text.startswith('@'):
        parts = text.split(' ', 1)
        mention_len = len(parts[0].encode('utf-16-le')) // 2

    q_text_bytes = q_msg.encode('utf-8')
    q_attach_bytes = q_att.encode('utf-8')

    buf = bytearray()
    buf += bytes([0x01, 0x00, 0x03, 0x0b, 0x01])
    buf += struct.pack('<I', 0)                  # 4 bytes 0x00000000
    buf += struct.pack('<H', mention_len)        # 2 bytes độ dài mention tag chính xác
    buf += struct.pack('<I', q_uid)              # 4 bytes Quoted Owner UID
    buf += bytes([0x02])                         # 1 byte 0x02
    buf += struct.pack('<I', q_uid)              # 4 bytes Quoted Owner UID
    buf += struct.pack('<Q', q_ts)               # 8 bytes Quoted Timestamp ms
    buf += struct.pack('<Q', q_gmi)              # 8 bytes Quoted GlobalMsgId
    buf += struct.pack('<Q', q_cmi)              # 8 bytes Quoted CliMsgId
    buf += struct.pack('<H', q_typ)              # 2 bytes Quoted CliMsgType
    buf += struct.pack('<H', len(q_text_bytes)) + q_text_bytes     # Length-prefixed quoted text
    buf += struct.pack('<H', len(q_attach_bytes)) + q_attach_bytes # Length-prefixed quoted attach
    buf += struct.pack('<Q', ttl_ms)             # 8 bytes TTL ms (0 nếu không tự xóa)
    buf += struct.pack('<H', 7)                  # 2 bytes 0x0007
    buf += b'\xff' * 12                          # 12 bytes 0xff
    buf += struct.pack('<I', len(prop_bytes)) + prop_bytes         # Length-prefixed property JSON
    buf += text_bytes                            # Message text
    return bytes(buf)

def build_d3_message_1to1(text: str, cryptkey: bytes, quote: Optional[Dict[str, Any]] = None, ttl: int = 0) -> bytes:
    """Đóng gói tin nhắn 1-1 mã hóa AES-CBC chuẩn nhị phân D3 (hỗ trợ Quote và TTL tự xóa)."""
    ttl_ms = int(ttl * 1000) if (ttl > 0 and ttl < 1000000) else int(ttl)
    iv = os.urandom(16)
    cipher = AES.new(cryptkey, AES.MODE_CBC, iv=iv)
    padded = pad(text.encode('utf-8'), 16)
    ct = cipher.encrypt(padded)

    text_block = bytes([0x01]) + iv + struct.pack('<H', len(ct)) + ct

    prop_obj = {
        'sSrcType': -1,
        'sSrcStr': '',
        'msg_warning_type': 0,
        'emoji': {'content': 0, 'num': 0, 'uniq': 0, 'first': '', 'last': '', 'most': '', 'text': 1}
    }
    prop_bytes = json.dumps(prop_obj, separators=(',', ':')).encode('utf-8')

    if not quote:
        if ttl_ms > 0:
            ttl_block = bytes([0x08]) + struct.pack('<I', ttl_ms) + bytes(4)
            prop_header = bytes([0x29, 0x00, 0x02, 0x07, 0x00]) + (b'\xff' * 12) + struct.pack('<I', len(prop_bytes)) + prop_bytes
            return prop_header + ttl_block + text_block
        prop_header = bytes([0x29, 0x00, 0x01, 0x07, 0x00]) + (b'\xff' * 12) + struct.pack('<I', len(prop_bytes)) + prop_bytes
        return prop_header + text_block

    q_uid = int(quote.get('ownerId') or 0)
    q_ts = int(quote.get('ts') or int(time.time() * 1000))
    q_gmi = int(quote.get('globalMsgId') or 0)
    q_cmi = int(quote.get('cliMsgId') or int(time.time() * 1000))
    q_typ = int(quote.get('cliMsgType') or 1)
    q_msg = str(quote.get('msg') or '')
    q_att = str(quote.get('attach') or '')

    mention_len = 0
    if quote and quote.get('fromD'):
        tag = f"@{quote['fromD']}"
        if text.startswith(tag):
            mention_len = len(tag.encode('utf-16-le')) // 2
    if mention_len == 0 and quote and quote.get('ownerId'):
        tag_uid = f"@{quote['ownerId']}"
        if text.startswith(tag_uid):
            mention_len = len(tag_uid.encode('utf-16-le')) // 2
    if mention_len == 0 and text.startswith('@'):
        parts = text.split(' ', 1)
        mention_len = len(parts[0].encode('utf-16-le')) // 2

    q_text_bytes = q_msg.encode('utf-8')
    q_attach_bytes = q_att.encode('utf-8')

    buf = bytearray()
    buf += bytes([0x29, 0x00, 0x03, 0x0b, 0x01])
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
    buf += struct.pack('<Q', ttl_ms)
    buf += struct.pack('<H', 7)
    buf += b'\xff' * 12
    buf += struct.pack('<I', len(prop_bytes)) + prop_bytes
    buf += text_block
    return bytes(buf)

def build_gcm_frame(inner_pkt: bytes, dk: bytes) -> bytes:
    iv_gcm = os.urandom(12)
    cipher_gcm = AES.new(dk, AES.MODE_GCM, nonce=iv_gcm, mac_len=16)
    ct_gcm, tag_gcm = cipher_gcm.encrypt_and_digest(inner_pkt)
    body = ct_gcm + tag_gcm + iv_gcm
    return struct.pack('<IB', len(body) + 5, 4) + body

def decrypt_e2ee_text(ct_b64: str, iv_b64: str, cryptkey: bytes) -> str:
    if not cryptkey or not ct_b64 or not iv_b64:
        return ""
    try:
        iv = base64.b64decode(iv_b64)
        ct = base64.b64decode(ct_b64)
        pt = unpad(AES.new(cryptkey, AES.MODE_CBC, iv=iv).decrypt(ct), 16)
        return pt.decode('utf-8', errors='replace')
    except Exception:
        return ""


KEYWORD_RESPONSES = {
    "chào": "Chào bạn! Tôi là Zalo Socket Bot, chúc bạn một ngày tốt lành.",
    "hi": "Chào bạn! Chúc bạn ngày mới vui vẻ.",
    "hello": "Hello! Rất vui được trò chuyện cùng bạn.",
    "ping": "Pong! Kết nối Zalo Socket ổn định 100%.",
    "test": "Hệ thống kiểm tra hoạt động bình thường! [OK]",
}

def generate_bot_response(
    msg_txt: str,
    msg_type: str = "webchat",
    prefix: Optional[str] = "/",
    keywords_list: Optional[List[str]] = None,
    fixed_reply: Optional[str] = None,
    reply_all: bool = False,
    from_uid: Optional[int] = None,
    group_id: Optional[int] = None,
    is_bot_mentioned: bool = False,
) -> Optional[str]:
    """Sinh nội dung phản hồi cho Auto-Reply Bot dựa trên prefix, keywords, hoặc chế độ toàn bộ."""
    msg_txt = (msg_txt or "").strip()
    if not msg_txt:
        return None

    # 1. Xử lý lệnh theo Prefix (ví dụ: '/')
    if prefix and msg_txt.startswith(prefix):
        cmd_part = msg_txt[len(prefix):].strip()
        if not cmd_part:
            # Người dùng chỉ gõ '/' đơn thuần -> BỎ QUA
            return None

        parts = cmd_part.split(' ', 1)
        cmd_name = parts[0].lower().strip()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if not cmd_name or cmd_name.startswith('@'):
            # Lệnh rỗng hoặc mention tag -> BỎ QUA
            return None

        if cmd_name == "ping":
            return "🏓 Pong! Bot Socket đang trực tuyến mượt mà."
        elif cmd_name == "uid":
            lines = [f"👤 UID của bạn: {from_uid}" if from_uid else "👤 UID: không xác định"]
            if group_id:
                lines.append(f"👥 UID Group: {group_id}")
            return "\n".join(lines)
        elif cmd_name == "help":
            return (
                "🤖 [DANH SÁCH LỆNH BOT]\n"
                f"• {prefix}ping : Kiểm tra độ phản hồi\n"
                f"• {prefix}uid  : Xem UID của bạn & group\n"
                f"• {prefix}time : Xem ngày giờ hiện tại\n"
                f"• {prefix}echo <text> : Phản hồi lại nội dung\n"
                f"• {prefix}calc <phép tính> : Tính toán nhanh (vd: {prefix}calc 25*4)\n"
                f"• {prefix}setttl <thời gian> : Cài đặt tin nhắn tự xóa hội thoại (vd: {prefix}setttl 7d, {prefix}setttl 1d, {prefix}setttl 0)\n"
                f"• {prefix}ttl : Xem thông tin TTL tự xóa\n"
                f"• {prefix}info : Xem thông tin cấu hình Bot"
            )
        elif cmd_name == "time":
            return f"⏰ Thời gian hệ thống: {datetime.now(TZ_VN).strftime('%H:%M:%S %d/%m/%Y')} (GMT+7)"
        elif cmd_name == "echo":
            return f"🗣️ Echo: {arg}" if arg else f"Vui lòng nhập nội dung sau {prefix}echo"
        elif cmd_name in ("setttl", "ttlset"):
            if not arg:
                return (
                    f"⚙️ Cú pháp cài đặt Tin nhắn tự xóa (TTL):\n"
                    f"• {prefix}setttl 7d : Tự xóa sau 7 ngày (604800s)\n"
                    f"• {prefix}setttl 1d : Tự xóa sau 1 ngày (86400s)\n"
                    f"• {prefix}setttl 10s : Tự xóa sau 10 giây\n"
                    f"• {prefix}setttl 5s : Tự xóa sau 5 giây\n"
                    f"• {prefix}setttl 0 : Tắt tính năng tự xóa"
                )
            dur = parse_ttl_duration(arg)
            dur_str = f"{dur} giây" if dur < 86400 else f"{dur // 86400} ngày ({dur}s)"
            if dur == 0:
                return f"__ACTION_SET_TTL:0__ Đã tắt chế độ Tin nhắn tự xóa cho hội thoại."
            return f"__ACTION_SET_TTL:{dur}__ Đã thiết lập Tin nhắn tự xóa hội thoại là {dur_str}."
        elif cmd_name == "ttl":
            if arg:
                dur = parse_ttl_duration(arg)
                dur_str = f"{dur} giây" if dur < 86400 else f"{dur // 86400} ngày ({dur}s)"
                return f"⏳ Thời gian TTL: {dur_str}. Dùng {prefix}setttl {arg} để áp dụng cho hội thoại."
            return f"⏳ TTL (Time-To-Live) hỗ trợ các mốc: 5s, 10s, 1 ngày (1d = 86400s), 7 ngày (7d = 604800s). Dùng {prefix}setttl <mốc> để bật."
        elif cmd_name == "info":
            return "⚡ Zalo Realtime Socket Quoting Bot (AES-GCM + E2EE AES-CBC + TTL Support)"

        elif cmd_name == "calc":
            if not arg:
                return f"Cú pháp: {prefix}calc <biểu thức> (Ví dụ: {prefix}calc (12 + 8) * 5)"
            try:
                if re.match(r'^[0-9\+\-\*\/\(\)\.\s]+$', arg):
                    res = eval(arg, {"__builtins__": None}, {})
                    return f"🔢 Kết quả: {arg} = {res}"
                else:
                    return "❌ Biểu thức không hợp lệ. Chỉ chấp nhận các số và toán tử + - * /"
            except Exception as e:
                return f"❌ Lỗi tính toán: {e}"
        else:
            # Trong group, nếu là lệnh của bot khác (vd: /tl) hoặc không thuộc danh sách -> BỎ QUA tránh spam
            if group_id and not is_bot_mentioned:
                return None
            return f"❓ Lệnh {prefix}{cmd_name} không tồn tại. Gõ {prefix}help để xem danh sách lệnh."

    # 2. Xử lý từ khóa lọc (nếu có cấu hình --keywords)
    if keywords_list:
        lower_txt = msg_txt.lower()
        matched = any(kw.lower() in lower_txt for kw in keywords_list)
        if not matched:
            return None

    # 3. Phản hồi theo từ khóa phổ biến trong từ điển (Chỉ trong 1-1 hoặc khi được tag trong group)
    if not group_id or is_bot_mentioned or prefix is None:
        lower_txt = msg_txt.lower()
        for kw, resp in KEYWORD_RESPONSES.items():
            if kw == lower_txt or re.search(r'\b' + re.escape(kw) + r'\b', lower_txt):
                return f"🤖 {resp}"


    # 4. Phản hồi cố định nếu cấu hình --reply-text
    if fixed_reply:
        return fixed_reply

    # 5. Phản hồi toàn bộ nếu cấu hình --all
    if reply_all:
        if msg_txt:
            return f"🤖 [Auto-Reply] Đã nhận: '{msg_txt}'"
        elif msg_type == 'chat.photo':
            return "🤖 [Auto-Reply] Đã nhận hình ảnh của bạn!"
        elif msg_type == 'chat.sticker':
            return "🤖 [Auto-Reply] Sticker đẹp đấy!"
        elif msg_type == 'chat.voice':
            return "🤖 [Auto-Reply] Đã nhận tin nhắn thoại!"

    return None


class ZaloRealtimeChatClient:
    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        uid: Optional[int] = None,
        dk: Optional[bytes] = None,
        cryptkey: Optional[bytes] = None,
        f0_bytes: Optional[bytes] = None,
        init_frames_path: str = '/root/zalo/init_sequence.json',
        server_pool: Optional[List[Dict[str, Any]]] = None,
        auto_reconnect: bool = True,
        on_message: Optional[Callable[[Dict[str, Any]], None]] = None,
        quiet: bool = False
    ):
        self.host = host
        self.port = port
        self.uid = uid
        self.dk = dk
        self.cryptkey = cryptkey
        self.f0_bytes = f0_bytes
        self.init_frames_path = init_frames_path
        self.server_pool = server_pool or load_server_pool()
        self.auto_reconnect = auto_reconnect
        self.on_message_callback = on_message
        self.quiet = quiet

        self.sock: Optional[socket.socket] = None
        self.sock_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.recv_thread: Optional[threading.Thread] = None
        self.ping_thread: Optional[threading.Thread] = None
        self.supervisor_thread: Optional[threading.Thread] = None

        self.current_seq = -45
        self.seq_lock = threading.Lock()

        # Quản lý ACK & In-Flight requests
        self.pending_acks: Dict[int, Dict[str, Any]] = {}
        self.ack_lock = threading.Lock()
        self.general_ack_event = threading.Event()
        self.last_ack_result: Dict[str, Any] = {}
        self.init_data: Dict[str, Any] = {}
        self.is_connected = False
        self.last_activity_time = time.time()
        self.reconnect_count = 0

        # Debouncing typing notifications
        self.last_typing_times: Dict[int, float] = {}
        self.typing_lock = threading.Lock()

    def next_seq(self) -> int:
        with self.seq_lock:
            self.current_seq -= 1
            return self.current_seq

    def _apply_socket_keepalive(self, sock: socket.socket):
        """Cấu hình TCP Keep-Alive tầng hệ điều hành để tránh bị Router/NAT cắt kết nối ngầm."""
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, 'TCP_KEEPIDLE'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 10)
            if hasattr(socket, 'TCP_KEEPINTVL'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
            if hasattr(socket, 'TCP_KEEPCNT'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except Exception as e:
            LOGGER.debug(f"Apply keepalive warning: {e}")

    def connect(self, host: Optional[str] = None, port: Optional[int] = None):
        target_host = host or self.host
        target_port = port or self.port

        new_sock = socket.create_connection((target_host, target_port), timeout=12)
        self._apply_socket_keepalive(new_sock)

        if target_port == 443:
            req = f"GET / HTTP/1.1\r\nHost: {target_host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode('latin1')
            new_sock.sendall(req)
            resp = new_sock.recv(1024).decode('latin1', errors='ignore')
            if "HTTP/1." not in resp:
                new_sock.close()
                raise RuntimeError(f"HTTP Upgrade thất bại: {resp[:100]}")

        # Gửi Frame 0 Handshake
        f0_frame = struct.pack('<IB', len(self.f0_bytes) + 5, 8) + self.f0_bytes
        new_sock.sendall(f0_frame)

        with self.sock_lock:
            if self.sock:
                try: self.sock.close()
                except Exception: pass
            self.sock = new_sock
            self.host = target_host
            self.port = target_port
            self.is_connected = True
            self.last_activity_time = time.time()

        # Đọc init sequence frames
        if not self.init_data and os.path.isfile(self.init_frames_path):
            try:
                with open(self.init_frames_path, 'r', encoding='utf-8') as f:
                    self.init_data = json.load(f)
            except Exception:
                pass

        # Gửi các frame khởi tạo phiên ban đầu (Frames 1..3)
        init_frames = self.init_data.get('frames', [])[1:4]
        for fr in init_frames:
            raw_b = bytes.fromhex(fr['raw_frame_hex'])
            with self.sock_lock:
                self.sock.sendall(raw_b)
            time.sleep(0.01)
        time.sleep(0.2)

        # Khởi động luồng nhận tin nhắn nếu chưa chạy
        if not self.recv_thread or not self.recv_thread.is_alive():
            self.recv_thread = threading.Thread(target=self._recv_loop, daemon=True, name="ZaloRecvThread")
            self.recv_thread.start()

        # Khởi động luồng Heartbeat Ping duy trì kết nối (10s/lần)
        if not self.ping_thread or not self.ping_thread.is_alive():
            self.ping_thread = threading.Thread(target=self._heartbeat_loop, daemon=True, name="ZaloPingThread")
            self.ping_thread.start()

        # Khởi động luồng Giám sát & Tự động Reconnect
        if self.auto_reconnect and (not self.supervisor_thread or not self.supervisor_thread.is_alive()):
            self.supervisor_thread = threading.Thread(target=self._supervisor_loop, daemon=True, name="ZaloSupervisorThread")
            self.supervisor_thread.start()

    def _heartbeat_loop(self):
        """Gửi heartbeat ping định kỳ mỗi 10 giây để đảm bảo socket duy trì 24/7 không bị ngắt."""
        while not self.stop_event.is_set():
            if self.stop_event.wait(10):
                break
            if not self.is_connected:
                continue
            try:
                # CMD 1971 SUB 0 Ping frame chuẩn: bb=0, ty=1, ver=3, params=e7b728bfad
                seq = self.next_seq()
                ck = ((0 + 1 + seq + self.uid + 3 + 1971 + 0) & 0xFFFFFFFF) ^ 0x6ce7daa0
                inner = struct.pack('<IBBiIBHB', ck, 0, 1, seq, self.uid, 3, 1971, 0) + bytes.fromhex('e7b728bfad')
                raw = build_gcm_frame(inner, self.dk)
                with self.sock_lock:
                    if self.sock and self.is_connected:
                        self.sock.sendall(raw)
                        self.last_activity_time = time.time()
                LOGGER.debug(f"[PING] Sent Heartbeat Ping CMD 1971 (Seq={seq})")
            except Exception as e:
                LOGGER.warning(f"Error in heartbeat ping: {e}")
                self.is_connected = False

    def _supervisor_loop(self):
        """Luồng giám sát tự động kết nối lại (Auto-Reconnect & Failover) khi rớt mạng."""
        while not self.stop_event.is_set():
            time.sleep(2.0)
            if self.stop_event.is_set():
                break

            if not self.is_connected or (time.time() - self.last_activity_time) > 45:
                now_str = datetime.now().strftime('%H:%M:%S')
                print(f"[{now_str}] ⚠️ [MẤT KẾT NỐI] Đang tự động kết nối lại...")
                self.reconnect_count += 1
                target_server = self.host
                target_port = self.port

                try:
                    self.connect(host=target_server, port=target_port)
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] [✔ THÀNH CÔNG] Đã khôi phục kết nối Socket ({target_server}:{target_port})!")
                except Exception as re_err:
                    LOGGER.debug(f"Reconnect attempt failed: {re_err}")
                    time.sleep(3.0)

    def _send_delivery_ack(self, target_uid: int, cmsg_id: int, is_group: bool = False):
        """Gửi ACK đã nhận tin (Delivery Receipt) về server."""
        try:
            cmd = 202 if is_group else 102
            sub = 3
            seq = self.next_seq()
            ck = compute_checksum(cmd, sub, seq, self.uid, target_uid, 3, cmsg_id)
            params = struct.pack('<IBII', target_uid, 3, cmsg_id, 0)
            inner = struct.pack('<IBBiIBHB', ck, 1, 2, seq, self.uid, 3, cmd, sub) + params
            raw = build_gcm_frame(inner, self.dk)
            with self.sock_lock:
                if self.sock and not self.stop_event.is_set():
                    self.sock.sendall(raw)
                    self.last_activity_time = time.time()
            LOGGER.debug(f"[ACK] Sent Delivery Receipt CMD {cmd} SUB {sub} for msg 0x{cmsg_id:08x}")
        except Exception as e:
            LOGGER.warning(f"Error sending delivery ack: {e}")

    def _recv_loop(self):
        buf = bytearray()
        while not self.stop_event.is_set():
            try:
                if not self.sock or not self.is_connected:
                    time.sleep(0.5)
                    continue

                self.sock.settimeout(1.0)
                chunk = self.sock.recv(4096)
                if not chunk:
                    LOGGER.warning("Socket closed by remote host.")
                    self.is_connected = False
                    time.sleep(1.0)
                    continue

                buf.extend(chunk)
                self.last_activity_time = time.time()

                while len(buf) >= 5:
                    flen, ftype = struct.unpack('<IB', buf[:5])
                    if flen < 5 or flen > 262144:
                        buf.pop(0)
                        continue
                    if len(buf) < flen:
                        break
                    fbody = bytes(buf[5:flen])
                    del buf[:flen]

                    if ftype in (3, 4):
                        try:
                            iv, tag, ct = fbody[-12:], fbody[-28:-12], fbody[:-28]
                            pt = AES.new(self.dk, AES.MODE_GCM, nonce=iv, mac_len=16).decrypt_and_verify(ct, tag)
                            if len(pt) < 18:
                                continue
                            r_ck, bb, ty, r_seq, r_uid, ver, r_cmd, r_sub = struct.unpack('<IBBiIBHB', pt[:18])
                            params = pt[18:]
                            self._handle_incoming_packet(r_cmd, r_sub, r_seq, r_uid, params)
                        except Exception as de:
                            LOGGER.debug(f"Decrypt frame error: {de}")
            except socket.timeout:
                continue
            except Exception as e:
                LOGGER.error(f"Recv loop error: {e}")
                self.is_connected = False
                time.sleep(1.0)

    def _handle_incoming_packet(self, cmd: int, sub: int, seq: int, uid: int, params: bytes):
        now_str = datetime.now().strftime('%H:%M:%S')
        code = struct.unpack('<i', params[:4])[0] if len(params) >= 4 else (params[0] if params else 0)
        LOGGER.debug(f"[RECV] CMD={cmd} SUB={sub} SEQ={seq} UID={uid} len={len(params)}")

        # 0. CMD 1971 SUB 0: Heartbeat Pong
        if cmd == 1971:
            LOGGER.debug(f"[PONG] Heartbeat Pong ACK từ Server")
            return

        # 1. NHẬN TIN NHẮN (CMD 101, 201, 1865, 1867)
        if cmd in (101, 201, 1865, 1867):
            decomp_json = None
            is_group = (cmd in (201, 1867))
            cmsg_id = 0

            payload_bytes = params
            if len(params) >= 13:
                try:
                    p_uid, p_type, cmsg_id, flags = struct.unpack('<IBII', params[:13])
                    payload_bytes = params[13:]
                except Exception:
                    pass

            # A. Giải mã XOR d3 theo UID người gửi
            if cmd in (101, 201):
                for try_u in (uid, self.uid):
                    try:
                        d3_dec = xor_decode_d3(payload_bytes, try_u)
                        decomp = gzip.decompress(d3_dec)
                        decomp_json = json.loads(decomp.decode('utf-8', errors='ignore'))
                        if decomp_json:
                            break
                    except Exception:
                        pass

            # B. Giải mã GZIP trực tiếp (CMD 1865/1867)
            if not decomp_json and payload_bytes.startswith(b'\x1f\x8b'):
                try:
                    decomp = gzip.decompress(payload_bytes)
                    decomp_json = json.loads(decomp.decode('utf-8', errors='ignore'))
                except Exception:
                    pass

            # C. Giải mã JSON thuần
            if not decomp_json:
                try:
                    decomp_json = json.loads(payload_bytes.decode('utf-8', errors='ignore'))
                except Exception:
                    pass

            # Tự động gửi Delivery Receipt về server
            if cmd in (101, 201) and cmsg_id:
                threading.Thread(target=self._send_delivery_ack, args=(uid, cmsg_id, is_group), daemon=True).start()

            # Phân tích sự kiện tin nhắn
            if decomp_json and isinstance(decomp_json, dict):
                msg_list = decomp_json.get('msg', [])
                if not isinstance(msg_list, list):
                    msg_list = [msg_list]

                for item in msg_list:
                    if not isinstance(item, dict):
                        continue
                    t_obj = item.get('text', {})
                    ttype = t_obj.get('type')
                    tdata = t_obj.get('data', {})

                    raw_from_u = tdata.get('fromU')
                    msg_id = tdata.get('id') or item.get('id')
                    cmi_id = tdata.get('cliMsgId') or cmsg_id

                    # Xác định rõ danh tính người gửi (Self vs Peer)
                    if cmd == 1865:
                        is_self = True
                        from_uid = self.uid
                        from_name = "Tôi"
                        to_id = tdata.get('to') or uid
                        is_group = False
                    elif cmd == 101:
                        is_self = False
                        from_uid = raw_from_u or uid
                        from_name = tdata.get('fromD') or get_name(from_uid)
                        to_id = tdata.get('to') or self.uid
                        is_group = False
                    elif cmd in (201, 1867):
                        is_group = True
                        to_id = uid
                        if raw_from_u == 0 or raw_from_u == self.uid:
                            is_self = True
                            from_uid = self.uid
                            from_name = "Tôi"
                        else:
                            is_self = False
                            from_uid = raw_from_u or uid
                            from_name = tdata.get('fromD') or get_name(from_uid)
                    else:
                        is_self = (raw_from_u == self.uid)
                        from_uid = raw_from_u or uid
                        from_name = tdata.get('fromD') or get_name(from_uid)
                        to_id = tdata.get('to') or uid

                    # Decrypt E2EE nếu có
                    msg_txt = tdata.get('msg', '')
                    if tdata.get('mcrypt') == 1 and tdata.get('iv') and self.cryptkey:
                        dec = decrypt_e2ee_text(msg_txt, tdata.get('iv'), self.cryptkey)
                        if dec:
                            msg_txt = dec

                    # Bỏ qua packet echo rỗng do server tự sinh khi gửi tin
                    if is_self and not msg_txt and cmd in (1865, 1867):
                        continue

                    # Trích xuất Quote (Trích dẫn tin nhắn) nếu có
                    quote_data = tdata.get('quote')
                    if isinstance(quote_data, str) and quote_data.startswith('{'):
                        try: quote_data = json.loads(quote_data)
                        except Exception: pass

                    # Trích xuất Mentions (@tag)
                    mentions_data = tdata.get('mentions')
                    if isinstance(mentions_data, str) and mentions_data.startswith('['):
                        try: mentions_data = json.loads(mentions_data)
                        except Exception: mentions_data = []
                    elif not isinstance(mentions_data, list):
                        mentions_data = []

                    # Tự động loại bỏ vùng text mention để lấy nội dung câu lệnh thực sự
                    clean_txt, is_bot_tagged, mentioned_uids = clean_message_text(msg_txt, mentions_data, bot_uid=self.uid)

                    event_info = {
                        'cmd': cmd,
                        'is_group': is_group,
                        'is_self': is_self,
                        'from_uid': from_uid,
                        'from_name': from_name,
                        'to_id': to_id,
                        'msg_id': msg_id,
                        'cli_msg_id': cmi_id,
                        'msg_type': ttype,
                        'text': msg_txt,
                        'clean_text': clean_txt,
                        'mentions': mentions_data,
                        'is_bot_mentioned': is_bot_tagged,
                        'mentioned_uids': mentioned_uids,
                        'quote': quote_data,
                        'raw': tdata,
                        'ts': tdata.get('ts') or int(time.time() * 1000)
                    }

                    # In Console Log gọn gàng, rõ ràng
                    dest_str = f"Group {to_id}" if is_group else ("Bạn" if not is_self else get_name(to_id))
                    quote_str = ""
                    if quote_data and isinstance(quote_data, dict):
                        q_name = quote_data.get('fromD', '?')
                        q_msg = quote_data.get('msg', '')
                        quote_str = f"\n   ↳ [Trích dẫn {q_name}]: '{q_msg}'"

                    if is_self:
                        if msg_txt:
                            print(f"[{now_str}] 📤 [BẠN GỬI ➔ {dest_str}]: '{msg_txt}'{quote_str}")
                    else:
                        if ttype == 'webchat':
                            tag = f"GROUP {to_id}" if is_group else "1-1"
                            print(f"[{now_str}] 💬 [{tag}] {from_name} ➔ {dest_str}: '{msg_txt}'{quote_str}")
                        elif ttype == 'chat.sticker':
                            attach = tdata.get('attach', {})
                            if isinstance(attach, str):
                                try: attach = json.loads(attach)
                                except Exception: attach = {}
                            stk_id = attach.get('id') or attach.get('stkid', '?')
                            print(f"[{now_str}] 🎭 [STICKER] {from_name} ➔ {dest_str}: #{stk_id}")
                        elif ttype in ('chat.photo', 'chat.video'):
                            attach = tdata.get('attach', {})
                            if isinstance(attach, str):
                                try: attach = json.loads(attach)
                                except Exception: attach = {}
                            url = attach.get('href') or attach.get('hdUrl') or attach.get('url', '')
                            kind = "ẢNH" if ttype == 'chat.photo' else "VIDEO"
                            print(f"[{now_str}] 🖼️  [{kind}] {from_name} ➔ {dest_str}: {url}")
                        elif ttype == 'chat.voice':
                            attach = tdata.get('attach', {})
                            if isinstance(attach, str):
                                try: attach = json.loads(attach)
                                except Exception: attach = {}
                            url = attach.get('href') or attach.get('url', '')
                            print(f"[{now_str}] 🎤 [VOICE] {from_name} ➔ {dest_str}: {url}")
                        elif ttype == 'chat.reaction':
                            r_id = tdata.get('rMsgId') or msg_id
                            r_icon = tdata.get('rType') or '❤️'
                            print(f"[{now_str}] ❤️  [REACTION] {from_name} thả {r_icon} vào tin #{r_id}")
                        elif ttype in ('chat.undo', 'chat.delete'):
                            print(f"[{now_str}] 🗑️  [THU HỒI] {from_name} đã thu hồi tin nhắn #{msg_id}")

                    # Callback xử lý sự kiện
                    if self.on_message_callback:
                        try:
                            self.on_message_callback(event_info)
                        except Exception as ce:
                            LOGGER.warning(f"Error in on_message callback: {ce}")

        # 2. CMD 102 SUB 3 / CMD 202 SUB 3 (Receipts)
        elif (cmd == 102 or cmd == 202) and sub == 3:
            try:
                json_part = params[4:].decode('utf-8', errors='ignore').strip()
                if json_part.startswith('{'):
                    js = json.loads(json_part)
                    for item in js.get("data", []):
                        for m in item.get("msg", []):
                            cmi = m.get("cmi")
                            gmi = m.get("gmi")
                            err = m.get("err", 0)
                            if err == 0:
                                with self.ack_lock:
                                    self.last_ack_result = {"success": True, "err_code": 0, "details": m, "gmi": gmi, "cmi": cmi}
                                    if cmi in self.pending_acks:
                                        self.pending_acks[cmi]["event"].set()
                                        self.pending_acks[cmi]["result"] = m
                                    self.general_ack_event.set()
            except Exception:
                pass

        # 3. CMD 106 SUB 1 / CMD 206 SUB 1: Typing Status (Debounced gọn gàng)
        elif (cmd == 106 or cmd == 206) and sub == 1:
            now = time.time()
            with self.typing_lock:
                if uid in self.last_typing_times and (now - self.last_typing_times[uid]) < 6.0:
                    return
                self.last_typing_times[uid] = now

            t_name = get_name(uid)
            if len(params) >= 4:
                try:
                    target_dest = struct.unpack('<I', params[:4])[0]
                    if target_dest and target_dest != self.uid:
                        print(f"[{now_str}] ✍️  {t_name} đang soạn tin trong Group {target_dest}...")
                    else:
                        print(f"[{now_str}] ✍️  {t_name} đang soạn tin nhắn tới bạn...")
                except Exception:
                    pass

        # 4. Outbound Sent Confirmation (CMD 113 SUB 41 / CMD 207 SUB 1)
        elif (cmd == 113 and sub == 41) or (cmd == 207 and sub == 1):
            if code == 0:
                with self.ack_lock:
                    self.last_ack_result = {"success": True, "err_code": 0}
                    self.general_ack_event.set()

        # 5. CMD 3 SUB 0: Session Disconnect
        elif cmd == 3 and sub == 0:
            if code == -22:
                print(f"[{now_str}] ⚠️ [THÔNG BÁO PHIÊN] Đã có kết nối mới thay thế (Code=-22).")

        # 6. CMD 2060 SUB 0: Confirmation of Conversation TTL Update
        elif cmd == 2060:
            if code == 0:
                print(f"[{now_str}] ⏱️ [TTL] Server xác nhận: Cài đặt Tin nhắn tự xóa (TTL) thành công! (Code=0)")
                with self.ack_lock:
                    self.last_ack_result = {"success": True, "err_code": 0}
                    self.general_ack_event.set()
            else:
                print(f"[{now_str}] ⚠️ [TTL] Server báo lỗi cài đặt TTL: Code={code}")


    # -------------------------------------------------------------------------
    # GỬI TIN NHẮN 1-1 (HỖ TRỢ QUOTE TRÍCH DẪN)
    # -------------------------------------------------------------------------
    def send_1to1(
        self,
        target_uid: int,
        text: str,
        quote: Optional[Dict[str, Any]] = None,
        ttl: int = 0,
        typing_first: bool = False,
        timeout: float = 5.0
    ) -> Dict[str, Any]:
        if not self.is_connected or not self.sock:
            raise RuntimeError("Client chưa kết nối tới Socket Server!")

        if typing_first:
            seq_typ = self.next_seq()
            cmsg_typ = int(time.time() * 1000) & 0xFFFFFFFF
            ck_typ = compute_checksum(106, 1, seq_typ, self.uid, target_uid, 3, cmsg_typ)
            params_typ = struct.pack('<IBII', target_uid, 3, cmsg_typ, 416)
            inner_typ = struct.pack('<IBBiIBHB', ck_typ, 1, 2, seq_typ, self.uid, 3, 106, 1) + params_typ
            with self.sock_lock:
                self.sock.sendall(build_gcm_frame(inner_typ, self.dk))
                self.last_activity_time = time.time()
            time.sleep(0.4)

        seq_msg = self.next_seq()
        cmsg_msg = int(time.time() * 1000) & 0xFFFFFFFF
        ck_msg = compute_checksum(113, 41, seq_msg, self.uid, target_uid, 3, cmsg_msg)

        d3_plain = build_d3_message_1to1(text, self.cryptkey, quote=quote, ttl=ttl)
        d3_xor = xor_encode_d3(d3_plain, self.uid)
        params_msg = struct.pack('<IBII', target_uid, 3, cmsg_msg, 416) + d3_xor
        inner_msg = struct.pack('<IBBiIBHB', ck_msg, 1, 2, seq_msg, self.uid, 3, 113, 41) + params_msg
        raw_frame = build_gcm_frame(inner_msg, self.dk)

        evt = threading.Event()
        with self.ack_lock:
            self.pending_acks[cmsg_msg] = {"event": evt, "result": None}
            self.general_ack_event.clear()

        try:
            with self.sock_lock:
                if not self.is_connected or not self.sock:
                    return {"success": False, "error": "Chưa kết nối"}
                self.sock.sendall(raw_frame)
                self.last_activity_time = time.time()
        except (BrokenPipeError, ConnectionResetError, OSError) as se:
            now_str = datetime.now().strftime('%H:%M:%S')
            print(f"[{now_str}] ⚠️ [LỖI SOCKET 1-1] Socket bị ngắt ({se}). Đang kích hoạt reconnect...")
            self._reconnect_safe()
            return {"success": False, "error": str(se)}

        now_str = datetime.now().strftime('%H:%M:%S')
        q_hint = f" ↳ (Trích dẫn: '{quote.get('msg', '')}')" if quote else ""
        ttl_hint = f" ⏳ [TTL={ttl}s]" if ttl > 0 else ""
        print(f"[{now_str}] 📤 [GỬI 1-1 ➔ {get_name(target_uid)}]: '{text}'{ttl_hint}{q_hint}")

        # Chờ ACK
        got_ack = evt.wait(timeout=timeout) or self.general_ack_event.wait(timeout=0.8)
        res = self.pending_acks.pop(cmsg_msg, {}).get("result") or self.last_ack_result

        if res.get("success") or res.get("err") == 0 or res.get("err_code") == 0:
            gmi = res.get("gmi") or res.get("details", {}).get("gmi")
            return {"success": True, "gmi": gmi, "details": res}
        else:
            return {"success": False, "error": "Timeout"}

    # -------------------------------------------------------------------------
    # GỬI TIN NHẮN GROUP (HỖ TRỢ QUOTE TRÍCH DẪN & TTL)
    # -------------------------------------------------------------------------
    def send_group(
        self,
        group_id: int,
        text: str,
        quote: Optional[Dict[str, Any]] = None,
        ttl: int = 0,
        typing_first: bool = False,
        timeout: float = 5.0
    ) -> Dict[str, Any]:
        if not self.is_connected or not self.sock:
            raise RuntimeError("Client chưa kết nối tới Socket Server!")

        if typing_first:
            seq_typ = self.next_seq()
            cmsg_typ = int(time.time() * 1000) & 0xFFFFFFFF
            ck_typ = compute_checksum(206, 1, seq_typ, self.uid, group_id, 3, cmsg_typ)
            params_typ = struct.pack('<IBII', group_id, 3, cmsg_typ, 416)
            inner_typ = struct.pack('<IBBiIBHB', ck_typ, 1, 2, seq_typ, self.uid, 3, 206, 1) + params_typ
            try:
                with self.sock_lock:
                    if self.sock:
                        self.sock.sendall(build_gcm_frame(inner_typ, self.dk))
                        self.last_activity_time = time.time()
            except Exception:
                pass
            time.sleep(0.4)

        seq_msg = self.next_seq()
        cmsg_msg = int(time.time() * 1000) & 0xFFFFFFFF
        ck_msg = compute_checksum(207, 1, seq_msg, self.uid, group_id, 4, cmsg_msg)

        d3_plain = build_d3_message_group(text, quote=quote, ttl=ttl)
        d3_xor = xor_encode_d3(d3_plain, self.uid)
        params_msg = struct.pack('<IBII', group_id, 4, cmsg_msg, 416) + d3_xor
        inner_msg = struct.pack('<IBBiIBHB', ck_msg, 1, 2, seq_msg, self.uid, 3, 207, 1) + params_msg
        raw_frame = build_gcm_frame(inner_msg, self.dk)

        evt = threading.Event()
        with self.ack_lock:
            self.pending_acks[cmsg_msg] = {"event": evt, "result": None}
            self.general_ack_event.clear()

        try:
            with self.sock_lock:
                if not self.is_connected or not self.sock:
                    return {"success": False, "error": "Chưa kết nối"}
                self.sock.sendall(raw_frame)
                self.last_activity_time = time.time()
        except (BrokenPipeError, ConnectionResetError, OSError) as se:
            now_str = datetime.now().strftime('%H:%M:%S')
            print(f"[{now_str}] ⚠️ [LỖI SOCKET GROUP] Socket bị ngắt ({se}). Đang kích hoạt reconnect...")
            self._reconnect_safe()
            return {"success": False, "error": str(se)}


        now_str = datetime.now().strftime('%H:%M:%S')
        q_hint = f" ↳ (Trích dẫn: '{quote.get('msg', '')}')" if quote else ""
        ttl_hint = f" ⏳ [TTL={ttl}s]" if ttl > 0 else ""
        print(f"[{now_str}] 📤 [GỬI GROUP {group_id}]: '{text}'{ttl_hint}{q_hint}")

        got_ack = evt.wait(timeout=timeout) or self.general_ack_event.wait(timeout=0.8)
        res = self.pending_acks.pop(cmsg_msg, {}).get("result") or self.last_ack_result

        if res.get("success") or res.get("err") == 0 or res.get("err_code") == 0:
            gmi = res.get("gmi") or res.get("details", {}).get("gmi")
            return {"success": True, "gmi": gmi, "details": res}
        else:
            return {"success": False, "error": "Timeout"}

    # -------------------------------------------------------------------------
    # THIẾT LẬP TIN NHẮN TỰ XÓA (TTL) CẤP HỘI THOẠI (CMD 2060 / 0x080C)
    # -------------------------------------------------------------------------
    def set_conversation_ttl(
        self,
        target_id: int,
        ttl_seconds: int,
        is_group: bool = True,
        timeout: float = 5.0
    ) -> Dict[str, Any]:
        """
        Kích hoạt hoặc thay đổi chế độ Tin nhắn tự xóa (TTL) cho hội thoại (Group hoặc 1-1).
        CMD: 2060 (0x080C), Sub: 0, Version: 3
        Dựa trên phân tích Smali từ Zalo Android gốc (Lgz/w7.smali & Lgz/z7.smali):
          Payload (24 bytes):
            - 1B: 0x01
            - 4B uint32 LE: 0 (CoreUtility.l)
            - 2B uint16 LE: 0 (language code)
            - 4B uint32 LE: 1 (uc.d(1))
            - 1B: 0x02 nếu là Group, 0x01 nếu là 1-1
            - 4B uint32 LE: target_id (Group ID hoặc User UID)
            - 8B uint64 LE: ttl_seconds (0 = tắt, 5, 10, 86400=1d, 604800=7d, v.v.)
        """
        if not self.is_connected or not self.sock:
            raise RuntimeError("Client chưa kết nối tới Socket Server!")

        seq = self.next_seq()
        ck = compute_checksum(2060, 0, seq, self.uid, target=0, target_type=0, cmsg=0, bb=1, ty=0, ver=3)

        target_type_byte = 0x02 if is_group else 0x01
        params = (
            bytes([0x01]) +
            struct.pack('<I', 0) +
            struct.pack('<H', 0) +
            struct.pack('<I', 1) +
            bytes([target_type_byte]) +
            struct.pack('<I', target_id) +
            struct.pack('<Q', ttl_seconds)
        )

        inner_pkt = struct.pack('<IBBiIBHB', ck, 1, 0, seq, self.uid, 3, 2060, 0) + params
        raw_frame = build_gcm_frame(inner_pkt, self.dk)

        with self.ack_lock:
            self.general_ack_event.clear()

        with self.sock_lock:
            self.sock.sendall(raw_frame)
            self.last_activity_time = time.time()

        now_str = datetime.now().strftime('%H:%M:%S')
        dest_type = f"Group {target_id}" if is_group else f"1-1 {get_name(target_id)}"
        ttl_desc = f"{ttl_seconds}s" if ttl_seconds > 0 else "Tắt (0s)"
        print(f"[{now_str}] ⏱️ [SET TTL CONVERSATION] Gửi lệnh thiết lập TTL cho {dest_type} ➔ {ttl_desc}")

        got_ack = self.general_ack_event.wait(timeout=timeout)
        res = self.last_ack_result
        if got_ack and (res.get("success") or res.get("err_code") == 0):
            return {"success": True, "ttl": ttl_seconds}
        return {"success": False, "error": "Timeout hoặc Server báo lỗi"}

    def close(self):

        self.stop_event.set()
        self.is_connected = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass


def interactive_chat_session(client: ZaloRealtimeChatClient, default_to: Optional[int] = None, default_group: Optional[int] = None):
    """Giao diện dòng lệnh tương tác trực tiếp (Interactive Chat Room)."""
    print("\n╔══════════════════════════════════════════════════════════════════╗")
    print("║          ZALO REALTIME FULL-DUPLEX CHAT CONSOLE                  ║")
    print("╠══════════════════════════════════════════════════════════════════╣")
    print("║ Cú pháp gửi tin:                                                 ║")
    print("║  • 1-1 <uid> <nội dung>       : Gửi tin nhắn 1-1                 ║")
    print("║  • group <group_id> <nội dung>: Gửi tin nhắn nhóm                ║")
    print("║  • to <nội dung>              : Gửi nhanh đến mục tiêu mặc định  ║")
    print("║  • exit / quit                : Đóng kết nối và thoát            ║")
    print("╚══════════════════════════════════════════════════════════════════╝\n")

    while not client.stop_event.is_set():
        try:
            line = input("\n[Nhập tin] > ").strip()
            if not line:
                continue

            if line.lower() in ('exit', 'quit', 'q'):
                print("[*] Đang đóng phiên chat...")
                break

            # Xử lý lệnh gửi 1-1
            m_11 = re.match(r'^(?:1-1|to|user|u)\s+(\d+)\s+(.+)$', line, re.IGNORECASE)
            if m_11:
                t_uid = int(m_11.group(1))
                msg_txt = m_11.group(2)
                client.send_1to1(t_uid, msg_txt)
                continue

            # Xử lý lệnh gửi group
            m_grp = re.match(r'^(?:group|g|grp)\s+(\d+)\s+(.+)$', line, re.IGNORECASE)
            if m_grp:
                g_id = int(m_grp.group(1))
                msg_txt = m_grp.group(2)
                client.send_group(g_id, msg_txt)
                continue

            # Gửi nhanh tới mục tiêu mặc định
            if default_to and not line.startswith('/'):
                client.send_1to1(default_to, line)
            elif default_group and not line.startswith('/'):
                client.send_group(default_group, line)
            else:
                print("[!] Vui lòng nhập rõ cú pháp: 1-1 <uid> <nội dung> hoặc group <gid> <nội dung>")

        except (KeyboardInterrupt, EOFError):
            print("\n[*] Đã nhận tín hiệu dừng (Ctrl+C).")
            break
        except Exception as e:
            print(f"[!] Lỗi khi gửi: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Zalo Realtime Full-Duplex Chat & Smart Quoting Bot",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    # Nhóm tham số vận hành Bot
    parser.add_argument("-b", "--bot", "--auto-reply", dest="auto_reply", action="store_true", help="Bật chế độ Auto-Reply Bot")
    parser.add_argument("--prefix", type=str, default="/", help="Tiền tố lệnh Bot (Mặc định: '/', truyền '' nếu không dùng prefix)")
    parser.add_argument("--no-quote", action="store_true", help="Không trích dẫn tin nhắn gốc khi bot trả lời")
    parser.add_argument("--keywords", type=str, help="Danh sách từ khóa cần phản hồi (cách nhau bởi dấu phẩy, e.g. 'chào,hi,bot')")
    parser.add_argument("--reply-text", type=str, help="Nội dung tin nhắn trả lời cố định")
    parser.add_argument("--all", action="store_true", help="Tự động trả lời tất cả tin nhắn")

    # Nhóm tham số gửi tin & lắng nghe
    parser.add_argument("-i", "--interactive", action="store_true", help="Bật giao diện chat terminal tương tác")
    parser.add_argument("-l", "--listen", action="store_true", help="Chế độ chỉ lắng nghe (Daemon)")
    parser.add_argument("--to", type=int, default=277635559, help="UID người dùng đích 1-1")
    parser.add_argument("--group", type=int, default=686355764, help="ID Group đích")
    parser.add_argument("--msg", type=str, help="Gửi ngay 1 tin nhắn khi khởi động")
    parser.add_argument("--ttl", type=int, default=0, help="Thời gian tự xóa tin nhắn TTL tính bằng giây (vd: 5, 10, 86400, 0=vĩnh viễn)")
    parser.add_argument("-d", "--duration", type=int, default=0, help="Thời gian chạy tính bằng giây (0 = chạy 24/7)")

    # Nhóm tham số cấu hình hệ thống
    parser.add_argument("-s", "--server", type=str, default=DEFAULT_HOST, help=f"Host Socket Server (Mặc định: {DEFAULT_HOST})")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help="Port Socket Server (Mặc định: 443)")
    parser.add_argument("--zaloprefs", type=str, default="/root/zalo/zaloprefs", help="Đường dẫn database zaloprefs")
    parser.add_argument("--frame0-file", type=str, default="/root/zalo/frame0.bin", help="Đường dẫn file Frame 0 Handshake")
    parser.add_argument("--init-sequence", type=str, default="/root/zalo/init_sequence.json", help="Đường dẫn file Init Sequence")

    args = parser.parse_args()

    # Đọc thông tin xác thực
    p_data = parse_zaloprefs(args.zaloprefs)
    cur_uid = p_data.get('current_uid')
    if not cur_uid or cur_uid not in p_data['users']:
        sys.exit("[!] Không tìm thấy tài khoản người dùng trong zaloprefs.")

    uinfo = p_data['users'][cur_uid]
    sender_uid = uinfo['uid']
    dk_bytes = uinfo['dk']
    ck_bytes = uinfo['cryptkey']

    if not os.path.isfile(args.frame0_file):
        sys.exit(f"[!] Không tìm thấy file Frame 0: {args.frame0_file}")
    f0_bytes = open(args.frame0_file, 'rb').read()

    server_pool = load_server_pool()

    # Parse keywords filter list
    kw_list = [k.strip() for k in args.keywords.split(',')] if args.keywords else None
    last_reply_times: Dict[int, float] = {}
    rate_lock = threading.Lock()

    def handle_incoming(ev: Dict[str, Any]):
        if not args.auto_reply:
            return

        # 1. Bỏ qua tin nhắn do chính bot gửi (Tránh vòng lặp lặp vô hạn)
        if ev.get('is_self') or ev.get('from_uid') == sender_uid:
            return

        from_u = ev.get('from_uid')
        if not from_u:
            return

        raw_txt = (ev.get('text') or '').strip()
        clean_txt = (ev.get('clean_text') or raw_txt).strip()
        is_bot_tagged = ev.get('is_bot_mentioned', False)
        ttype = ev.get('msg_type', 'webchat')

        # 2. Bỏ qua tin nhắn echo từ bot
        if raw_txt.startswith("🤖") or raw_txt.startswith("[Auto-Reply]") or raw_txt.startswith("🏓") or raw_txt.startswith("⏰") or raw_txt.startswith("🗣️") or raw_txt.startswith("🔢") or raw_txt.startswith("👤"):
            return

        # 3. Rate limiter chống spam (Tối đa 1 tin phản hồi mỗi 1.2s cho 1 user)
        now = time.time()
        with rate_lock:
            if from_u in last_reply_times and (now - last_reply_times[from_u]) < 1.2:
                return
            last_reply_times[from_u] = now

        # Nếu người dùng tag bot trực tiếp mà không gõ prefix (ví dụ: @Bot ping, @Bot help, @Bot uid)
        target_cmd_txt = clean_txt
        if is_bot_tagged and args.prefix and not target_cmd_txt.startswith(args.prefix):
            first_word = target_cmd_txt.split(' ')[0].lower()
            if first_word in ("ping", "help", "uid", "time", "echo", "calc", "info"):
                target_cmd_txt = f"{args.prefix}{target_cmd_txt}"

        # 4. Sinh nội dung phản hồi theo cấu hình
        reply_txt = generate_bot_response(
            msg_txt=target_cmd_txt,
            msg_type=ttype,
            prefix=args.prefix if args.prefix != "" else None,
            keywords_list=kw_list,
            fixed_reply=args.reply_text,
            reply_all=args.all,
            from_uid=from_u,
            group_id=ev.get('to_id') if ev.get('is_group') else None,
            is_bot_mentioned=is_bot_tagged,
        )

        if reply_txt:
            # Xử lý lệnh thiết lập TTL cuộc trò chuyện nếu có
            set_ttl_match = re.search(r'__ACTION_SET_TTL:(\d+)__\s*', reply_txt)
            if set_ttl_match:
                ttl_action_val = int(set_ttl_match.group(1))
                reply_txt = re.sub(r'__ACTION_SET_TTL:\d+__\s*', '', reply_txt).strip()
                dest_id = ev.get('to_id') if ev.get('is_group') else from_u
                try:
                    client.set_conversation_ttl(dest_id, ttl_action_val, is_group=bool(ev.get('is_group')))
                except Exception as ex:
                    print(f"⚠️ Lỗi khi gửi lệnh cài đặt TTL: {ex}")

            # Tạo Quote Object từ tin nhắn được phản hồi (trừ khi truyền --no-quote)
            quote_payload = None if args.no_quote else build_quote_from_event(ev)

            if ev.get('is_group'):
                # Tạo thẻ @Tên_người_dùng chuẩn xác
                t_name = ev.get('from_name') or get_name(from_u) or str(from_u)
                if t_name.endswith(')') and ' (' in t_name:
                    t_name = t_name.split(' (')[0].strip()
                t_name = t_name.strip()

                if t_name and not reply_txt.startswith('@'):
                    group_reply_txt = f"@{t_name} {reply_txt}"
                else:
                    group_reply_txt = reply_txt

                threading.Thread(
                    target=lambda: client.send_group(ev.get('to_id'), group_reply_txt, quote=quote_payload, ttl=args.ttl, typing_first=False),
                    daemon=True
                ).start()
            else:
                threading.Thread(
                    target=lambda: client.send_1to1(from_u, reply_txt, quote=quote_payload, ttl=args.ttl, typing_first=False),
                    daemon=True
                ).start()

    client = ZaloRealtimeChatClient(
        host=args.server,
        port=args.port,
        uid=sender_uid,
        dk=dk_bytes,
        cryptkey=ck_bytes,
        f0_bytes=f0_bytes,
        init_frames_path=args.init_sequence,
        server_pool=server_pool,
        auto_reconnect=True,
        on_message=handle_incoming
    )

    try:
        client.connect()

        # Tự động thiết lập TTL cho hội thoại nếu có tham số --ttl
        if args.ttl > 0:
            if args.group:
                try:
                    client.set_conversation_ttl(args.group, args.ttl, is_group=True)
                except Exception as e:
                    print(f"⚠️ Lỗi tự động thiết lập TTL Group: {e}")
            elif args.to:
                try:
                    client.set_conversation_ttl(args.to, args.ttl, is_group=False)
                except Exception as e:
                    print(f"⚠️ Lỗi tự động thiết lập TTL 1-1: {e}")

        # Dashboard thông tin khởi chạy
        print("╔══════════════════════════════════════════════════════════════════╗")
        print("║           ZALO SOCKET REALTIME CLIENT & QUOTING BOT              ║")
        print("╠══════════════════════════════════════════════════════════════════╣")
        print(f"║ • Tài khoản: {get_name(sender_uid):<48} ║")
        print(f"║ • Máy chủ:   {args.server}:{args.port:<45} ║")
        print(f"║ • Chế độ:    {'Auto-Reply Bot [BẬT]' if args.auto_reply else ('Interactive Console' if args.interactive else 'Chỉ lắng nghe (Daemon)'):<48} ║")
        if args.auto_reply:
            print(f"║ • Tiền tố:   {args.prefix if args.prefix != '' else '[Tất cả/Từ khóa]':<48} ║")
            print(f"║ • Quoting:   {'BẬT (Trích dẫn tin nhắn gốc)' if not args.no_quote else 'TẮT (Chỉ text thuần)':<48} ║")
            print(f"║ • Anti-Loop: BẬT [100% Loại bỏ vòng lặp spam]                  ║")
        if args.ttl > 0:
            ttl_txt = f"{args.ttl}s" if args.ttl < 86400 else f"{args.ttl // 86400} ngày ({args.ttl}s)"
            print(f"║ • TTL Tự xóa:BẬT ({ttl_txt:<41}) ║")
        print("║ • Giữ mạng:  Ping Heartbeat (10s) + Auto-Reconnect (24/7)        ║")
        print("╚══════════════════════════════════════════════════════════════════╝\n")


        # Gửi tin nhắn tức thì nếu có chỉ định --msg
        if args.msg:
            if args.to:
                client.send_1to1(args.to, args.msg)
            elif args.group:
                client.send_group(args.group, args.msg)

        # Chế độ chạy
        if args.interactive:
            interactive_chat_session(client, default_to=args.to, default_group=args.group)
        else:
            print("[*] Đang trực tuyến & duy trì kết nối 24/7 (Nhấn Ctrl+C để dừng)...")
            start_t = time.time()
            while not client.stop_event.is_set():
                if args.duration > 0 and (time.time() - start_t) >= args.duration:
                    break
                time.sleep(0.5)

    finally:
        client.close()

if __name__ == '__main__':
    main()
