#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main.py — Giao diện dòng lệnh (CLI) & Auto-Reply Bot Realtime cho Zalo TCP Socket Client.
Sử dụng trọn vẹn kiến trúc SDK module hóa `core/`.
"""

import argparse
import base64
import json
import logging
import math
import os
import random
import re
import signal
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple

# Múi giờ Việt Nam (GMT+7)
TZ_VN = timezone(timedelta(hours=7))

from core import (
    ZaloClient,
    ZaloLoginClient,
    ThreadType,
    ReactionIcon,
    UserProfile,
    UserAPI,
    GroupAPI,
    MessageAPI,
    SessionManager,
    sign_params,
    parse_ttl_duration,
    utf16_len,
    extract_target_uid
)
from core.socket import ZaloSocketClient, DEFAULT_SERVERS

# Alias cho tương thích ngược
ZaloUserInfoAPI = UserAPI

logging.basicConfig(level=logging.INFO, format='[%(asctime)s][%(levelname)s] %(message)s')
logger = logging.getLogger("ZaloMain")


def load_session(session_path: str = "/root/zalo/fresh_session.json") -> dict:
    """Nạp thông tin phiên đăng nhập từ file JSON hoặc fallback từ zaloprefs."""
    if os.path.isfile(session_path):
        try:
            data = SessionManager.load(session_path)
            uid = data.get('uid')
            dk = SessionManager.extract_dk(data)
            cryptkey = SessionManager.extract_cryptkey(data)
            session_key = data.get('session_key')
            ksid = data.get('ksid')
            if uid and dk:
                return {
                    "uid": int(uid),
                    "dk": dk,
                    "session_key": session_key,
                    "ksid": ksid,
                    "cryptkey": cryptkey,
                    "socketServers": data.get('socketServers') or data.get('servers') or [],
                    "source": session_path
                }
        except Exception as e:
            logger.warning(f"Lỗi đọc {session_path}: {e}")

    # Fallback zaloprefs SQLite
    zaloprefs_path = "/root/zalo/zaloprefs"
    if os.path.isfile(zaloprefs_path):
        try:
            db = sqlite3.connect(zaloprefs_path)
            cur = db.cursor()
            rows = cur.execute("SELECT key, value FROM prefs_v2").fetchall()
            db.close()
            current_uid = None
            dk_val = None
            crypt_val = None
            for k, v in rows:
                if k == 'currentUserUid':
                    current_uid = int(str(v).strip())
                elif 'KEY_SET_VALUE' in k and not dk_val:
                    dk_val = str(v).strip()
                elif 'CryptKey' in k and not crypt_val:
                    crypt_val = str(v).strip()

            if current_uid and dk_val:
                return {
                    "uid": current_uid,
                    "dk": base64.b64decode(dk_val),
                    "cryptkey": base64.b64decode(crypt_val) if crypt_val else None,
                    "socketServers": [],
                    "source": zaloprefs_path
                }
        except Exception as ex:
            logger.warning(f"Lỗi đọc {zaloprefs_path}: {ex}")

    raise FileNotFoundError("Không tìm thấy thông tin phiên hợp lệ trong fresh_session.json hoặc zaloprefs.")


def load_contacts(contacts_path: str = "/root/zalo/contacts.json") -> Dict[int, str]:
    contact_map = {}
    if os.path.isfile(contacts_path):
        try:
            with open(contacts_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                items = data.get('data', []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                for item in items:
                    if isinstance(item, dict) and 'uid' in item:
                        contact_map[int(item['uid'])] = item.get('phone') or item.get('name') or str(item['uid'])
        except Exception:
            pass
    return contact_map


CONTACTS = load_contacts()


def get_name(uid: int, fallback: str = None) -> str:
    if fallback and fallback.strip() and fallback.lower() != 'null':
        return fallback
    if uid in CONTACTS:
        return f"{CONTACTS[uid]} ({uid})"
    return str(uid)


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

    clean_str = re.sub(r'^@[^\s/]+\s*', '', clean_str).strip()
    return (clean_str, is_bot_mentioned, all_uids)


def build_quote_object(
    msg_id: int,
    cli_msg_id: int,
    owner_uid: int,
    owner_name: str,
    msg_text: str,
    group_id: Optional[int] = None,
    msg_type: int = 1,
    ts: Optional[int] = None,
    attach: str = "",
    ttl: int = 0
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
        "ttl": int(ttl or 0)
    }


def build_quote_from_event(ev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Tự động chuyển đổi sự kiện tin nhắn đến thành Quote Object."""
    if not ev:
        return None
    from_u = ev.get('from_uid') or 0
    raw = ev.get('raw', {}) or {}
    from_name = raw.get('fromD') or ev.get('from_name') or CONTACTS.get(from_u) or str(from_u)

    msg_id = ev.get('msg_id') or 0
    cmi = ev.get('cli_msg_id') or 0
    msg_txt = ev.get('content') or ev.get('text') or ''
    gid = ev.get('to_group') or ev.get('to_id') if ev.get('is_group') else None
    ts = ev.get('ts') or int(time.time() * 1000)
    q_ttl = int(ev.get('ttl') or (ev.get('raw') or {}).get('ttl') or 0)
    attach_str = ""

    if isinstance(raw.get('attach'), (dict, list)):
        try:
            attach_str = json.dumps(raw['attach'], separators=(',', ':'))
        except Exception:
            attach_str = ""
    elif isinstance(raw.get('attach'), str):
        attach_str = raw['attach']

    if not attach_str and raw.get('mentions'):
        m_list = raw.get('mentions')
        if isinstance(m_list, list) and len(m_list) > 0:
            attach_str = build_mention_attach(m_list)

    ttype = ev.get('msg_type') or ev.get('type') or 'webchat'
    type_code = 1
    if ttype == 'chat.photo':
        type_code = 2
        if not msg_txt:
            msg_txt = "[Hình ảnh]"
    elif ttype == 'chat.sticker':
        type_code = 6
        if not msg_txt:
            msg_txt = "[Sticker]"
    elif ttype == 'chat.voice':
        type_code = 4
        if not msg_txt:
            msg_txt = "[Tin nhắn thoại]"
    elif ttype == 'chat.video':
        type_code = 3
        if not msg_txt:
            msg_txt = "[Video]"
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
        attach=attach_str,
        ttl=q_ttl
    )


def format_message_data(target_data: Dict[str, Any], is_quote: bool = True) -> str:
    """Format toan bo du lieu (100%) cua tin nhan / quote khong emoji, khong description."""
    if not target_data or not isinstance(target_data, dict):
        return "[DATA] Khong co du lieu."

    header = "[DATA QUOTE]" if is_quote else "[DATA MESSAGE]"
    lines = [header]

    msg_id = target_data.get('globalMsgId') or target_data.get('msg_id') or target_data.get('id') or target_data.get('gmi') or 0
    cli_id = target_data.get('cliMsgId') or target_data.get('cli_msg_id') or target_data.get('cmi') or 0
    from_u = target_data.get('ownerId') or target_data.get('owner_uid') or target_data.get('from_uid') or target_data.get('fromU') or target_data.get('uid') or 0
    from_d = target_data.get('fromD') or target_data.get('from_name') or target_data.get('from_display') or target_data.get('displayName') or ""
    group_id = target_data.get('gOwnerId') or target_data.get('to_group') or target_data.get('groupId') or target_data.get('to_id') or None
    msg_type = target_data.get('cliMsgType') or target_data.get('msg_type') or target_data.get('msgType') or target_data.get('type') or 1
    content = target_data.get('msg') if 'msg' in target_data else (target_data.get('content') or target_data.get('text') or '')
    ts_val = target_data.get('ts') or target_data.get('timestamp') or 0
    ttl_val = target_data.get('ttl') or 0
    attach_val = target_data.get('attach')
    mentions_val = target_data.get('mentions')

    ts_str = str(ts_val)
    if ts_val and isinstance(ts_val, (int, float)) and ts_val > 1000000000:
        try:
            ts_sec = ts_val / 1000.0 if ts_val > 10000000000 else float(ts_val)
            dt = datetime.fromtimestamp(ts_sec, tz=TZ_VN)
            ts_str = f"{ts_val} ({dt.strftime('%Y-%m-%d %H:%M:%S')})"
        except Exception:
            pass

    type_names = {1: "text", 2: "photo", 3: "video", 4: "voice", 6: "sticker", 7: "link", 11: "location", 24: "file"}
    if isinstance(msg_type, int) and msg_type in type_names:
        type_str = f"{msg_type} ({type_names[msg_type]})"
    else:
        type_str = str(msg_type)

    if msg_id: lines.append(f"id: {msg_id}")
    if cli_id: lines.append(f"cli_msg_id: {cli_id}")
    if from_u: lines.append(f"from_uid: {from_u}")
    if from_d: lines.append(f"from_name: {from_d}")
    if group_id: lines.append(f"group_id: {group_id}")
    lines.append(f"type: {type_str}")
    lines.append(f"ts: {ts_str}")
    lines.append(f"ttl: {ttl_val}")
    lines.append(f"msg: {content}")

    if attach_val:
        if isinstance(attach_val, (dict, list)):
            lines.append(f"attach: {json.dumps(attach_val, ensure_ascii=False, separators=(',', ':'))}")
        else:
            lines.append(f"attach: {attach_val}")

    if mentions_val:
        if isinstance(mentions_val, (dict, list)):
            lines.append(f"mentions: {json.dumps(mentions_val, ensure_ascii=False, separators=(',', ':'))}")
        else:
            lines.append(f"mentions: {mentions_val}")

    try:
        raw_str = json.dumps(target_data, ensure_ascii=False, default=str, separators=(',', ':'))
        lines.append(f"raw: {raw_str}")
    except Exception:
        lines.append(f"raw: {str(target_data)}")

    return "\n".join(lines)


COLOR_NAMES = {
    "red": "db342e", "do": "db342e", "đỏ": "db342e",
    "green": "15a85f", "xanhla": "15a85f", "xanh_la": "15a85f",
    "yellow": "f7b503", "vang": "f7b503", "vàng": "f7b503",
    "orange": "f27806", "cam": "f27806",
    "blue": "0068ff", "xanh": "0068ff", "xanhduong": "0068ff",
    "purple": "7b1fa2", "tim": "7b1fa2", "tím": "7b1fa2",
    "pink": "e91e63", "hong": "e91e63", "hồng": "e91e63",
    "black": "000000", "den": "000000", "đen": "000000",
    "gray": "888888", "xam": "888888", "xám": "888888"
}

ZALO_FONTS = {
    "young": 15433,
    "school": 15434,
    "pangolin": 15435,
    "fountain": 15436,
    "pixel": 13598,
    "vintage": 13600,
    "terminal": 13624,
    "florence": 13606,
    "notes": 13607,
    "elegant": 13611,
    "amatic": 13615,
    "gulaabee": 13616,
    "ahava": 13617,
    "retro": 13625,
}

ZALO_FONT_NAMES = {v: k for k, v in ZALO_FONTS.items()}


def get_zalo_fonts_guide(prefix: str = "/") -> str:
    """Trả về danh sách các font chữ chuẩn trong Zalo."""
    lines = ["[DANH SÁCH FONT CHỮ ZALO]"]
    for name, fid in ZALO_FONTS.items():
        lines.append(f"• {name.ljust(10)}: {fid}")
    lines.append(f"\nCú pháp: {prefix}test font <tên/id> <text>")
    lines.append(f"Ví dụ: {prefix}test font retro Xin chào")
    return "\n".join(lines)


def get_test_command_guide(prefix: str = "/") -> str:
    """Trả về hướng dẫn cú pháp lệnh test style chuẩn Zalo Binary Protocol."""
    return (
        "[HƯỚNG DẪN LỆNH TEST]\n"
        f"• {prefix}test font <tên/id> <text> : Test kiểu chữ typo (vd: {prefix}test font retro Hello)\n"
        f"• {prefix}test size <50-300> <text> : Test kích thước chữ (vd: {prefix}test size 200 Big)\n"
        f"• {prefix}test color <hex> <text> : Test màu chữ (vd: {prefix}test color db342e Red)\n"
        f"• {prefix}test bold <text> : Test chữ in đậm\n"
        f"• {prefix}test italic <text> : Test chữ in nghiêng\n"
        f"• {prefix}test underline <text> : Test chữ gạch chân\n"
        f"• {prefix}test strike <text> : Test chữ gạch ngang\n"
        f"• {prefix}test fontsize <13|18> <text> : Test cỡ chữ RTF\n"
        f"• {prefix}test list <1|2> <text> : Test danh sách (1: bullet, 2: số)\n"
        f"• {prefix}test rtf <text> : Test full RTF spans"
    )


def parse_test_style_command(arg_str: str, prefix: str = "/") -> Tuple[Optional[str], Optional[Dict[str, Any]], Optional[str]]:
    """
    Phân tích cú pháp các tùy chọn style từ lệnh test theo đúng chuẩn zalo_send_v8.
    Hỗ trợ kết hợp đồng thời Font, Size, Color, Bold, Italic... (VD: .test font retro size 200 Hello)
    Trả về: (guide_or_error_msg, style_params_dict, content_text)
    """
    raw = (arg_str or "").strip()
    if not raw or raw.lower() in ("help", "h", "?", "guide", "--help", "-h"):
        return (get_test_command_guide(prefix), None, None)

    tokens = raw.split()
    if not tokens:
        return (get_test_command_guide(prefix), None, None)

    # Nếu chỉ gõ "font" hoặc "font help" / "font list"
    if tokens[0].lower().lstrip('-') in ("font", "typo", "style") and (len(tokens) == 1 or tokens[1].lower() in ("help", "list", "h", "?", "--help")):
        return (get_zalo_fonts_guide(prefix), None, None)

    params: Dict[str, Any] = {}
    i = 0
    font_name_used = None

    while i < len(tokens):
        tok = tokens[i].lower().lstrip('-')

        # 1. Font / Typo
        if tok in ("font", "typo", "style") and "style_id" not in params:
            if i + 1 < len(tokens):
                f_tok = tokens[i + 1].lower()
                if f_tok in ZALO_FONTS:
                    params["style_id"] = ZALO_FONTS[f_tok]
                    font_name_used = f_tok
                    i += 2
                    continue
                elif f_tok.isdigit():
                    style_id = int(f_tok)
                    params["style_id"] = style_id
                    font_name_used = ZALO_FONT_NAMES.get(style_id, str(style_id))
                    i += 2
                    continue
                elif i > 0:
                    break
                else:
                    return (f"Font '{tokens[i + 1]}' không hợp lệ.\n\n" + get_zalo_fonts_guide(prefix), None, None)
            elif i > 0:
                break
            else:
                return (get_zalo_fonts_guide(prefix), None, None)

        # 2. Size
        elif tok in ("size", "co", "cỡ") and "size" not in params:
            if i + 1 < len(tokens) and (tokens[i + 1].isdigit() or (tokens[i + 1].startswith('-') and tokens[i + 1][1:].isdigit())):
                params["size"] = int(tokens[i + 1])
                i += 2
                continue
            elif i > 0:
                break
            else:
                if i + 1 < len(tokens):
                    return (f"Lỗi: Kích thước size phải là số nguyên (Ví dụ: {prefix}test size 200 Big)", None, None)
                return (f"Cú pháp: {prefix}test size <50-300> <text> (Ví dụ: {prefix}test size 200 Big)", None, None)

        # 3. Color
        elif tok in ("color", "mau", "màu", "colour") and "color" not in params:
            if i + 1 < len(tokens):
                c_tok = tokens[i + 1].lower().lstrip('#')
                col_hex = COLOR_NAMES.get(c_tok, c_tok)
                if re.match(r'^[0-9a-fA-F]{3,8}$', col_hex):
                    params["color"] = col_hex
                    i += 2
                    continue
                elif i > 0:
                    break
                else:
                    return (f"Lỗi: Mã màu hex không hợp lệ (Ví dụ: {prefix}test color db342e hoặc {prefix}test color red)", None, None)
            elif i > 0:
                break
            else:
                return (f"Cú pháp: {prefix}test color <hex> <text> (Ví dụ: {prefix}test color db342e Red)", None, None)

        # 4. Bold
        elif tok in ("bold", "b", "dam", "đậm") and "bold" not in params:
            params["bold"] = True
            i += 1
            continue

        # 5. Italic
        elif tok in ("italic", "i", "nghieng", "nghiêng") and "italic" not in params:
            params["italic"] = True
            i += 1
            continue

        # 6. Underline
        elif tok in ("underline", "u", "gachchan", "gạchchân") and "underline" not in params:
            params["underline"] = True
            i += 1
            continue

        # 7. Strike
        elif tok in ("strike", "s", "gachngang", "gạchngang") and "strike" not in params:
            params["strike"] = True
            i += 1
            continue

        # 8. Fontsize
        elif tok in ("fontsize", "f", "size_rtf") and "fontsize" not in params:
            if i + 1 < len(tokens) and tokens[i + 1].isdigit():
                params["fontsize"] = int(tokens[i + 1])
                i += 2
                continue
            elif i > 0:
                break
            else:
                if i + 1 < len(tokens):
                    return (f"Lỗi: Cỡ chữ RTF phải là số nguyên (13=nhỏ, 18=to)", None, None)
                return (f"Cú pháp: {prefix}test fontsize <13|18> <text> (Ví dụ: {prefix}test fontsize 18 Hello)", None, None)

        # 9. List
        elif tok in ("list", "lst", "danhsach") and "list_type" not in params:
            if i + 1 < len(tokens) and tokens[i + 1] in ("1", "2"):
                params["list_type"] = int(tokens[i + 1])
                i += 2
                continue
            elif i > 0:
                break
            else:
                if i + 1 < len(tokens):
                    return (f"Lỗi: Loại list phải là 1 (bullet) hoặc 2 (số)", None, None)
                return (f"Cú pháp: {prefix}test list <1|2> <text> (1: bullet, 2: số)", None, None)

        # 10. RTF Full
        elif tok in ("rtf", "rich", "full") and i == 0:
            params["bold"] = True
            params["italic"] = True
            params["color"] = "db342e"
            params["fontsize"] = 18
            i += 1
            continue

        else:
            # Gặp từ không phải style keyword -> toàn bộ phần còn lại là text content
            break

    if not params:
        return (get_test_command_guide(prefix), None, None)

    remaining_words = tokens[i:]
    if remaining_words:
        text_content = " ".join(remaining_words).strip()
    else:
        parts = []
        if "style_id" in params:
            parts.append(f"Font {(font_name_used or str(params['style_id'])).title()}")
        if "size" in params:
            parts.append(f"Size {params['size']}")
        if "color" in params:
            parts.append(f"Color #{params['color']}")
        if params.get("bold"):
            parts.append("Bold")
        if params.get("italic"):
            parts.append("Italic")
        if params.get("underline"):
            parts.append("Underline")
        if params.get("strike"):
            parts.append("Strike")
        text_content = f"Test {' + '.join(parts)}" if parts else "Test Styled Message"

    return (None, params, text_content)


KEYWORD_RESPONSES = {
    "chào": "Chào bạn! Tôi là Zalo Socket Bot.",
    "hi": "Chào bạn!",
    "hello": "Hello! Rất vui được trò chuyện cùng bạn.",
    "ping": "Pong!",
    "test": "Hệ thống hoạt động bình thường! [OK]",
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
    bot_uid: Optional[int] = None,
    mentioned_uids: Optional[List[int]] = None,
    quote_owner_id: Optional[int] = None,
    quote_data: Optional[Dict[str, Any]] = None,
    raw_event: Optional[Dict[str, Any]] = None,
    user_info_api: Optional[UserAPI] = None,
    group_api: Optional[GroupAPI] = None,
    start_time: Optional[float] = None,
    msg_count: int = 0
) -> Optional[str]:
    """
    Sinh nội dung phản hồi cho Auto-Reply Bot dựa trên tiền tố lệnh (prefix),
    danh sách từ khóa (keywords), hoặc chế độ trả lời toàn bộ.
    """
    msg_txt = (msg_txt or "").strip()
    if not msg_txt:
        return None

    # 1. Xử lý lệnh theo Prefix (ví dụ: '/' hoặc '.')
    if prefix and msg_txt.startswith(prefix):
        cmd_part = msg_txt[len(prefix):].strip()
        if not cmd_part:
            return None

        parts = cmd_part.split(' ', 1)
        cmd_name = parts[0].lower().strip()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if not cmd_name or cmd_name.startswith('@'):
            return None

        # -------------------------------------------------------------------
        # [NHÓM 1]: Hệ thống, Kết nối & Menu trợ giúp
        # -------------------------------------------------------------------
        if cmd_name in ("help", "menu", "h"):
            return (
                "[DANH SÁCH LỆNH BOT]\n"
                f"• {prefix}ping : Kiểm tra trạng thái bot\n"
                f"• {prefix}test [loại] [text] : Thử nghiệm font / size / style text\n"
                f"• {prefix}data : Trích xuất 100% metadata tin nhắn quote\n"
                f"• {prefix}grid <link/code> : Lấy ID nhóm qua liên kết\n"
                f"• {prefix}uid [@tag/uid] : Tra cứu UID cá nhân / nhóm / target\n"
                f"• {prefix}profile [@tag/uid] : Tra cứu thông tin chi tiết người dùng\n"
                f"• {prefix}avatar [@tag/uid] : Lấy ảnh đại diện HD\n"
                f"• {prefix}img [thumb] <url> [caption] : Gửi hình ảnh tới cuộc trò chuyện\n"
                f"• {prefix}vid [thumb] <url> [caption] : Gửi video tới cuộc trò chuyện\n"
                f"• {prefix}doodle [thumb] <url> [caption] : Gửi hình vẽ (doodle)\n"
                f"• {prefix}time : Xem ngày giờ hệ thống chuẩn VN\n"
                f"• {prefix}uptime : Thống kê thời gian hoạt động\n"
                f"• {prefix}botinfo : Xem thông tin kỹ thuật bot\n"
                f"• {prefix}calc <math> : Tính toán biểu thức toán học\n"
                f"• {prefix}echo <text> : Lặp lại nội dung tin nhắn\n"
                f"• {prefix}react <icon/text> : Thả cảm xúc tin nhắn\n"
                f"• {prefix}pin <nội dung> : Ghim tin nhắn / Topic nhóm\n"
                f"• {prefix}unpin : Bỏ ghim tin nhắn nhóm\n"
                f"• {prefix}kick [@tag/uid] : Xóa thành viên khỏi nhóm\n"
                f"• {prefix}ban [@tag/uid] : Chặn thành viên khỏi nhóm\n"
                f"• {prefix}block [@tag/uid] : Chặn người dùng 1-1\n"
                f"• {prefix}leave : Rời khỏi nhóm\n"
                f"• {prefix}poll <hỏi> | <opt1> | <opt2> : Tạo bình chọn\n"
                f"• {prefix}recall (quote msg) : Thu hồi tin nhắn cho tất cả mọi người\n"
                f"• {prefix}delete (quote msg) : Xóa tin nhắn ở phía mình\n"
                f"• {prefix}join <link/uid> : Tham gia nhóm\n"
                f"• {prefix}disband : Giải tán nhóm\n"
                f"• {prefix}setttl <thời gian> : Cài đặt tin nhắn tự xóa\n"
                f"• {prefix}ttl : Xem thông tin TTL"
            )

        elif cmd_name in ("test", "style", "styling"):
            guide_or_err, style_params, text_content = parse_test_style_command(arg, prefix=prefix)
            if guide_or_err:
                return guide_or_err
            return f"__ACTION_SEND_STYLE:{json.dumps(style_params)}__ {text_content}"

        elif cmd_name in ("data", "raw", "msgdata", "dump"):
            if quote_data and isinstance(quote_data, dict):
                return format_message_data(quote_data, is_quote=True)
            elif raw_event and isinstance(raw_event, dict):
                return format_message_data(raw_event, is_quote=False)
            else:
                return "[DATA] Khong tim thay thong tin tin nhan."

        elif cmd_name in ("ginfo", "groupinfo", "preview", "xemnhom"):
            if not arg:
                return f"Cú pháp: {prefix}preview <link_nhóm/code>\nVí dụ: {prefix}preview https://zalo.me/g/uilfynmhm09irmodtwrq"
            g_inst = group_api or GroupAPI()
            try:
                p_res = g_inst.preview_group_link(arg)
                return p_res.get('formatted_preview') or f"Không thể lấy thông tin nhóm từ link: {arg}"
            except Exception as e:
                return f"Lỗi tra cứu thông tin nhóm: {e}"

        elif cmd_name in ("grid", "groupid", "gid"):
            if not arg:
                return f"Cú pháp: {prefix}grid <link_nhóm/link_code>\nVí dụ: {prefix}grid https://zalo.me/g/krgx195dxdbjx1bm2fbd"
            g_inst = group_api or GroupAPI()
            try:
                # preview_group_link trả về đầy đủ: group_id, name, owner, creation date, members, join button
                p_res = g_inst.preview_group_link(arg)
                if p_res and (p_res.get('group_id') or p_res.get('name')):
                    return p_res.get('formatted_preview') or (
                        f"[THÔNG TIN NHÓM]\n"
                        f"• Group ID: {p_res.get('group_id', 'Không xác định')}\n"
                        f"• Tên: {p_res.get('name', '?')}\n"
                        f"• Link: {p_res.get('link_url', arg)}\n"
                        f"👉 Thao tác: [THAM GIA]"
                    )
                # Fallback: chỉ resolve group_id
                t_type, gid, code = GroupAPI.parse_group_target(arg)
                link_code = code or arg.strip()
                if gid:
                    return f"[GROUP ID]\n• Target: {arg}\n• Group ID: {gid}"
                resolved_gid = g_inst.resolve_group_id_from_link(link_code)
                if resolved_gid:
                    return f"[GROUP ID]\n• Link: {arg}\n• Mã liên kết: {link_code}\n• Group ID: {resolved_gid}"
                return f"[GROUP ID]\n• Link: {arg}\n• Mã liên kết: {link_code}\n• Trạng thái: Không thể phân giải Group ID từ liên kết này (link có thể đã hết hạn hoặc không tồn tại)."
            except Exception as e:
                return f"Lỗi tra cứu thông tin nhóm: {e}"

        elif cmd_name in ("ping", "p"):
            return "Pong! Bot Socket trực tuyến."

        elif cmd_name in ("uptime", "stats", "status"):
            now_t = time.time()
            up_s = int(now_t - (start_time or now_t))
            days, rem = divmod(up_s, 86400)
            hours, rem = divmod(rem, 3600)
            mins, secs = divmod(rem, 60)
            up_parts = []
            if days > 0: up_parts.append(f"{days} ngày")
            if hours > 0: up_parts.append(f"{hours} giờ")
            if mins > 0: up_parts.append(f"{mins} phút")
            up_parts.append(f"{secs} giây")
            uptime_str = " ".join(up_parts)
            return (
                "[THỐNG KÊ HOẠT ĐỘNG BOT]\n"
                f"• Uptime: {uptime_str}\n"
                f"• Đã xử lý: {msg_count} tin nhắn\n"
                "• Kết nối: TCP TLS Binary Socket (AES-GCM / E2EE)"
            )

        elif cmd_name in ("time", "date", "gio", "ngay"):
            now = datetime.now(TZ_VN)
            weekdays = ["Thứ Hai", "Thứ Ba", "Thứ Tư", "Thứ Năm", "Thứ Sáu", "Thứ Bảy", "Chủ Nhật"]
            w_str = weekdays[now.weekday()]
            return f"Thời gian hệ thống: {now.strftime('%H:%M:%S')} | {w_str}, {now.strftime('%d/%m/%Y')} (GMT+7)"

        elif cmd_name in ("botinfo", "about"):
            return (
                "[ZALO REALTIME SOCKET BOT]\n"
                f"• Bot UID: {bot_uid or '463450795'}\n"
                "• Kiến trúc: Core SDK v2.0 (Zero-Thirdparty)\n"
                "• Giao thức: Zalo Binary Protocol v3 (D3 Stream)\n"
                "• Bảo mật: AES-GCM + E2EE AES-128-CBC"
            )

        # -------------------------------------------------------------------
        # [NHÓM 2]: Người dùng & Hồ sơ
        # -------------------------------------------------------------------
        elif cmd_name in ("uid", "id", "me"):
            lines = [f"UID: {from_uid}" if from_uid else "UID: không xác định"]
            target_uid = extract_target_uid(arg, mentioned_uids=mentioned_uids, quote_owner_id=quote_owner_id, bot_uid=bot_uid)
            if target_uid and target_uid != from_uid and target_uid != bot_uid:
                lines.append(f"Target UID: {target_uid}")
            if group_id:
                lines.append(f"Group UID: {group_id}")
            if bot_uid:
                lines.append(f"Bot UID: {bot_uid}")
            return "\n".join(lines)

        elif cmd_name in ("profile", "info", "user"):
            target_uid = extract_target_uid(arg, mentioned_uids=mentioned_uids, quote_owner_id=quote_owner_id, bot_uid=bot_uid)
            if not target_uid and from_uid and not arg:
                target_uid = from_uid

            if target_uid:
                api = user_info_api or UserAPI()
                if hasattr(api, 'get_user_profile'):
                    info = api.get_user_profile(target_uid)
                elif hasattr(api, 'get_user_info'):
                    info = api.get_user_info(target_uid)
                else:
                    info = None
                if info:
                    if hasattr(api, 'format_user_info'):
                        return api.format_user_info(info)
                    return UserAPI.format_user_info(info)
                return f"Không tìm thấy thông tin cho UID: {target_uid}"
            return (
                f"[HƯỚNG DẪN LỆNH {prefix}profile]\n"
                f"• {prefix}profile <uid>: Xem thông tin người dùng theo UID\n"
                f"• {prefix}profile @tag: Xem thông tin người được tag\n"
                f"• Quote tin nhắn + {prefix}profile: Xem thông tin người gửi"
            )

        elif cmd_name in ("avatar", "ava"):
            target_uid = extract_target_uid(arg, mentioned_uids=mentioned_uids, quote_owner_id=quote_owner_id, bot_uid=bot_uid) or from_uid
            if target_uid:
                api = user_info_api or UserAPI()
                info = None
                if hasattr(api, 'get_user_profile'):
                    info = api.get_user_profile(target_uid)
                elif hasattr(api, 'get_user_info'):
                    info = api.get_user_info(target_uid)
                
                ava_url = None
                name_str = f"UID {target_uid}"
                if info:
                    if hasattr(info, 'avatar') and info.avatar:
                        ava_url = info.avatar
                        name_str = getattr(info, 'display_name', name_str)
                    elif isinstance(info, dict) and info.get('avatar'):
                        ava_url = info['avatar']
                        name_str = info.get('displayName') or name_str

                if ava_url:
                    from core.utils.helpers import get_high_res_avatar
                    high_ava = get_high_res_avatar(ava_url)
                    return f"[AVATAR ZALO - {name_str}]\n• Kích thước: Chuẩn HD (s600)\n• Liên kết: {high_ava}"
                return f"[!] Chưa có ảnh đại diện được lưu cho {name_str}. Người dùng có thể đang để avatar mặc định."
            return f"Cú pháp: {prefix}avatar @tag hoặc {prefix}avatar <uid>"

        elif cmd_name in ("img", "photo", "image", "anh"):
            target_url = ""
            thumb_url = ""
            caption = ""
            raw_arg = arg.strip()
            if not raw_arg:
                # Kiểm tra nếu đang quote tin nhắn có hình ảnh
                if quote_data and isinstance(quote_data, dict):
                    att = quote_data.get('attach')
                    if isinstance(att, str) and att.startswith('{'):
                        try: att = json.loads(att)
                        except Exception: pass
                    if isinstance(att, dict):
                        target_url = att.get('href') or att.get('hdUrl') or att.get('url') or ""
                        thumb_url = att.get('thumb') or ""
                if not target_url:
                    return (
                        f"[HƯỚNG DẪN LỆNH {prefix}{cmd_name}]\n"
                        f"• Cú pháp: {prefix}{cmd_name} <link_ảnh> [caption]\n"
                        f"• Hoặc: {prefix}{cmd_name} <link_thumb> <link_ảnh> [caption]\n"
                        f"Ví dụ: {prefix}{cmd_name} https://picsum.photos/600/400 Ảnh demo\n"
                        f"• Hoặc Quote tin nhắn ảnh + gõ {prefix}{cmd_name}"
                    )
            else:
                tokens = raw_arg.split()
                if len(tokens) >= 2 and (tokens[0].startswith('http://') or tokens[0].startswith('https://')) and (tokens[1].startswith('http://') or tokens[1].startswith('https://')):
                    thumb_url = tokens[0]
                    target_url = tokens[1]
                    caption = " ".join(tokens[2:]) if len(tokens) > 2 else ""
                else:
                    parts = raw_arg.split(' ', 1)
                    target_url = parts[0].strip()
                    thumb_url = ""
                    caption = parts[1].strip() if len(parts) > 1 else ""

            action_data = json.dumps({
                "url": target_url,
                "thumb_url": thumb_url,
                "caption": caption
            }, ensure_ascii=False)
            return f"__ACTION_SEND_PHOTO:{action_data}__ Đang gửi hình ảnh tới cuộc trò chuyện..."

        elif cmd_name in ("doodle", "ve", "draw"):
            target_url = ""
            thumb_url = ""
            caption = ""
            raw_arg = arg.strip()
            if not raw_arg:
                if quote_data and isinstance(quote_data, dict):
                    att = quote_data.get('attach')
                    if isinstance(att, str) and att.startswith('{'):
                        try: att = json.loads(att)
                        except Exception: pass
                    if isinstance(att, dict):
                        target_url = att.get('href') or att.get('hdUrl') or att.get('url') or ""
                        thumb_url = att.get('thumb') or ""
                if not target_url:
                    return (
                        f"[HƯỚNG DẪN LỆNH {prefix}{cmd_name}]\n"
                        f"• Cú pháp: {prefix}{cmd_name} <link_doodle> [caption]\n"
                        f"• Hoặc: {prefix}{cmd_name} <link_thumb> <link_doodle> [caption]\n"
                        f"Ví dụ: {prefix}{cmd_name} https://example.com/doodle.png Hình vẽ demo"
                    )
            else:
                tokens = raw_arg.split()
                if len(tokens) >= 2 and (tokens[0].startswith('http://') or tokens[0].startswith('https://')) and (tokens[1].startswith('http://') or tokens[1].startswith('https://')):
                    thumb_url = tokens[0]
                    target_url = tokens[1]
                    caption = " ".join(tokens[2:]) if len(tokens) > 2 else ""
                else:
                    parts = raw_arg.split(' ', 1)
                    target_url = parts[0].strip()
                    thumb_url = ""
                    caption = parts[1].strip() if len(parts) > 1 else ""

            action_data = json.dumps({
                "url": target_url,
                "thumb_url": thumb_url,
                "caption": caption
            }, ensure_ascii=False)
            return f"__ACTION_SEND_DOODLE:{action_data}__ Đang gửi hình vẽ (doodle) tới cuộc trò chuyện..."

        elif cmd_name in ("video", "vid", "clip"):
            video_url = ""
            thumb_url = ""
            caption = ""
            raw_arg = arg.strip()
            if not raw_arg:
                if quote_data and isinstance(quote_data, dict):
                    att = quote_data.get('attach')
                    if isinstance(att, str) and att.startswith('{'):
                        try: att = json.loads(att)
                        except Exception: pass
                    if isinstance(att, dict):
                        video_url = att.get('href') or att.get('hdUrl') or att.get('url') or ""
                        thumb_url = att.get('thumb') or att.get('thumbUrl') or ""
                if not video_url:
                    return (
                        f"[HƯỚNG DẪN LỆNH {prefix}{cmd_name}]\n"
                        f"• Cú pháp: {prefix}{cmd_name} <url_thumb> <url_video> [caption]\n"
                        f"• Hoặc: {prefix}{cmd_name} <url_video> [caption]\n"
                        f"Ví dụ: {prefix}{cmd_name} https://example.com/thumb.jpg https://example.com/video.mp4 Video demo\n"
                        f"• Hoặc Quote tin nhắn video + gõ {prefix}{cmd_name}"
                    )
            else:
                tokens = raw_arg.split()
                if len(tokens) >= 2 and (tokens[0].startswith('http://') or tokens[0].startswith('https://')) and (tokens[1].startswith('http://') or tokens[1].startswith('https://')):
                    thumb_url = tokens[0]
                    video_url = tokens[1]
                    caption = " ".join(tokens[2:]) if len(tokens) > 2 else ""
                else:
                    parts = raw_arg.split(' ', 1)
                    video_url = parts[0].strip()
                    thumb_url = ""
                    caption = parts[1].strip() if len(parts) > 1 else ""

            action_data = json.dumps({
                "url": video_url,
                "thumb_url": thumb_url,
                "caption": caption
            }, ensure_ascii=False)
            return f"__ACTION_SEND_VIDEO:{action_data}__ Đang gửi video tới cuộc trò chuyện..."

        elif cmd_name in ("block", "chan"):
            target_uid = extract_target_uid(arg, mentioned_uids=mentioned_uids, quote_owner_id=quote_owner_id, bot_uid=bot_uid)
            if target_uid:
                if bot_uid and int(target_uid) == int(bot_uid):
                    return "[!] Không thể tự chặn chính bot."
                action_data = json.dumps({"uid": int(target_uid), "is_block": True})
                return f"__ACTION_BLOCK:{action_data}__ Đã gửi lệnh chặn người dùng {target_uid}."
            return f"Cú pháp: {prefix}block @tag hoặc {prefix}block <uid>"

        elif cmd_name in ("unblock", "bochan", "mochan"):
            target_uid = extract_target_uid(arg, mentioned_uids=mentioned_uids, quote_owner_id=quote_owner_id, bot_uid=bot_uid)
            if target_uid:
                action_data = json.dumps({"uid": int(target_uid), "is_block": False})
                return f"__ACTION_BLOCK:{action_data}__ Đã gửi lệnh bỏ chặn người dùng {target_uid}."
            return f"Cú pháp: {prefix}unblock @tag hoặc {prefix}unblock <uid>"

        # -------------------------------------------------------------------
        # [NHÓM 3]: Quản trị nhóm & Tương tác Socket
        # -------------------------------------------------------------------
        elif cmd_name in ("kick", "ban", "duoi"):
            if not group_id:
                return "[!] Lệnh kick/ban chỉ khả dụng trong nhóm chat."
            target_uid = extract_target_uid(arg, mentioned_uids=mentioned_uids, quote_owner_id=quote_owner_id, bot_uid=bot_uid)
            if target_uid:
                if bot_uid and int(target_uid) == int(bot_uid):
                    return "[!] Không thể tự kick chính bot."
                is_block = (cmd_name == "ban")
                action_data = json.dumps({"uid": int(target_uid), "is_block": is_block})
                action_name = "ban (chặn vào lại)" if is_block else "kick"
                return f"__ACTION_KICK:{action_data}__ Đã gửi lệnh {action_name} thành viên {target_uid} khỏi nhóm."
            return (
                f"[HƯỚNG DẪN LỆNH {prefix}{cmd_name}]\n"
                f"• {prefix}{cmd_name} <uid>: {cmd_name.capitalize()} thành viên theo UID\n"
                f"• {prefix}{cmd_name} @tag: {cmd_name.capitalize()} thành viên được tag\n"
                f"• Quote tin nhắn + {prefix}{cmd_name}: {cmd_name.capitalize()} người gửi tin nhắn\n"
                f"• {prefix}ban @tag/uid: Kick và chặn không cho vào lại nhóm"
            )

        elif cmd_name in ("leave", "out", "roi", "thoat"):
            target_gid = None
            if arg and arg.strip().isdigit():
                target_gid = int(arg.strip())
            elif group_id:
                target_gid = int(group_id)
            if not target_gid:
                return f"[!] Vui lòng chỉ định Group ID cần rời: {prefix}{cmd_name} <group_id> hoặc dùng trong nhóm chat."
            return f"__ACTION_LEAVE:{target_gid}__ Đang tiến hành rời khỏi nhóm ID: {target_gid}..."

        elif cmd_name in ("poll", "binhchon", "vote"):
            if not group_id:
                return "[!] Lệnh tạo bình chọn chỉ khả dụng trong nhóm chat."
            if not arg or ('|' not in arg and ',' not in arg):
                return (
                    f"[HƯỚNG DẪN LỆNH {prefix}poll]\n"
                    f"• {prefix}poll <Câu hỏi> | <Lựa chọn 1> | <Lựa chọn 2> | ...\n"
                    f"Ví dụ: {prefix}poll Trưa nay ăn gì? | Cơm tấm | Bún bò | Phở"
                )
            parts = [p.strip() for p in (arg.split('|') if '|' in arg else arg.split(',')) if p.strip()]
            if len(parts) < 3:
                return "[!] Vui lòng nhập 1 câu hỏi và ít nhất 2 lựa chọn (phân cách bằng dấu |)"
            q = parts[0]
            opts = parts[1:]
            action_data = json.dumps({"question": q, "options": opts}, ensure_ascii=False)
            return f"__ACTION_POLL:{action_data}__ Đã tạo cuộc bình chọn: {q}"

        elif cmd_name in ("recall", "thuhoi", "revoke"):
            c_msg = 0
            g_msg = 0
            if quote_data and isinstance(quote_data, dict):
                c_msg = quote_data.get('cliMsgId') or quote_data.get('cmi') or 0
                g_msg = quote_data.get('globalMsgId') or quote_data.get('gmi') or 0
            elif arg.isdigit():
                c_msg = int(arg)
            if not c_msg and not g_msg:
                return f"[!] Quote tin nhắn cần thu hồi hoặc nhập CLI Msg ID: {prefix}{cmd_name} <cmsg_id>"
            action_data = json.dumps({
                "cli_msg_id": c_msg,
                "global_msg_id": g_msg,
                "owner_id": quote_owner_id or 0
            })
            return f"__ACTION_RECALL:{action_data}__ Đã gửi yêu cầu thu hồi tin nhắn cho tất cả mọi người."

        elif cmd_name in ("del", "delete", "xoa"):
            tokens_lower = arg.lower().split()
            only_me_keywords = {"onlyme", "only_me", "me", "self", "canhan", "ca_nhan", "chotoi", "cho_toi", "phiaminh", "phia_minh"}
            is_only_me = any(t in only_me_keywords for t in tokens_lower)
            
            c_msg = 0
            g_msg = 0
            if quote_data and isinstance(quote_data, dict):
                c_msg = quote_data.get('cliMsgId') or quote_data.get('cmi') or 0
                g_msg = quote_data.get('globalMsgId') or quote_data.get('gmi') or 0
            else:
                for tok in tokens_lower:
                    if tok.isdigit():
                        c_msg = int(tok)
                        break
            
            if not c_msg and not g_msg:
                return f"[!] Quote tin nhắn cần xóa hoặc nhập CLI Msg ID: {prefix}{cmd_name} [onlyme] <cmsg_id>"
            
            action_data = json.dumps({
                "cli_msg_id": c_msg,
                "global_msg_id": g_msg,
                "owner_id": quote_owner_id or 0,
                "only_me": is_only_me
            })
            if is_only_me:
                return f"__ACTION_DELETE:{action_data}__ Đã xóa tin nhắn khỏi cuộc trò chuyện của bạn."
            else:
                return f"__ACTION_DELETE:{action_data}__ Đã xóa tin nhắn trong cuộc trò chuyện."

        elif cmd_name in ("react", "reaction", "tim", "like", "haha", "wow", "cry", "angry", "dislike", "broken", "tha"):
            icon = arg or ("❤️" if cmd_name in ("react", "reaction", "tim", "tha") else ("👍" if cmd_name == "like" else ("😂" if cmd_name == "haha" else ("😮" if cmd_name == "wow" else ("😭" if cmd_name == "cry" else ("😡" if cmd_name == "angry" else ("👎" if cmd_name == "dislike" else ("💔" if cmd_name == "broken" else "❤️"))))))))
            r_type, r_icon, display_str = ReactionIcon.resolve(icon)
            if r_type == -1:
                return f"__ACTION_REACT:{r_icon}__ Đã gỡ cảm xúc khỏi tin nhắn!"
            return f"__ACTION_REACT:{r_icon}__ Đã thả cảm xúc {display_str} vào tin nhắn!"

        elif cmd_name in ("pin", "ghim"):
            pin_title = arg or "Thông báo ghim"
            return f"__ACTION_PIN:{pin_title}__ Đã ghim tin nhắn vào bảng tin nhóm!"

        elif cmd_name in ("unpin", "boghim", "un_pin", "goghim", "go_ghim"):
            topic_arg = arg.strip() if arg else ""
            if topic_arg.isdigit():
                return f"__ACTION_UNPIN:{topic_arg}__ Đã gửi yêu cầu bỏ ghim bài viết ID {topic_arg} trong nhóm!"
            elif quote_data and isinstance(quote_data, dict) and (quote_data.get('globalMsgId') or quote_data.get('gmi')):
                g_id = quote_data.get('globalMsgId') or quote_data.get('gmi')
                return f"__ACTION_UNPIN:{g_id}__ Đã gửi yêu cầu bỏ ghim tin nhắn #{g_id} trong nhóm!"
            return "__ACTION_UNPIN__ Đã gửi yêu cầu bỏ ghim tin nhắn trong nhóm!"

        elif cmd_name in ("pins", "pinned", "danhsachghim", "dsghim", "xemghim"):
            if not group_id:
                return "[!] Lệnh xem danh sách ghim chỉ khả dụng trong nhóm chat."
            
            g_inst = group_api or GroupAPI()
            topics = []
            try:
                res = g_inst.get_pinned_topics(group_id=group_id)
                if isinstance(res, dict):
                    topics = res.get('topics') or res.get('ack_result', {}).get('topics') or []
            except Exception as ex:
                logger.warning(f"Lỗi tra cứu tin ghim: {ex}")

            if topics:
                lines = [f"[DANH SÁCH TIN GHIM - NHÓM {group_id}]", f"Tổng số tin đã ghim: {len(topics)}\n"]
                for idx, item in enumerate(topics, 1):
                    tid = item.get('id') or item.get('topicId') or item.get('globalMsgId') or 'N/A'
                    content = item.get('content') or item.get('msg') or item.get('title') or '(Nội dung không xác định)'
                    creator = item.get('creator', {}) if isinstance(item.get('creator'), dict) else {}
                    c_name = creator.get('dpn') or creator.get('name') or 'Thành viên'
                    lines.append(f"{idx}. Topic #{tid}")
                    lines.append(f"   • Nội dung: \"{content}\"")
                    lines.append(f"   • Người ghim: {c_name}")
                lines.append(f"\n👉 Dùng: {prefix}unpin <topic_id> để gỡ ghim.")
                return "\n".join(lines)
            else:
                return (
                    f"[DANH SÁCH TIN GHIM - NHÓM {group_id}]\n"
                    f"• Bảng tin nhóm hiện tại chưa có bài viết nào được ghim.\n"
                    f"• Ghim tin nhắn mới: {prefix}pin <nội dung>\n"
                    f"• Bỏ ghim tin nhắn: Quote tin nhắn đã ghim + {prefix}unpin hoặc {prefix}unpin <topic_id>"
                )

        elif cmd_name in ("disband", "giaitan"):
            return "__ACTION_DISBAND__ Đang tiến hành giải tán nhóm..."

        elif cmd_name in ("join", "thamgia", "vaonhom"):
            if not arg:
                return (
                    f"[HƯỚNG DẪN LỆNH {prefix}join]\n"
                    f"• {prefix}join <link_nhóm>: Tham gia nhóm qua liên kết (zalo.me/g/...)\n"
                    f"• {prefix}join <group_id>: Tham gia nhóm qua ID nhóm\n"
                    f"• {prefix}join <link_nhóm> <group_id>: Tham gia nhóm qua link và ID"
                )
            t_type, gid, code = GroupAPI.parse_group_target(arg)
            target_clean = code if (t_type == "link" and code) else (gid if (t_type == "id" and gid) else arg)
            action_data = json.dumps({"type": t_type, "target": target_clean, "raw": arg})
            if t_type == "id" or (gid and not code):
                return f"__ACTION_JOIN:{action_data}__ Đang gửi yêu cầu tham gia nhóm ID: {gid or arg}..."
            return f"__ACTION_JOIN:{action_data}__ Đang gửi yêu cầu tham gia nhóm qua liên kết: {arg}..."

        elif cmd_name in ("setttl", "ttlset"):
            if not arg:
                return (
                    f"Cú pháp: {prefix}setttl <7d|1d|10s|5s|0>\n"
                    f"Ví dụ: {prefix}setttl 7d (7 ngày), {prefix}setttl 0 (tắt)"
                )
            dur = parse_ttl_duration(arg)
            dur_str = f"{dur} giây" if dur < 86400 else f"{dur // 86400} ngày ({dur}s)"
            if dur == 0:
                return "__ACTION_SET_TTL:0__ Đã tắt chế độ Tin nhắn tự xóa."
            return f"__ACTION_SET_TTL:{dur}__ Đã cài đặt Tin nhắn tự xóa: {dur_str}."

        elif cmd_name == "ttl":
            if arg:
                dur = parse_ttl_duration(arg)
                dur_str = f"{dur} giây" if dur < 86400 else f"{dur // 86400} ngày ({dur}s)"
                return f"TTL (Time-To-Live): {dur_str}. Dùng {prefix}setttl {arg} để áp dụng."
            return f"TTL (Time-To-Live) hỗ trợ: 5s, 10s, 1d (86400s), 7d (604800s), 0 (tắt). Cú pháp: {prefix}setttl <mốc>"

        # -------------------------------------------------------------------
        # [NHÓM 4]: Tiện ích
        # -------------------------------------------------------------------
        elif cmd_name in ("echo", "say"):
            return f"{arg}" if arg else f"Cú pháp: {prefix}echo <nội dung>"

        elif cmd_name in ("calc", "math"):
            if not arg:
                return f"Cú pháp: {prefix}calc <biểu thức> (Ví dụ: {prefix}calc (12 + 8) * 5)"
            try:
                cleaned = arg.replace('^', '**').replace('x', '*').replace('X', '*').replace(':', '/')
                if re.match(r'^[0-9\+\-\*\/\(\)\.\s\%\,a-zA-Z]+$', cleaned):
                    allowed_names = {
                        'sqrt': math.sqrt, 'sin': math.sin, 'cos': math.cos, 'tan': math.tan,
                        'abs': abs, 'round': round, 'pow': pow, 'ceil': math.ceil, 'floor': math.floor,
                        'pi': math.pi, 'e': math.e, 'log': math.log, 'log10': math.log10
                    }
                    res = eval(cleaned, {"__builtins__": {}}, allowed_names)
                    return f"Kết quả: {arg} = {res}"
                else:
                    return "Biểu thức không hợp lệ. Chỉ chấp nhận các số và toán tử + - * /"
            except Exception as e:
                return f"Lỗi tính toán: {e}"

        else:
            if group_id and not is_bot_mentioned:
                return None
            return f"Lệnh {prefix}{cmd_name} không tồn tại. Gõ {prefix}help để xem danh sách lệnh."

    # 2. Xử lý từ khóa lọc (nếu có cấu hình --keywords)
    if keywords_list:
        lower_txt = msg_txt.lower()
        matched = any(kw.lower() in lower_txt for kw in keywords_list)
        if not matched:
            return None

    # 3. Phản hồi theo từ khóa phổ biến trong từ điển
    if not group_id or is_bot_mentioned or prefix is None:
        lower_txt = msg_txt.lower()
        for kw, resp in KEYWORD_RESPONSES.items():
            if kw == lower_txt or re.search(r'\b' + re.escape(kw) + r'\b', lower_txt):
                return resp

    # 4. Phản hồi cố định nếu cấu hình --reply-text
    if fixed_reply:
        return fixed_reply

    # 5. Phản hồi toàn bộ nếu cấu hình --all
    if reply_all:
        if msg_txt:
            return f"[Auto-Reply] Đã nhận: '{msg_txt}'"
        elif msg_type == 'chat.photo':
            return "[Auto-Reply] Đã nhận hình ảnh của bạn!"
        elif msg_type == 'chat.sticker':
            return "[Auto-Reply] Sticker đẹp đấy!"
        elif msg_type == 'chat.voice':
            return "[Auto-Reply] Đã nhận tin nhắn thoại!"

    return None


class ZaloBotEngine:
    """Động cơ xử lý sự kiện realtime và tự động trả lời (Auto-Reply Bot)."""

    def __init__(
        self,
        client: ZaloSocketClient,
        prefix: Optional[str] = "/",
        keywords: Optional[List[str]] = None,
        reply_text: Optional[str] = None,
        reply_all: bool = False,
        no_quote: bool = False,
        ttl: int = 0,
        rate_limit_sec: float = 1.2,
        default_style: Optional[Dict[str, Any]] = None
    ):
        self.client = client
        self.prefix = prefix
        self.keywords = keywords
        self.reply_text = reply_text
        self.reply_all = reply_all
        self.no_quote = no_quote
        self.ttl = ttl
        self.rate_limit_sec = rate_limit_sec
        self.default_style = dict(default_style or {})
        self.last_reply_times: Dict[int, float] = {}
        self.rate_lock = threading.Lock()
        self.user_info_api = UserAPI()
        self.group_api = GroupAPI(socket_client=client)
        self.start_time = time.time()
        self.msg_count = 0

    def handle_message(self, parsed_frame: Dict[str, Any]):
        """Xử lý sự kiện tin nhắn nhận được từ Socket."""
        cmd = parsed_frame.get('cmd')
        parsed_data = parsed_frame.get('parsed_data')

        if cmd in (101, 201, 1865, 1867) and parsed_data:
            messages = parsed_data.get('messages', [])
            for m in messages:
                from_u = m.get('from_uid')
                if not from_u or from_u == self.client.uid or m.get('is_self'):
                    continue
                to_g = m.get('to_group')
                from_d = m.get('from_display') or m.get('from_name') or get_name(from_u) or str(from_u)
                content = m.get('content', '') or m.get('text', '')
                self._process_command(to_g, from_u, from_d, content, m)

    def _process_command(self, group_id: Optional[int], from_uid: int, from_display: str, text: str, extra: Optional[Dict[str, Any]] = None):
        """Điểm vào xử lý lệnh/tin nhắn nhận được."""
        if not from_uid or from_uid == self.client.uid:
            return
        ev = extra if extra is not None else {}
        if not ev:
            ev = {
                'is_group': bool(group_id),
                'to_group': group_id,
                'from_uid': from_uid,
                'from_name': from_display,
                'content': text,
                'text': text,
                'msg_id': 0,
                'cli_msg_id': 0,
                'type': 'webchat',
                'raw': {}
            }
        self._process_event(ev)

    def _send_reply(
        self,
        dest_id: int,
        reply_text: str,
        is_group: bool,
        quote_payload: Optional[Dict[str, Any]] = None,
        style_params: Optional[Dict[str, Any]] = None
    ):
        """Gửi tin nhắn phản hồi tới group hoặc 1-1 hỗ trợ Quote, TTL và Style."""
        try:
            self.client.send_typing(dest_id, is_group=is_group)
        except Exception:
            pass
        ttl_ms = self.ttl * 1000 if self.ttl > 0 else 0
        extra_kwargs = {}
        if self.default_style:
            extra_kwargs.update(self.default_style)
        if style_params:
            extra_kwargs.update(style_params)

        ALLOWED_MSG_KWARGS = {'style_id', 'size', 'color', 'bold', 'italic', 'underline', 'strike', 'fontsize', 'list_type', 'rtf_mode', 'mentions'}
        filtered_kwargs = {k: v for k, v in extra_kwargs.items() if k in ALLOWED_MSG_KWARGS}

        if is_group:
            self.client.send_group_message(dest_id, reply_text, quote_data=quote_payload, ttl_ms=ttl_ms, **filtered_kwargs)
        else:
            self.client.send_1to1_message(dest_id, reply_text, quote_data=quote_payload, ttl_ms=ttl_ms, **filtered_kwargs)

    def _process_event(self, ev: Dict[str, Any]):
        from_u = ev.get('from_uid')
        if not from_u:
            return

        # 1. Anti-Loop: Không xử lý tin nhắn của chính mình
        if from_u == self.client.uid or ev.get('is_self'):
            return

        raw_txt = (ev.get('content') or ev.get('text') or '').strip()
        # Bỏ qua các bản tin trống hoặc sync metadata không có text/attach/quote
        if not raw_txt and not ev.get('attach') and not ev.get('quote') and ev.get('type') == 'webchat':
            return

        self.msg_count += 1
        to_group = ev.get('to_group')
        from_display = ev.get('from_name') or get_name(from_u) or str(from_u)

        # In log ra terminal
        if to_group:
            print(f"\n📩 [Group {to_group}] {from_display} (UID: {from_u}): {raw_txt}")
        else:
            print(f"\n📩 [1-1] {from_display} (UID: {from_u}): {raw_txt}")

        # 2. Bỏ qua tin nhắn echo từ bot
        if (
            raw_txt.startswith("Pong!")
            or raw_txt.startswith("[Auto-Reply]")
            or raw_txt.startswith("[DATA")
            or raw_txt.startswith("[HƯỚNG DẪN LỆNH TEST]")
            or raw_txt.startswith("[HUONG DAN LENH TEST]")
            or raw_txt.startswith("[GROUP ID]")
            or raw_txt.startswith("Thời gian hệ thống")
            or raw_txt.startswith("Kết quả")
            or raw_txt.startswith("UID:")
            or raw_txt.startswith("TTL:")
            or raw_txt.startswith("[THỐNG KÊ")
            or raw_txt.startswith("[DANH SÁCH")
            or raw_txt.startswith("[ZALO REALTIME")
            or raw_txt.startswith("Avatar (")
            or raw_txt.startswith("🤖")
        ):
            return

        # 3. Tách mention
        clean_txt, is_bot_tagged, uids = clean_message_text(raw_txt, ev.get('mentions'), self.client.uid)

        # 4. Rate limiter chống spam
        now = time.time()
        with self.rate_lock:
            if from_u in self.last_reply_times and (now - self.last_reply_times[from_u]) < self.rate_limit_sec:
                return
            self.last_reply_times[from_u] = now

        # Auto-prefix nếu tag bot trực tiếp
        target_cmd_txt = clean_txt
        if is_bot_tagged and self.prefix and not target_cmd_txt.startswith(self.prefix):
            first_word = target_cmd_txt.split(' ')[0].lower() if target_cmd_txt else ''
            if first_word in (
                "ping", "test", "style", "styling", "help", "menu", "uid", "id", "me", "time", "date", "gio", "ngay",
                "uptime", "stats", "status", "botinfo", "about", "echo", "say", "calc", "math",
                "info", "user", "profile", "avatar", "ava", "img", "photo", "image", "anh", "setttl", "ttl", "ttlset", "grid", "groupid", "gid", "ginfo", "groupinfo", "preview", "xemnhom",
                "react", "reaction", "tim", "like", "haha", "wow", "cry", "angry", "dislike", "broken", "tha",
                "pin", "ghim", "unpin", "boghim", "disband", "giaitan",
                "kick", "ban", "duoi", "add", "them", "leave", "out", "join", "poll", "recall", "thuhoi", "revoke", "delete", "del", "xoa",
                "data", "raw", "msgdata", "dump"
            ):
                target_cmd_txt = f"{self.prefix}{target_cmd_txt}"

        quote_obj = ev.get('quote') or (ev.get('raw') or {}).get('quote')
        if isinstance(quote_obj, str) and quote_obj.strip().startswith('{'):
            try:
                quote_obj = json.loads(quote_obj)
            except Exception:
                pass

        quote_owner = None
        if isinstance(quote_obj, dict):
            quote_owner = quote_obj.get('ownerId') or quote_obj.get('owner_uid') or quote_obj.get('uid')
            if quote_owner:
                try:
                    quote_owner = int(quote_owner)
                except Exception:
                    quote_owner = None

        # Học metadata người dùng từ sự kiện Socket
        if from_u:
            self.user_info_api.register_seen_user(from_u, display_name=from_display)

        # 5. Sinh nội dung phản hồi
        reply_txt = generate_bot_response(
            msg_txt=target_cmd_txt,
            msg_type=ev.get('type', 'webchat'),
            prefix=self.prefix,
            keywords_list=self.keywords,
            fixed_reply=self.reply_text,
            reply_all=self.reply_all,
            from_uid=from_u,
            group_id=to_group,
            is_bot_mentioned=is_bot_tagged,
            bot_uid=self.client.uid,
            mentioned_uids=uids,
            quote_owner_id=quote_owner,
            quote_data=quote_obj if isinstance(quote_obj, dict) else None,
            raw_event=ev,
            user_info_api=self.user_info_api,
            group_api=self.group_api,
            start_time=self.start_time,
            msg_count=self.msg_count
        )

        if reply_txt:
            # Xử lý lệnh Test / Send Style
            style_params = {}
            style_match = re.search(r'__ACTION_SEND_STYLE:(.*?)__\s*', reply_txt)
            if style_match:
                style_json_str = style_match.group(1)
                reply_txt = re.sub(r'__ACTION_SEND_STYLE:.*?__\s*', '', reply_txt).strip()
                try:
                    style_params = json.loads(style_json_str)
                except Exception:
                    style_params = {}

            # Xử lý lệnh thiết lập TTL cuộc trò chuyện
            set_ttl_match = re.search(r'__ACTION_SET_TTL:(\d+)__\s*', reply_txt)
            if set_ttl_match:
                ttl_action_val = int(set_ttl_match.group(1))
                reply_txt = re.sub(r'__ACTION_SET_TTL:\d+__\s*', '', reply_txt).strip()
                self.ttl = ttl_action_val
                logger.info(f"⚙️ [TTL] Đã thiết lập TTL tin nhắn của Bot thành {ttl_action_val}s.")

            # Xử lý lệnh Reaction
            react_match = re.search(r'__ACTION_REACT:(.*?)__\s*', reply_txt)
            if react_match:
                icon_val = react_match.group(1)
                reply_txt = re.sub(r'__ACTION_REACT:.*?__\s*', '', reply_txt).strip()
                target_dest = to_group if to_group else from_u
                c_msg = (
                    (quote_obj.get('cliMsgId') or quote_obj.get('cmi')) if isinstance(quote_obj, dict) else (
                        ev.get('cli_msg_id') or ev.get('cliMsgId') or (ev.get('raw') or {}).get('cliMsgId') or int(time.time() * 1000)
                    )
                )
                g_msg = (
                    (quote_obj.get('globalMsgId') or quote_obj.get('gmi')) if isinstance(quote_obj, dict) else (
                        ev.get('msg_id') or ev.get('globalMsgId') or (ev.get('raw') or {}).get('id') or 0
                    )
                )
                self.group_api.send_reaction(target_id=target_dest, cli_msg_id=c_msg, global_msg_id=g_msg, icon=icon_val, is_group=bool(to_group))

            # Xử lý lệnh Pin Message
            pin_match = re.search(r'__ACTION_PIN:(.*?)__\s*', reply_txt)
            if pin_match:
                pin_val = pin_match.group(1)
                reply_txt = re.sub(r'__ACTION_PIN:.*?__\s*', '', reply_txt).strip()
                if to_group:
                    c_msg = (
                        (quote_obj.get('cliMsgId') or quote_obj.get('cmi')) if isinstance(quote_obj, dict) else (
                            ev.get('cli_msg_id') or ev.get('cliMsgId') or (ev.get('raw') or {}).get('cliMsgId') or int(time.time() * 1000)
                        )
                    )
                    g_msg = (
                        (quote_obj.get('globalMsgId') or quote_obj.get('gmi')) if isinstance(quote_obj, dict) else (
                            ev.get('msg_id') or ev.get('globalMsgId') or (ev.get('raw') or {}).get('id') or 0
                        )
                    )
                    self.group_api.pin_message(group_id=to_group, title=pin_val, cli_msg_id=c_msg, global_msg_id=g_msg, sender_uid=self.client.uid, sender_name=from_display)

            # Xử lý lệnh Unpin Message
            unpin_match = re.search(r'__ACTION_UNPIN:(.*?)__\s*', reply_txt)
            if unpin_match:
                unpin_topic_str = unpin_match.group(1)
                reply_txt = re.sub(r'__ACTION_UNPIN:.*?__\s*', '', reply_txt).strip()
                if to_group:
                    c_msg = ((quote_obj.get('cliMsgId') or quote_obj.get('cmi')) if isinstance(quote_obj, dict) else 0)
                    g_msg = ((quote_obj.get('globalMsgId') or quote_obj.get('gmi')) if isinstance(quote_obj, dict) else 0)
                    tid = int(unpin_topic_str) if unpin_topic_str.isdigit() else (int(g_msg) if g_msg else 0)
                    self.group_api.unpin_message(group_id=to_group, topic_id=tid, global_msg_id=g_msg, cli_msg_id=c_msg)
            elif "__ACTION_UNPIN__" in reply_txt:
                reply_txt = reply_txt.replace("__ACTION_UNPIN__", "").strip()
                if to_group:
                    c_msg = ((quote_obj.get('cliMsgId') or quote_obj.get('cmi')) if isinstance(quote_obj, dict) else 0)
                    g_msg = ((quote_obj.get('globalMsgId') or quote_obj.get('gmi')) if isinstance(quote_obj, dict) else 0)
                    self.group_api.unpin_message(group_id=to_group, topic_id=int(g_msg or 0), global_msg_id=g_msg, cli_msg_id=c_msg)

            # Xử lý lệnh Fetch Pins / Xem danh sách ghim
            if "__ACTION_FETCH_PINS__" in reply_txt:
                reply_txt = reply_txt.replace("__ACTION_FETCH_PINS__", "").strip()
                if to_group:
                    self.group_api.get_pinned_topics(group_id=to_group)

            # Xử lý lệnh Disband Group
            disband_target_gid = None
            if "__ACTION_DISBAND__" in reply_txt:
                disband_target_gid = to_group
                reply_txt = reply_txt.replace("__ACTION_DISBAND__", "").strip()

            # Xử lý lệnh Leave Group
            leave_target_gid = None
            leave_match = re.search(r'__ACTION_LEAVE(?::(\d+))?__\s*', reply_txt)
            if leave_match:
                leave_target_gid = int(leave_match.group(1)) if leave_match.group(1) else (to_group or None)
                reply_txt = re.sub(r'__ACTION_LEAVE(?::\d+)?__\s*', '', reply_txt).strip()

            # Xử lý lệnh Create Poll
            poll_match = re.search(r'__ACTION_POLL:(.*?)__\s*', reply_txt)
            if poll_match:
                poll_json_str = poll_match.group(1)
                reply_txt = re.sub(r'__ACTION_POLL:.*?__\s*', '', reply_txt).strip()
                if to_group:
                    try:
                        p_data = json.loads(poll_json_str)
                        self.group_api.create_poll(
                            group_id=to_group,
                            question=p_data.get('question', ''),
                            options=p_data.get('options', [])
                        )
                    except Exception as p_err:
                        logger.warning(f"Lỗi thực thi tạo poll: {p_err}")

            # Xử lý lệnh Recall Message (Thu hồi cho tất cả mọi người)
            recall_match = re.search(r'__ACTION_RECALL:(.*?)__\s*', reply_txt)
            if recall_match:
                recall_json_str = recall_match.group(1)
                reply_txt = re.sub(r'__ACTION_RECALL:.*?__\s*', '', reply_txt).strip()
                try:
                    r_data = json.loads(recall_json_str)
                    target_dest = to_group if to_group else from_u
                    c_msg = r_data.get('cli_msg_id', 0)
                    g_msg = r_data.get('global_msg_id', 0)
                    owner_id = r_data.get('owner_id') or None
                    self.group_api.recall_message(
                        group_id=target_dest,
                        cli_msg_id=c_msg,
                        global_msg_id=g_msg,
                        owner_id=owner_id,
                        is_group=bool(to_group)
                    )
                except Exception as r_err:
                    logger.warning(f"Lỗi thực thi thu hồi tin nhắn: {r_err}")

            # Xử lý lệnh Delete Message (Xóa tin nhắn)
            delete_match = re.search(r'__ACTION_DELETE:(.*?)__\s*', reply_txt)
            if delete_match:
                del_json_str = delete_match.group(1)
                reply_txt = re.sub(r'__ACTION_DELETE:.*?__\s*', '', reply_txt).strip()
                try:
                    d_data = json.loads(del_json_str)
                    target_dest = to_group if to_group else from_u
                    only_me = d_data.get('only_me', False)
                    c_msg = d_data.get('cli_msg_id', 0)
                    g_msg = d_data.get('global_msg_id', 0)
                    owner_id = d_data.get('owner_id') or None
                    self.group_api.delete_message(
                        group_id=target_dest,
                        cli_msg_id=c_msg,
                        global_msg_id=g_msg,
                        owner_id=owner_id,
                        is_group=bool(to_group),
                        only_me=only_me
                    )
                except Exception as d_err:
                    logger.warning(f"Lỗi thực thi xóa tin nhắn: {d_err}")

            # Xử lý lệnh Kick / Ban Group Member
            kick_match = re.search(r'__ACTION_KICK:(.*?)__\s*', reply_txt)
            if kick_match:
                kick_json_str = kick_match.group(1)
                reply_txt = re.sub(r'__ACTION_KICK:.*?__\s*', '', reply_txt).strip()
                if to_group:
                    try:
                        k_data = json.loads(kick_json_str)
                        k_uid = k_data.get('uid')
                        k_block = k_data.get('is_block', False)
                        if k_uid:
                            self.group_api.kick_member(group_id=to_group, member_uids=[k_uid], is_block=k_block)
                    except Exception as k_err:
                        logger.warning(f"Lỗi thực thi lệnh kick/ban: {k_err}")

            # Xử lý lệnh Send Photo / Gửi ảnh
            photo_match = re.search(r'__ACTION_SEND_PHOTO:(.*?)__\s*', reply_txt)
            if photo_match:
                photo_json_str = photo_match.group(1)
                reply_txt = re.sub(r'__ACTION_SEND_PHOTO:.*?__\s*', '', reply_txt).strip()
                try:
                    p_data = json.loads(photo_json_str)
                    target_dest = to_group if to_group else from_u
                    p_url = p_data.get('url', '')
                    p_thumb = p_data.get('thumb_url') or p_data.get('thumb') or None
                    p_cap = p_data.get('caption', '')
                    if p_url:
                        self.client.send_photo(
                            target_id=target_dest,
                            photo_url_or_path=p_url,
                            is_group=bool(to_group),
                            caption=p_cap,
                            thumb_url=p_thumb
                        )
                        return
                except Exception as p_err:
                    logger.warning(f"Lỗi thực thi gửi ảnh: {p_err}")

            # Xử lý lệnh Send Doodle / Gửi hình vẽ
            doodle_match = re.search(r'__ACTION_SEND_DOODLE:(.*?)__\s*', reply_txt)
            if doodle_match:
                doodle_json_str = doodle_match.group(1)
                reply_txt = re.sub(r'__ACTION_SEND_DOODLE:.*?__\s*', '', reply_txt).strip()
                try:
                    d_data = json.loads(doodle_json_str)
                    target_dest = to_group if to_group else from_u
                    d_url = d_data.get('url', '')
                    d_thumb = d_data.get('thumb_url') or d_data.get('thumb') or None
                    d_cap = d_data.get('caption', '')
                    if d_url:
                        self.client.send_doodle(
                            target_id=target_dest,
                            doodle_url_or_path=d_url,
                            thread_type=ThreadType.GROUP if to_group else ThreadType.USER,
                            caption=d_cap,
                            thumb_url=d_thumb
                        )
                        return
                except Exception as d_err:
                    logger.warning(f"Lỗi thực thi gửi doodle: {d_err}")

            # Xử lý lệnh Send Video / Gửi video
            video_match = re.search(r'__ACTION_SEND_VIDEO:(.*?)__\s*', reply_txt)
            if video_match:
                video_json_str = video_match.group(1)
                reply_txt = re.sub(r'__ACTION_SEND_VIDEO:.*?__\s*', '', reply_txt).strip()
                try:
                    v_data = json.loads(video_json_str)
                    target_dest = to_group if to_group else from_u
                    v_url = v_data.get('url', '')
                    v_thumb = v_data.get('thumb_url') or v_data.get('thumb') or None
                    v_cap = v_data.get('caption', '')
                    if v_url:
                        self.client.send_video(
                            target_id=target_dest,
                            video_url_or_path=v_url,
                            thread_type=ThreadType.GROUP if to_group else ThreadType.USER,
                            caption=v_cap,
                            thumb_url=v_thumb
                        )
                        return
                except Exception as v_err:
                    logger.warning(f"Lỗi thực thi gửi video: {v_err}")

            # Xử lý lệnh Block User 1-1
            block_match = re.search(r'__ACTION_BLOCK:(.*?)__\s*', reply_txt)
            if block_match:
                block_json_str = block_match.group(1)
                reply_txt = re.sub(r'__ACTION_BLOCK:.*?__\s*', '', reply_txt).strip()
                try:
                    b_data = json.loads(block_json_str)
                    b_uid = b_data.get('uid')
                    if b_uid:
                        self.group_api.block_user(target_uid=b_uid, is_block=b_data.get('is_block', True))
                except Exception as b_err:
                    logger.warning(f"Lỗi thực thi lệnh block user: {b_err}")

            # Xử lý lệnh Join Group (Link / UID)
            join_match = re.search(r'__ACTION_JOIN:(.*?)__\s*', reply_txt)
            if join_match:
                join_json_str = join_match.group(1)
                reply_txt = re.sub(r'__ACTION_JOIN:.*?__\s*', '', reply_txt).strip()
                try:
                    j_data = json.loads(join_json_str)
                    j_target = j_data.get('target')
                    if j_target:
                        threading.Thread(target=self.group_api.join_group, args=(j_target,), daemon=True).start()
                except Exception as j_err:
                    logger.warning(f"Lỗi thực thi lệnh join group: {j_err}")

            quote_payload = None if self.no_quote else build_quote_from_event(ev)

            if to_group:
                t_name = from_display.strip()
                if t_name.endswith(')') and ' (' in t_name:
                    t_name = t_name.split(' (')[0].strip()
                t_name = t_name.strip()

                if t_name and not reply_txt.startswith('@'):
                    group_reply_txt = f"@{t_name} {reply_txt}"
                else:
                    group_reply_txt = reply_txt

                print(f"🤖 [Bot Auto-Reply -> Group {to_group}]: {group_reply_txt}")
                self._send_reply(to_group, group_reply_txt, is_group=True, quote_payload=quote_payload, style_params=style_params)
                if leave_target_gid:
                    time.sleep(0.3)
                    self.group_api.leave_group(group_id=leave_target_gid)
                if disband_target_gid:
                    time.sleep(0.3)
                    self.group_api.disband_group(group_id=disband_target_gid)
            else:
                print(f"🤖 [Bot Auto-Reply -> 1-1 UID {from_u}]: {reply_txt}")
                self._send_reply(from_u, reply_txt, is_group=False, quote_payload=quote_payload, style_params=style_params)
                if leave_target_gid:
                    time.sleep(0.3)
                    self.group_api.leave_group(group_id=leave_target_gid)
                if disband_target_gid:
                    time.sleep(0.3)
                    self.group_api.disband_group(group_id=disband_target_gid)


def main():
    parser = argparse.ArgumentParser(description="Zalo TCP Socket Binary Client & Bot (Core SDK Powered)")
    parser.add_argument("--session", default="/root/zalo/fresh_session.json", help="Đường dẫn file session JSON")
    parser.add_argument("--frame0", default="/root/zalo/frame0.bin", help="Đường dẫn file Frame 0 Handshake Ticket")
    parser.add_argument("--to", "--dest", dest="to", type=int, default=None, help="UID người nhận để gửi tin 1-1 (--to hoặc --dest)")
    parser.add_argument("--group", "--gid", dest="group", type=int, default=None, help="Group ID để gửi tin nhóm (--group hoặc --gid)")
    parser.add_argument("--msg", "--text", dest="msg", type=str, default=None, help="Nội dung tin nhắn cần gửi (--msg hoặc --text)")
    parser.add_argument("--ttl", "--ttk", dest="ttl", default=None, help="Thời gian tự xóa TTL (giây hoặc cú pháp: 30s, 1m, 1h, 1d, 7d)")
    parser.add_argument("--group-ttl", type=int, default=None, help="Thời gian tự xóa tin nhóm theo mili-giây (VD: 86400000 = 1 ngày)")
    parser.add_argument("--typing", type=float, default=None, help="Thời gian treo 'đang soạn tin' (giây) trước khi gửi")
    parser.add_argument("--bold", action="store_true", help="Định dạng chữ đậm (RTF bold)")
    parser.add_argument("--italic", action="store_true", help="Định dạng chữ nghiêng (RTF italic)")
    parser.add_argument("--underline", action="store_true", help="Định dạng gạch chân (RTF underline)")
    parser.add_argument("--strike", action="store_true", help="Định dạng gạch ngang (RTF strike)")
    parser.add_argument("--fontsize", type=int, default=None, help="Cỡ chữ RTF (VD: 13=nhỏ, 18=to)")
    parser.add_argument("--color", type=str, default=None, help="Màu chữ hex (VD: db342e đỏ, 15a85f xanh lá, f7b503 vàng, f27806 cam)")
    parser.add_argument("--size", type=int, default=None, help="Kích thước text (50=mini, 300=to)")
    parser.add_argument("--font", "--style", "--typo", dest="font", type=str, default=None, help="Kiểu chữ/Font Typography (VD: retro, young, 15433...)")
    parser.add_argument("--list", type=int, default=None, choices=[1, 2], help="Danh sách RTF (1=bullet list, 2=numbered list)")
    parser.add_argument("--rtf-mode", default="fwd", choices=["fwd", "nofwd", "plain"], help="Chế độ đóng gói RTF (mặc định: fwd)")
    parser.add_argument("--listen", action="store_true", help="Chế độ chỉ lắng nghe tin nhắn realtime")
    parser.add_argument("--bot", action="store_true", help="Kích hoạt chế độ Auto-Reply Bot")
    parser.add_argument("--prefix", default="/", help="Tiền tố lệnh bot (mặc định: /)")
    parser.add_argument("--keywords", default=None, help="Danh sách từ khóa kích hoạt bot (phân cách bằng dấu phẩy)")
    parser.add_argument("--reply-text", default=None, help="Nội dung phản hồi cố định cho mọi tin nhắn phù hợp")
    parser.add_argument("--all", action="store_true", help="Tự động trả lời tất cả các tin nhắn nhận được")
    parser.add_argument("--no-quote", action="store_true", help="Không gửi kèm trích dẫn (quote)")
    parser.add_argument("--rate-limit", type=float, default=1.2, help="Khoảng thời gian rate limit giữa 2 tin nhắn từ 1 user (giây, mặc định 1.2)")
    parser.add_argument("--duration", type=int, default=0, help="Thời gian chạy (giây, 0 = vô hạn)")
    parser.add_argument("--profile", "--info", dest="profile", type=str, default=None, help="Xem thông tin chi tiết của 1 User ID (--profile <uid>)")
    parser.add_argument("--friends", action="store_true", help="Liệt kê toàn bộ danh sách bạn bè")
    parser.add_argument("--react", type=str, default=None, help="Thả cảm xúc vào tin nhắn (vd: ❤️, 👍, 😂, 😮, 😭, 😡, 💔)")
    parser.add_argument("--cmsg", type=int, default=0, help="Client Msg ID của tin nhắn cần tương tác")
    parser.add_argument("--gmsg", type=int, default=0, help="Global Msg ID của tin nhắn cần tương tác")
    parser.add_argument("--pin", type=str, default=None, help="Ghim tin nhắn / Topic vào nhóm")
    parser.add_argument("--unpin", action="store_true", help="Bỏ ghim tin nhắn trong nhóm")
    parser.add_argument("--disband", action="store_true", help="Giải tán nhóm chat")
    parser.add_argument("--leave", nargs="?", const=True, default=None, help="Rời khỏi nhóm chat (--leave hoặc --leave <GID>)")
    parser.add_argument("--poll", type=str, default=None, help="Tạo bình chọn ('Câu hỏi | Lựa chọn 1 | Lựa chọn 2')")
    parser.add_argument("--block", type=str, default=None, help="Chặn người dùng 1-1 (--block <uid>)")
    parser.add_argument("--recall", "--del", dest="recall", type=int, default=None, help="Thu hồi tin nhắn (--recall <cli_msg_id>)")
    parser.add_argument("--kick", type=str, default=None, help="Kick / Xóa thành viên khỏi nhóm (--kick <uid>)")
    parser.add_argument("--ban", type=str, default=None, help="Ban / Chặn thành viên khỏi nhóm (--ban <uid>)")
    parser.add_argument("--add", type=str, default=None, help="Thêm thành viên vào nhóm (--add <uid>)")
    parser.add_argument("--join", dest="join_target", type=str, default=None, help="Tham gia nhóm qua link (zalo.me/g/...) hoặc Group ID (--join <link/uid>)")
    parser.add_argument("--login", action="store_true", help="Đăng nhập tài khoản Zalo mới (Số điện thoại + Mật khẩu)")
    parser.add_argument("--phone", type=str, default=None, help="Số điện thoại dùng để đăng nhập (--phone <so_dt>)")
    parser.add_argument("--password", "--pass", dest="password", type=str, default=None, help="Mật khẩu tài khoản (--password <mat_khau>)")
    parser.add_argument("--debug", action="store_true", help="Bật chế độ debug log")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("ZaloSocketClient").setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)

    if args.login:
        from core.login import ZaloLoginClient
        phone = args.phone or input("📱 Nhập số điện thoại Zalo: ").strip()
        import getpass
        password = args.password or getpass.getpass("🔑 Nhập mật khẩu Zalo: ").strip()
        client = ZaloLoginClient()
        session = client.login(phone=phone, password=password, out_session_path=args.session)
        print(f"[✔] Đã hoàn tất đăng nhập! UID: {session.get('uid')}, Session lưu tại: {args.session}")
        return

    if args.profile:
        api = UserAPI(args.session)
        target_uid = extract_target_uid(args.profile) or args.profile
        user_data = api.get_user_profile(target_uid)
        if user_data:
            print(UserAPI.format_user_info(user_data))
        else:
            print(f"[!] Không tìm thấy thông tin cho: {args.profile}")
        return

    if args.friends:
        api = UserAPI(args.session)
        friends = api.get_all_friends()
        print(f"👥 Danh sách bạn bè ({len(friends)} người):")
        for u in friends:
            print(f"• {u.display_name} (UID: {u.user_id}) - {u.gender.to_display_string(u.gender.value)}")
        return

    ttl_seconds = parse_ttl_duration(str(args.ttl)) if args.ttl is not None else 0

    # Nạp session
    try:
        session_info = load_session(args.session)
        logger.info(f"[✔] Đã nạp phiên thành công cho UID: {session_info['uid']} (Nguồn: {session_info['source']})")
    except Exception as e:
        logger.error(f"[❌] Lỗi nạp session: {e}")
        sys.exit(1)

    bot_engine: Optional[ZaloBotEngine] = None

    def on_msg(parsed_frame):
        if bot_engine and args.bot:
            threading.Thread(target=bot_engine.handle_message, args=(parsed_frame,), daemon=True).start()
        elif args.listen:
            cmd = parsed_frame.get('cmd')
            data = parsed_frame.get('parsed_data')
            if cmd in (101, 201, 1865, 1867) and data:
                for m in data.get('messages', []):
                    from_d = m.get('from_display') or m.get('from_name') or str(m.get('from_uid'))
                    content = m.get('content', '') or m.get('text', '')
                    if not content and not m.get('attach') and not m.get('quote'):
                        continue
                    if m.get('is_group'):
                        print(f"\n📩 [Group {m.get('to_group')}] 👤 {from_d} ({m.get('from_uid')}): {content}")
                    else:
                        print(f"\n📩 [1-1] 👤 {from_d} ({m.get('from_uid')}): {content}")

    # Khởi tạo Socket Client từ core.socket
    client = ZaloSocketClient(
        uid=session_info['uid'],
        dk=session_info['dk'],
        session_key=session_info.get('session_key'),
        ksid=session_info.get('ksid'),
        cryptkey=session_info.get('cryptkey'),
        frame0_path=args.frame0,
        server_pool=session_info.get('socketServers') or DEFAULT_SERVERS,
        on_message_callback=on_msg,
        debug=args.debug
    )

    # Phân tích kiểu chữ/font mặc định từ tham số CLI
    font_id: Optional[int] = None
    if args.font:
        f_raw = str(args.font).strip().lower()
        if f_raw in ZALO_FONTS:
            font_id = ZALO_FONTS[f_raw]
        else:
            try:
                font_id = int(f_raw)
            except ValueError:
                logger.warning(f"[!] Tên font '{args.font}' không hợp lệ. Danh sách hỗ trợ: {', '.join(ZALO_FONTS.keys())}")

    if args.bot:
        kw_list = [k.strip() for k in args.keywords.split(',')] if args.keywords else None
        bot_default_style = {}
        if font_id is not None:
            bot_default_style["style_id"] = font_id
            logger.info(f"🎨 [Bot Style] Font mặc định: {ZALO_FONT_NAMES.get(font_id, str(font_id)).title()} (ID: {font_id})")
        if args.size is not None:
            bot_default_style["size"] = args.size
        if args.color:
            c_raw = str(args.color).strip().lower().lstrip('#')
            bot_default_style["color"] = COLOR_NAMES.get(c_raw, c_raw)
        if args.bold:
            bot_default_style["bold"] = True
        if args.italic:
            bot_default_style["italic"] = True
        if args.underline:
            bot_default_style["underline"] = True
        if args.strike:
            bot_default_style["strike"] = True
        if args.fontsize is not None:
            bot_default_style["fontsize"] = args.fontsize
        if args.list is not None:
            bot_default_style["list_type"] = args.list
        if args.rtf_mode:
            bot_default_style["rtf_mode"] = args.rtf_mode

        bot_engine = ZaloBotEngine(
            client,
            prefix=args.prefix,
            keywords=kw_list,
            reply_text=args.reply_text,
            reply_all=args.all,
            no_quote=args.no_quote,
            ttl=ttl_seconds,
            rate_limit_sec=args.rate_limit,
            default_style=bot_default_style
        )

    # Kết nối Socket và Handshake
    try:
        ok = client.connect()
        if not ok:
            logger.error("[❌] Không thể hoàn tất Handshake Socket. Đang thoát.")
            sys.exit(1)
    except Exception as e:
        logger.error(f"[❌] Lỗi kết nối Socket: {e}")
        sys.exit(1)

    def handle_sigint(sig, frame):
        logger.info("\nĐang dừng Zalo Socket Client...")
        client.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    # Xử lý các lệnh tương tác Socket-Native
    has_action = (
        args.react or args.pin or args.unpin or args.disband or (args.leave is not None and args.leave is not False)
        or args.poll or args.block or args.recall or args.kick or args.ban
        or args.add or args.join_target
    )

    if has_action:
        target_dest = args.group or args.to
        if not target_dest and not (args.kick or args.ban or args.add or args.join_target or args.block or (args.leave is not None and args.leave is not False)):
            logger.error("[❌] Vui lòng chỉ định --group <GID> hoặc --to <UID> để thực hiện tương tác.")
        else:
            if args.react:
                client.send_reaction(target_id=target_dest, cli_msg_id=args.cmsg, global_msg_id=args.gmsg, icon=args.react, is_group=bool(args.group))
                logger.info(f"[✔] Đã gửi cảm xúc {args.react} tới {'Group ' + str(args.group) if args.group else 'UID ' + str(args.to)}!")

            if args.pin:
                if not args.group:
                    logger.error("[❌] Tính năng ghim tin nhắn chỉ hỗ trợ cho nhóm (--group <GID>).")
                else:
                    client.pin_message(group_id=args.group, title=args.pin, global_msg_id=args.gmsg, cli_msg_id=args.cmsg)
                    logger.info(f"[✔] Đã gửi yêu cầu ghim tin nhắn vào Group {args.group}!")

            if args.unpin:
                if not args.group:
                    logger.error("[❌] Tính năng bỏ ghim tin nhắn chỉ hỗ trợ cho nhóm (--group <GID>).")
                else:
                    client.unpin_message(group_id=args.group)
                    logger.info(f"[✔] Đã gửi yêu cầu bỏ ghim tin nhắn trong Group {args.group}!")

            if args.disband:
                if not args.group:
                    logger.error("[❌] Tính năng giải tán nhóm chỉ hỗ trợ cho nhóm (--group <GID>).")
                else:
                    client.disband_group(group_id=args.group)
                    logger.info(f"[✔] Đã gửi lệnh giải tán Group {args.group}!")

            if args.leave is not None and args.leave is not False:
                leave_gid = None
                if isinstance(args.leave, str) and args.leave.isdigit():
                    leave_gid = int(args.leave)
                elif args.group:
                    leave_gid = int(args.group)
                if not leave_gid:
                    logger.error("[❌] Tính năng rời nhóm cần chỉ định nhóm: --group <GID> hoặc --leave <GID>.")
                else:
                    res_leave = client.leave_group(group_id=leave_gid, wait_response=True)
                    if isinstance(res_leave, dict) and res_leave.get('success'):
                        logger.info(f"[✔] Đã rời khỏi Group {leave_gid} thành công (Server ACK Status=0)!")
                    else:
                        logger.info(f"[✔] Đã gửi yêu cầu rời khỏi Group {leave_gid} (Server ACK: {res_leave})")

            if args.poll:
                if not args.group:
                    logger.error("[❌] Tính năng tạo bình chọn chỉ hỗ trợ cho nhóm (--group <GID>).")
                else:
                    parts = [p.strip() for p in (args.poll.split('|') if '|' in args.poll else args.poll.split(',')) if p.strip()]
                    if len(parts) >= 3:
                        q = parts[0]
                        opts = parts[1:]
                        client.create_poll(group_id=args.group, question=q, options=opts)
                        logger.info(f"[✔] Đã gửi yêu cầu tạo bình chọn '{q}' trong Group {args.group}!")
                    else:
                        logger.error("[❌] Vui lòng nhập câu hỏi và ít nhất 2 lựa chọn: 'Câu hỏi | Lựa chọn 1 | Lựa chọn 2'")

            if args.block:
                b_uid = extract_target_uid(str(args.block)) or int(args.block)
                client.block_user(target_uid=b_uid, is_block=True)
                logger.info(f"[✔] Đã gửi lệnh chặn người dùng {b_uid}!")

            if args.recall:
                if not target_dest:
                    logger.error("[❌] Vui lòng chỉ định --group <GID> hoặc --to <UID> để thu hồi tin nhắn.")
                else:
                    client.delete_message(group_id=target_dest, cli_msg_id=args.recall, global_msg_id=args.gmsg, is_group=bool(args.group))
                    logger.info(f"[✔] Đã gửi yêu cầu thu hồi tin nhắn #{args.recall}!")

            if args.kick:
                if not args.group:
                    logger.error("[❌] Tính năng kick thành viên chỉ hỗ trợ cho nhóm (--group <GID>).")
                else:
                    k_uid = extract_target_uid(str(args.kick)) or int(args.kick)
                    client.kick_member(group_id=args.group, member_uids=[k_uid], is_block=False)
                    logger.info(f"[✔] Đã gửi lệnh kick thành viên {k_uid} khỏi Group {args.group}!")

            if args.ban:
                if not args.group:
                    logger.error("[❌] Tính năng ban thành viên chỉ hỗ trợ cho nhóm (--group <GID>).")
                else:
                    b_uid = extract_target_uid(str(args.ban)) or int(args.ban)
                    client.block_group_member(group_id=args.group, member_uids=[b_uid])
                    logger.info(f"[✔] Đã gửi lệnh ban thành viên {b_uid} khỏi Group {args.group}!")

            if args.add:
                if not args.group:
                    logger.error("[❌] Tính năng thêm thành viên chỉ hỗ trợ cho nhóm (--group <GID>).")
                else:
                    a_uid = extract_target_uid(str(args.add)) or int(args.add)
                    client.add_member(group_id=args.group, member_uids=[a_uid], is_invite=False)
                    logger.info(f"[✔] Đã gửi lệnh thêm thành viên {a_uid} vào Group {args.group}!")

            if args.join_target:
                t_type, gid, code = GroupAPI.parse_group_target(args.join_target)
                if t_type == "id" or (gid and not code):
                    target_id = gid or int(args.join_target)
                    client.join_group(group_id=target_id, source=1)
                    if not args.group:
                        args.group = target_id
                    logger.info(f"[✔] Đã gửi yêu cầu tham gia Group ID {target_id} qua Socket (CMD 246 & 2000)!")
                else:
                    g_api = GroupAPI(session_path=args.session, socket_client=client)
                    res = g_api.join_group_by_link(code or args.join_target)
                    if isinstance(res, dict) and res.get('group_id') and not args.group:
                        args.group = res.get('group_id')
                    logger.info(f"[✔] Đã gửi yêu cầu tham gia nhóm qua link: {res.get('status') if isinstance(res, dict) else res}")

        if not (args.listen or args.bot or args.msg):
            time.sleep(1.0)
            client.close()
            return

    # Gửi tin nhắn nếu có tham số --msg / --text
    if args.msg:
        time.sleep(0.3)
        ttl_ms = args.group_ttl if args.group_ttl is not None else (ttl_seconds * 1000 if ttl_seconds > 0 else 0)

        font_id: Optional[int] = None
        if args.font:
            f_raw = str(args.font).strip().lower()
            if f_raw in ZALO_FONTS:
                font_id = ZALO_FONTS[f_raw]
            else:
                try:
                    font_id = int(f_raw)
                except ValueError:
                    logger.warning(f"[!] Tên font '{args.font}' không hợp lệ. Danh sách hỗ trợ: {', '.join(ZALO_FONTS.keys())}")

        if args.group:
            if args.typing:
                logger.info(f"[*] Đang hiển thị trạng thái đang soạn tin tới Group {args.group} ({args.typing}s)...")
                client.send_typing(args.group, is_group=True)
                time.sleep(args.typing)
            logger.info(f"[*] Đang gửi tin nhắn tới Group {args.group} (TTL={ttl_ms}ms, Font={args.font or 'Default'})...")
            client.send_group_message(
                args.group, args.msg, ttl_ms=ttl_ms,
                style_id=font_id, size=args.size, color=args.color,
                bold=args.bold, italic=args.italic, underline=args.underline,
                strike=args.strike, fontsize=args.fontsize, list_type=args.list,
                rtf_mode=args.rtf_mode
            )
            logger.info(f"[✔] Đã gửi tin nhắn tới Group {args.group} thành công (TTL={ttl_ms}ms)!")
        elif args.to:
            if args.typing is not None or ttl_ms > 0:
                typing_wait = args.typing if args.typing is not None else 0.4
                logger.info(f"[*] Đang gửi typing notification tới UID {args.to} ({typing_wait}s)...")
                client.send_typing(args.to, is_group=False)
                time.sleep(typing_wait)
            logger.info(f"[*] Đang gửi tin nhắn 1-1 tới UID {args.to} (TTL={ttl_ms}ms, Font={args.font or 'Default'}, Bold={args.bold}, Italic={args.italic}, Color={args.color})...")
            client.send_1to1_message(
                args.to, args.msg, ttl_ms=ttl_ms,
                style_id=font_id, size=args.size, color=args.color,
                bold=args.bold, italic=args.italic, underline=args.underline,
                strike=args.strike, fontsize=args.fontsize, list_type=args.list,
                rtf_mode=args.rtf_mode
            )
            logger.info(f"[✔] Đã gửi tin nhắn 1-1 tới UID {args.to} thành công (TTL={ttl_ms}ms)!")
        else:
            logger.warning("[⚠️] Bạn chưa chỉ định --group/--gid hoặc --to/--dest để gửi tin.")

        if not (args.listen or args.bot):
            time.sleep(1.5)

    # Chế độ chạy liên tục (Listen hoặc Bot)
    if args.listen or args.bot or (not args.msg):
        mode_str = "Auto-Reply Bot" if args.bot else "Lắng nghe Realtime"
        logger.info(f"[*] Đang chạy chế độ {mode_str}... Nhấn Ctrl+C để dừng.")
        start_t = time.time()
        try:
            while client.is_running:
                time.sleep(1)
                if args.duration > 0 and (time.time() - start_t) >= args.duration:
                    logger.info(f"Đã hết thời gian chạy ({args.duration}s). Đang dừng.")
                    break
        except KeyboardInterrupt:
            pass
        finally:
            client.close()
    else:
        time.sleep(1)
        client.close()


if __name__ == "__main__":
    main()
