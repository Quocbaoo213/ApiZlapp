#!/usr/bin/env python3
"""
core/utils/helpers.py — Các hàm tiện ích hỗ trợ xử lý chuỗi, TTL và chữ ký.
"""

import re
import hashlib
from typing import Dict, Any, Optional, List, Tuple

API_KEY = "0be3747aacc670a51a83230bcfe80173"
API_SECRET = "8cd0fc6c58e88e78d62db52f0e093367"
CLIENT_TYPE = "1"
CLIENT_VERSION = "260802903"
USER_AGENT = "Zalo/260802903 CFNetwork/1408.0.4 Darwin/22.5.0"


def sign_params(params: Dict[str, Any], secret: str = API_SECRET) -> str:
    """Tính toán chữ ký sig MD5 sorted keys cho Zalo Mobile API."""
    param_str = "".join(f"{k}={params[k]}" for k in sorted(params.keys()))
    return hashlib.md5((param_str + secret).encode("utf-8")).hexdigest()


def zalo_encode(payload: Any, cryptkey_b64: str) -> str:
    """
    Mã hóa payload (dict/list) theo chuẩn ZaloEncode (Go reference: util.ZaloEncode).
    AES-128-CBC, IV=0x00*16, PKCS7 padding, key từ base64(cryptkey).
    Trả về base64 string để gửi trong form field 'params'.
    """
    import json
    import base64
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    raw_key = base64.b64decode(cryptkey_b64)
    plain = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    iv = b'\x00' * 16
    cipher = AES.new(raw_key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plain, AES.block_size))
    return base64.b64encode(encrypted).decode('utf-8')


def parse_ttl_duration(val: str) -> int:
    """Chuyển đổi chuỗi thời gian người dùng nhập thành số giây TTL chuẩn Zalo."""
    val = (val or "").lower().strip()
    if val in ("0", "off", "tat", "tắt", "none", "disable", "no", ""):
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


def utf16_len(text: str) -> int:
    """Độ dài chuỗi theo đơn vị UTF-16 code units (2-byte) chuẩn Zalo."""
    return len((text or "").encode('utf-16-le')) // 2


def extract_target_uid(
    arg_text: str,
    mentioned_uids: Optional[List[int]] = None,
    quote_owner_id: Optional[int] = None,
    bot_uid: Optional[int] = None,
) -> Optional[int]:
    """Trích xuất UID mục tiêu từ @tag, arg số, hoặc quote reply."""
    if mentioned_uids:
        for u in mentioned_uids:
            if bot_uid is None or int(u) != int(bot_uid):
                return int(u)

    clean_arg = (arg_text or "").strip()
    if clean_arg.isdigit() and len(clean_arg) >= 4:
        return int(clean_arg)

    if quote_owner_id and (bot_uid is None or int(quote_owner_id) != int(bot_uid)):
        return int(quote_owner_id)

    return None


def to_math_bold(text: str) -> str:
    """Chuyển đổi ký tự ASCII sang Mathematical Bold (𝐓𝐞𝐬𝐭 𝐁𝐨𝐥𝐝)."""
    out = []
    for ch in text:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr(0x1D400 + o - 65))
        elif 97 <= o <= 122:
            out.append(chr(0x1D41A + o - 97))
        elif 48 <= o <= 57:
            out.append(chr(0x1D7CE + o - 48))
        else:
            out.append(ch)
    return "".join(out)


def to_math_italic(text: str) -> str:
    """Chuyển đổi ký tự ASCII sang Mathematical Italic (𝑇𝑒𝑠𝑡 𝐼𝑡𝑎𝑙𝑖𝑐)."""
    out = []
    for ch in text:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr(0x1D434 + o - 65))
        elif 97 <= o <= 122:
            if ch == 'h':
                out.append('\u210e')
            else:
                out.append(chr(0x1D44E + o - 97))
        else:
            out.append(ch)
    return "".join(out)


def to_math_bold_italic(text: str) -> str:
    """Chuyển đổi ký tự ASCII sang Mathematical Bold Italic (𝑻𝒆𝒔𝒕 𝑩𝒐𝒍𝒅 𝑰𝒕𝒂𝒍𝒊𝒄)."""
    out = []
    for ch in text:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr(0x1D468 + o - 65))
        elif 97 <= o <= 122:
            out.append(chr(0x1D482 + o - 97))
        else:
            out.append(ch)
    return "".join(out)


def to_combining_underline(text: str) -> str:
    """Thêm dấu gạch chân Unicode (u̲n̲d̲e̲r̲l̲i̲n̲e̲)."""
    return "".join(ch + "\u0332" if ch not in (" ", "\n", "\t") else ch for ch in text)


def to_combining_strike(text: str) -> str:
    """Thêm dấu gạch ngang Unicode (s̶t̶r̶i̶k̶e̶)."""
    return "".join(ch + "\u0336" if ch not in (" ", "\n", "\t") else ch for ch in text)


def apply_visual_styling(
    text: str,
    bold: bool = False,
    italic: bool = False,
    underline: bool = False,
    strike: bool = False,
    fontsize: Optional[int] = None,
    color: Optional[str] = None
) -> str:
    """
    Trả về nội dung văn bản gốc thuần túy, định dạng được mã hóa trực tiếp qua Zalo Native RTF Protocol.
    """
    return text


def estimate_account_creation(uid: int) -> str:
    """Ước tính khoảng thời gian khởi tạo tài khoản Zalo dựa trên dải số UID tuần tự."""
    u = int(uid)
    if u <= 0:
        return "Không xác định"
    if u < 50_000_000:
        return "~2012 - 2014 (Giai đoạn đầu Zalo)"
    elif u < 150_000_000:
        return "~2015 - 2016"
    elif u < 350_000_000:
        return "~2017 - 2018"
    elif u < 550_000_000:
        return "~2019 - 2020"
    elif u < 750_000_000:
        return "~2021 - 2022"
    elif u < 900_000_000:
        return "~2023 - 2024"
    else:
        return "~2025 - 2026 (Tài khoản mới)"


def get_high_res_avatar(avatar_url: Optional[str]) -> str:
    """Nâng cấp URL avatar từ s160/s120 sang s600 hoặc ảnh gốc chất lượng cao."""
    if not avatar_url:
        return ""
    # s160-26-ava-talk.zadn.vn -> s600-26-ava-talk.zadn.vn
    res = re.sub(r's\d+-(\d+-ava-talk)', r's600-\1', avatar_url)
    return res


def resolve_photo_metadata(
    source: str,
    default_width: int = 800,
    default_height: int = 600,
    timeout: float = 5.0
) -> Tuple[str, int, int, int]:
    """
    Phân giải metadata ảnh (URL hoặc đường dẫn file cục bộ).
    Trả về: (photo_url_or_path, width, height, total_size)
    """
    import os
    import io
    import urllib.request
    from PIL import Image

    source = (source or "").strip()
    if not source:
        return ("", default_width, default_height, 0)

    # 1. Đường dẫn file cục bộ
    if os.path.exists(source) and os.path.isfile(source):
        try:
            size = os.path.getsize(source)
            with Image.open(source) as img:
                w, h = img.size
                return (source, w, h, size)
        except Exception:
            return (source, default_width, default_height, os.path.getsize(source) if os.path.exists(source) else 0)

    # 2. Remote URL (http:// hoặc https://)
    if source.startswith(("http://", "https://")):
        try:
            req = urllib.request.Request(
                source,
                headers={"User-Agent": USER_AGENT}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                content_len = resp.headers.get("Content-Length")
                total_size = int(content_len) if content_len and content_len.isdigit() else 0
                data = resp.read()
                if not total_size:
                    total_size = len(data)
                try:
                    with Image.open(io.BytesIO(data)) as img:
                        w, h = img.size
                        return (source, w, h, total_size)
                except Exception:
                    return (source, default_width, default_height, total_size)
        except Exception:
            return (source, default_width, default_height, 0)

    return (source, default_width, default_height, 0)


def resolve_video_metadata(
    source: str,
    default_width: int = 1280,
    default_height: int = 720,
    default_duration_ms: int = 10000,
    timeout: float = 5.0
) -> Tuple[str, int, int, int, int]:
    """
    Phân giải metadata video (URL hoặc đường dẫn file cục bộ).
    Trả về: (video_url_or_path, width, height, duration_ms, total_size)
    """
    import os
    import urllib.request

    source = (source or "").strip()
    if not source:
        return ("", default_width, default_height, default_duration_ms, 0)

    # 1. Đường dẫn file cục bộ
    if os.path.exists(source) and os.path.isfile(source):
        size = os.path.getsize(source)
        return (source, default_width, default_height, default_duration_ms, size)

    # 2. Remote URL
    if source.startswith(("http://", "https://")):
        try:
            req = urllib.request.Request(
                source,
                method="HEAD",
                headers={"User-Agent": USER_AGENT}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                content_len = resp.headers.get("Content-Length")
                total_size = int(content_len) if content_len and content_len.isdigit() else 0
                return (source, default_width, default_height, default_duration_ms, total_size)
        except Exception:
            return (source, default_width, default_height, default_duration_ms, 0)

    return (source, default_width, default_height, default_duration_ms, 0)

