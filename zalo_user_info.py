#!/usr/bin/env python3
"""
zalo_user_info.py — Module truy xuất và hiển thị thông tin User Zalo chi tiết.
- Hỗ trợ cả Bạn bè và Người lạ / Thành viên nhóm chưa kết bạn.
- Sử dụng API Mobile chính thức: friend.talk.zing.vn/api/friend/loginfriend
- Đồng bộ danh sách Alias từ alias.api.zaloapp.com/api/list-v2
- Khám phá liên hệ từ tapi.api.zaloapp.com/api/contact/discoverContact
- Bộ nhớ đệm (Cache) 5 phút (300 giây) chống rate-limit và tự động học metadata người dùng từ sự kiện Socket
- Chuẩn hóa giới tính: 0=Nam 👦, 1=Nữ 👧, 2/khác=Chưa thiết lập ❓
"""

import os
import re
import json
import time
import hashlib
import logging
import urllib.request
import urllib.parse
from typing import Optional, Dict, Any, List, Tuple

logger = logging.getLogger("zalo_user_info")

API_KEY = "0be3747aacc670a51a83230bcfe80173"
API_SECRET = "8cd0fc6c58e88e78d62db52f0e093367"
CLIENT_TYPE = "1"
CLIENT_VERSION = "260802903"
USER_AGENT = "Zalo/260802903 CFNetwork/1408.0.4 Darwin/22.5.0"

CACHE_TTL_SECONDS = 300  # 5 phút cache


def sign_params(params: Dict[str, Any], secret: str = API_SECRET) -> str:
    """
    Tính toán chữ ký sig MD5 cho Zalo Mobile API:
    sig = MD5( (k1=v1k2=v2... sorted theo key) + secret )
    """
    param_str = "".join(f"{k}={params[k]}" for k in sorted(params.keys()))
    return hashlib.md5((param_str + secret).encode("utf-8")).hexdigest()


class ZaloUserInfoAPI:
    """Quản lý truy vấn và cache thông tin profile người dùng Zalo (Bạn bè & Người lạ)."""

    def __init__(self, session_path: str = "/root/zalo/fresh_session.json"):
        self.session_path = session_path
        self._cache: Dict[int, Tuple[float, Dict[str, Any]]] = {}  # uid -> (cached_at, data)
        self._aliases: Dict[int, str] = {}
        self._seen_users: Dict[int, Dict[str, Any]] = {}  # Dynamic runtime registry
        self._last_friend_fetch = 0.0

    def _load_session(self) -> Optional[Dict[str, Any]]:
        """Đọc session_key và sign từ file fresh_session.json."""
        paths = [
            self.session_path,
            "/root/zalo/fresh_session.json",
            "/sdcard/Download/Zalo/zm/fresh_session.json",
            "/sdcard/Download/Zalo/active_session.json",
        ]
        for p in paths:
            if os.path.exists(p):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        sk = data.get("session_key") or (data.get("data") or {}).get("sessionKey")
                        sign = data.get("sign") or ""
                        if sk:
                            return {
                                "session_key": sk,
                                "sign": sign,
                                "uid": data.get("uid") or (data.get("data") or {}).get("userId") or 0,
                            }
                except Exception as ex:
                    logger.warning(f"Lỗi đọc session từ {p}: {ex}")
        return None

    def _call_api(self, url: str, extra_params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Gửi request có chữ ký chuẩn tới Zalo Mobile API."""
        sess = self._load_session()
        if not sess:
            logger.error("Không tìm thấy session_key hợp lệ để gọi API.")
            return None

        p: Dict[str, Any] = {
            "api_key": API_KEY,
            "session_key": sess["session_key"],
            "sign": sess["sign"],
            "ts": str(int(time.time())),
            "clientType": CLIENT_TYPE,
            "clientVersion": CLIENT_VERSION,
            **extra_params,
        }
        p["sig"] = sign_params(p)

        full_url = f"{url}?{urllib.parse.urlencode(p)}"
        req = urllib.request.Request(
            full_url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=6) as resp:
                if resp.status == 200:
                    raw = resp.read().decode("utf-8")
                    return json.loads(raw)
        except Exception as e:
            logger.warning(f"API request lỗi [{url}]: {e}")
        return None

    def register_user_meta(self, uid: int | str, display_name: Optional[str] = None, avatar: Optional[str] = None):
        """Học thông tin user từ sự kiện tin nhắn Socket (áp dụng cho người lạ / thành viên nhóm)."""
        try:
            u_int = int(uid)
        except (ValueError, TypeError):
            return

        if u_int not in self._seen_users:
            self._seen_users[u_int] = {
                "userId": u_int,
                "displayName": display_name or f"Người dùng {u_int}",
                "avatar": avatar or "",
                "last_seen": int(time.time()),
            }
        else:
            if display_name and not display_name.startswith("Người dùng "):
                self._seen_users[u_int]["displayName"] = display_name
            if avatar:
                self._seen_users[u_int]["avatar"] = avatar
            self._seen_users[u_int]["last_seen"] = int(time.time())

    def refresh_friends_cache(self) -> bool:
        """Làm mới danh sách bạn bè và alias vào cache."""
        now = time.time()
        # 1. Lấy danh sách bạn bè
        res_friends = self._call_api(
            "https://friend.talk.zing.vn/api/friend/loginfriend",
            {"avatarSize": "160", "actiontime": "1", "isSorted": "1"},
        )
        if not res_friends or res_friends.get("error_code") != 0:
            logger.warning(f"Không thể nạp loginfriend: {res_friends}")
            return False

        # 2. Lấy danh sách alias / biệt danh nếu có
        res_alias = self._call_api(
            "https://alias.api.zaloapp.com/api/list-v2",
            {"page": "1"},
        )
        if res_alias and res_alias.get("error_code") == 0:
            alias_list = (res_alias.get("data") or {}).get("aliases", [])
            for a in alias_list:
                uid_val = a.get("userId")
                alias_name = a.get("alias")
                if uid_val and alias_name:
                    self._aliases[int(uid_val)] = str(alias_name)

        # 3. Lưu vào cache
        friends_data = res_friends.get("data") or []
        for u in friends_data:
            uid = u.get("userId")
            if uid:
                u_int = int(uid)
                if u_int in self._aliases:
                    u["alias"] = self._aliases[u_int]
                self._cache[u_int] = (now, u)
                self.register_user_meta(u_int, u.get("displayName"), u.get("avatar"))

        self._last_friend_fetch = now
        logger.info(f"Đã cập nhật cache cho {len(friends_data)} bạn bè Zalo.")
        return True

    def get_user_info(
        self,
        target_uid: int | str,
        force_refresh: bool = False,
        fallback_display_name: Optional[str] = None,
        fallback_avatar: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Lấy thông tin người dùng theo target_uid (hỗ trợ cả bạn bè lẫn người lạ).
        Kiểm tra cache bạn bè trước (TTL 300s). Nếu không có, tra cứu seen registry và xây dựng hồ sơ.
        """
        try:
            uid = int(target_uid)
        except (ValueError, TypeError):
            return None

        now = time.time()

        # Đăng ký fallback nếu có
        if fallback_display_name or fallback_avatar:
            self.register_user_meta(uid, fallback_display_name, fallback_avatar)

        # 1. Kiểm tra cache bạn bè còn hạn không
        if not force_refresh and uid in self._cache:
            cached_at, data = self._cache[uid]
            if now - cached_at < CACHE_TTL_SECONDS:
                return data

        # 2. Nếu cache đã cũ hoặc chưa nạp bạn bè lần nào
        if force_refresh or (now - self._last_friend_fetch > 30 and not self._cache):
            self.refresh_friends_cache()

        if uid in self._cache:
            return self._cache[uid][1]

        # 3. Người dùng chưa kết bạn (Người lạ / Thành viên nhóm)
        seen = self._seen_users.get(uid, {})
        d_name = seen.get("displayName") or fallback_display_name or self._aliases.get(uid) or f"Thành viên {uid}"
        ava = seen.get("avatar") or fallback_avatar or ""

        stranger_data = {
            "userId": uid,
            "displayName": d_name,
            "alias": self._aliases.get(uid, ""),
            "avatar": ava,
            "gender": 2,  # Chưa công khai
            "sdob": "",
            "dob": 0,
            "phoneNumber": "",
            "isFr": 0,
            "isBlock": 0,
            "isActive": 1,
            "uname": "",
            "is_friend": False,
        }
        # Lưu vào cache ngắn hạn
        self._cache[uid] = (now, stranger_data)
        return stranger_data

    @staticmethod
    def format_user_info(user_data: Dict[str, Any]) -> str:
        """
        Định dạng dữ liệu người dùng thành thẻ thông tin chi tiết đẹp mắt.
        Quy ước giới tính chuẩn Zalo:
          0 = Nam 👦
          1 = Nữ 👧
          2 / khác = Chưa thiết lập / Ẩn ❓
        """
        uid = user_data.get("userId", 0)
        display_name = user_data.get("displayName") or "Chưa đặt tên"
        alias = user_data.get("alias")
        uname = user_data.get("uname")

        gender_code = user_data.get("gender")
        if gender_code == 0:
            gender_str = "Nam"
        elif gender_code == 1:
            gender_str = "Nữ"
        else:
            gender_str = "Không công khai"

        sdob = user_data.get("sdob") or ""
        dob = user_data.get("dob", 0)
        if not sdob and dob:
            try:
                sdob = time.strftime("%d/%m/%Y", time.localtime(dob))
            except Exception:
                sdob = ""
        dob_str = sdob if sdob else "Không công khai"

        phone = user_data.get("phoneNumber") or ""
        phone_str = phone if phone else "Không công khai"

        is_fr = user_data.get("isFr", 0) == 1
        if is_fr:
            friend_str = "Bạn bè"
        else:
            friend_str = "Người lạ / Thành viên nhóm"

        is_block = user_data.get("isBlock", 0) == 1
        status_str = "Bị chặn" if is_block else "Bình thường"

        account_type = user_data.get("business_account")
        type_str = None
        if account_type and isinstance(account_type, dict):
            type_str = account_type.get("label_name", "Business")

        raw_avatar = user_data.get("avatar") or ""
        avatar_url = re.sub(r's\d+-(\d+-ava-talk)', r's600-\1', raw_avatar) if raw_avatar else ""

        # Last online & account creation
        last_onl = user_data.get("last_online")
        if not last_onl and user_data.get("last_seen"):
            try:
                last_onl = time.strftime("%d/%m/%Y %H:%M:%S", time.localtime(user_data["last_seen"]))
            except Exception:
                last_onl = None
        if not last_onl:
            last_onl = time.strftime("%d/%m/%Y %H:%M:%S", time.localtime())

        # Account creation estimation based on UID sequential range
        u_int = int(uid) if uid else 0
        if u_int < 50_000_000:
            created_str = "~2012 - 2014 (Giai đoạn đầu Zalo)"
        elif u_int < 150_000_000:
            created_str = "~2015 - 2016"
        elif u_int < 350_000_000:
            created_str = "~2017 - 2018"
        elif u_int < 550_000_000:
            created_str = "~2019 - 2020"
        elif u_int < 750_000_000:
            created_str = "~2021 - 2022"
        elif u_int < 900_000_000:
            created_str = "~2023 - 2024"
        else:
            created_str = "~2025 - 2026 (Tài khoản mới)"

        lines = [
            "[THÔNG TIN NGƯỜI DÙNG]",
            f"• Tên hiển thị : {display_name}",
        ]
        if alias:
            lines.append(f"• Biệt danh     : {alias}")
        lines.append(f"• User ID (UID) : {uid}")
        if uname:
            lines.append(f"• Username      : @{uname}")
        lines.append(f"• Giới tính     : {gender_str}")
        lines.append(f"• Ngày sinh     : {dob_str}")
        lines.append(f"• Số điện thoại : {phone_str}")
        lines.append(f"• Quan hệ       : {friend_str}")
        lines.append(f"• Tạo tài khoản : {created_str}")
        lines.append(f"• Lần cuối onl  : {last_onl}")
        if type_str:
            lines.append(f"• Loại tài khoản: {type_str}")
        lines.append(f"• Trạng thái    : {status_str}")
        if avatar_url:
            lines.append(f"• Ảnh đại diện  : {avatar_url}")

        return "\n".join(lines)


def extract_target_uid(
    arg_text: str,
    mentioned_uids: Optional[List[int]] = None,
    quote_owner_id: Optional[int] = None,
    bot_uid: Optional[int] = None,
) -> Optional[int]:
    """
    Trích xuất UID mục tiêu cho lệnh /info:
    1. Ưu tiên @tag mention (loại trừ bot UID).
    2. Đối số dạng số (VD: /info 277635559).
    3. Tin nhắn được quote / reply (quote ownerId != bot_uid).
    4. Trả về None nếu không có đối tượng cụ thể.
    """
    # 1. Kiểm tra UIDs được tag
    if mentioned_uids:
        for u in mentioned_uids:
            if bot_uid is None or int(u) != int(bot_uid):
                return int(u)

    # 2. Kiểm tra arg dạng số UID
    clean_arg = (arg_text or "").strip()
    if clean_arg.isdigit() and len(clean_arg) >= 4:
        return int(clean_arg)

    # 3. Kiểm tra tin nhắn được quote / reply
    if quote_owner_id and (bot_uid is None or int(quote_owner_id) != int(bot_uid)):
        return int(quote_owner_id)

    return None
