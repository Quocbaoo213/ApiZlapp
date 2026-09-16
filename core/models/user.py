#!/usr/bin/env python3
"""
core/models/user.py — Data model cho User Profile Zalo.
"""

from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from .enums import Gender

TZ_VN = timezone(timedelta(hours=7))


@dataclass
class UserProfile:
    user_id: int
    display_name: str
    alias: Optional[str] = None
    username: Optional[str] = None
    gender: Gender = Gender.UNKNOWN
    dob: Optional[str] = None
    phone: Optional[str] = None
    is_friend: bool = False
    is_blocked: bool = False
    is_active: bool = True
    created_time: Optional[str] = None
    last_online: Optional[str] = None
    avatar: Optional[str] = None
    account_type: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "UserProfile":
        gender_code = d.get("gender")
        if gender_code == 0:
            g = Gender.MALE
        elif gender_code == 1:
            g = Gender.FEMALE
        else:
            g = Gender.UNKNOWN

        dob_val = d.get("sdob") or ""
        if not dob_val and d.get("dob"):
            try:
                dob_val = datetime.fromtimestamp(int(d["dob"]), tz=TZ_VN).strftime("%d/%m/%Y")
            except Exception:
                dob_val = ""

        acct_label = None
        if isinstance(d.get("business_account"), dict):
            acct_label = d["business_account"].get("label_name", "Business")

        uid_val = int(d.get("userId") or 0)
        
        # Last online formatting
        last_online_str = d.get("last_online")
        if not last_online_str and d.get("last_seen"):
            try:
                last_seen_ts = int(d["last_seen"])
                dt = datetime.fromtimestamp(last_seen_ts, tz=TZ_VN)
                last_online_str = dt.strftime("%d/%m/%Y %H:%M:%S")
            except Exception:
                last_online_str = None
        elif not last_online_str and d.get("actiontime"):
            try:
                at_ts = int(d["actiontime"])
                if at_ts > 1000000000000:
                    at_ts //= 1000
                dt = datetime.fromtimestamp(at_ts, tz=TZ_VN)
                last_online_str = dt.strftime("%d/%m/%Y %H:%M:%S")
            except Exception:
                last_online_str = None

        if not last_online_str:
            last_online_str = datetime.now(TZ_VN).strftime("%d/%m/%Y %H:%M:%S")

        # Account creation estimation
        from core.utils.helpers import estimate_account_creation, get_high_res_avatar
        created_str = d.get("created_time") or estimate_account_creation(uid_val)
        raw_avatar = d.get("avatar") or ""
        high_res = get_high_res_avatar(raw_avatar)

        return cls(
            user_id=uid_val,
            display_name=d.get("displayName") or f"Người dùng {uid_val}",
            alias=d.get("alias"),
            username=d.get("uname"),
            gender=g,
            dob=dob_val if dob_val else None,
            phone=d.get("phoneNumber") if d.get("phoneNumber") else None,
            is_friend=d.get("isFr", 0) == 1 or d.get("is_friend", False),
            is_blocked=d.get("isBlock", 0) == 1,
            is_active=d.get("isActive", 1) == 1,
            created_time=created_str,
            last_online=last_online_str,
            avatar=high_res if high_res else (raw_avatar if raw_avatar else None),
            account_type=acct_label,
            raw_data=d
        )

    @property
    def gender_display(self) -> str:
        """Chuỗi hiển thị giới tính có icon."""
        return Gender.to_display_string(self.gender)

    def to_card(self) -> str:
        """Định dạng hồ sơ thành thẻ thông tin chi tiết đẹp mắt."""
        lines = [
            "[THÔNG TIN NGƯỜI DÙNG]",
            f"• Tên hiển thị : {self.display_name}",
        ]
        if self.alias:
            lines.append(f"• Biệt danh     : {self.alias}")
        lines.append(f"• User ID (UID) : {self.user_id}")
        if self.username:
            lines.append(f"• Username      : @{self.username}")
        lines.append(f"• Giới tính     : {Gender.to_display_string(self.gender)}")
        lines.append(f"• Ngày sinh     : {self.dob or 'Không công khai'}")
        lines.append(f"• Số điện thoại : {self.phone or 'Không công khai'}")
        lines.append(f"• Quan hệ       : {'Bạn bè' if self.is_friend else 'Người lạ / Thành viên nhóm'}")
        if self.created_time:
            lines.append(f"• Tạo tài khoản : {self.created_time}")
        if self.last_online:
            lines.append(f"• Lần cuối onl  : {self.last_online}")
        if self.account_type:
            lines.append(f"• Loại tài khoản: {self.account_type}")
        lines.append(f"• Trạng thái    : {'Bị chặn' if self.is_blocked else 'Bình thường'}")
        if self.avatar:
            lines.append(f"• Ảnh đại diện  : {self.avatar}")
        return "\n".join(lines)

