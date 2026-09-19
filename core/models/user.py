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
    bio: Optional[str] = None
    cover: Optional[str] = None
    global_id: Optional[str] = None
    is_friend: bool = False
    is_blocked: bool = False
    is_active: bool = True
    created_time: Optional[str] = None
    last_online: Optional[str] = None
    avatar: Optional[str] = None
    account_type: Optional[str] = None
    last_update_time: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'UserProfile':
        gender_code = d.get('gender') if d.get('gender') is not None else d.get('ged')
        if gender_code == 0:
            g = Gender.MALE
        elif gender_code == 1:
            g = Gender.FEMALE
        else:
            g = Gender.UNKNOWN
        dob_val = d.get('sdob') or ''
        if not dob_val and d.get('dob'):
            try:
                dob_val = datetime.fromtimestamp(int(d['dob']), tz=TZ_VN).strftime('%d/%m/%Y')
            except Exception:
                dob_val = ''
        acct_label = None
        if isinstance(d.get('business_account'), dict):
            acct_label = d['business_account'].get('label_name', 'Business')
        uid_val = int(d.get('userId') or d.get('uid') or 0)
        last_online_str = d.get('last_online')
        if not last_online_str and d.get('last_action'):
            try:
                la_ts = int(d['last_action'])
                if la_ts > 0:
                    dt = datetime.fromtimestamp(la_ts, tz=TZ_VN)
                    last_online_str = dt.strftime('%d/%m/%Y %H:%M:%S')
            except Exception:
                last_online_str = None
        elif not last_online_str and d.get('last_seen'):
            try:
                last_seen_ts = int(d['last_seen'])
                dt = datetime.fromtimestamp(last_seen_ts, tz=TZ_VN)
                last_online_str = dt.strftime('%d/%m/%Y %H:%M:%S')
            except Exception:
                last_online_str = None
        elif not last_online_str and d.get('actiontime'):
            try:
                at_ts = int(d['actiontime'])
                if at_ts > 1000000000000:
                    at_ts //= 1000
                dt = datetime.fromtimestamp(at_ts, tz=TZ_VN)
                last_online_str = dt.strftime('%d/%m/%Y %H:%M:%S')
            except Exception:
                last_online_str = None
        if not last_online_str:
            last_online_str = datetime.now(TZ_VN).strftime('%d/%m/%Y %H:%M:%S')
        update_time_str = None
        if d.get('lastUpdateTime'):
            try:
                lu_ts = int(d['lastUpdateTime'])
                if lu_ts > 0:
                    dt_u = datetime.fromtimestamp(lu_ts, tz=TZ_VN)
                    update_time_str = dt_u.strftime('%d/%m/%Y %H:%M:%S')
            except Exception:
                update_time_str = None
        from core.utils.helpers import estimate_account_creation, get_high_res_avatar
        created_str = d.get('created_time') or estimate_account_creation(uid_val)
        raw_avatar = d.get('avatar') or d.get('avt') or ''
        high_res = get_high_res_avatar(raw_avatar) if raw_avatar else None
        d_name = d.get('displayName') or d.get('dpn') or f'Người dùng {uid_val}'
        bio_text = d.get('stt') or d.get('bio') or None
        cover_url = d.get('cover') or None
        global_id = d.get('globalId') or None
        phone_val = d.get('phoneNumber') or d.get('phone') or None
        if phone_val == '':
            phone_val = None
        return cls(
            user_id=uid_val,
            display_name=d_name,
            alias=d.get('alias'),
            username=d.get('uname') or d.get('usr') or None,
            gender=g,
            dob=dob_val if dob_val else None,
            phone=phone_val,
            bio=bio_text,
            cover=cover_url,
            global_id=global_id,
            is_friend=d.get('isFr', 0) == 1 or d.get('is_friend', False),
            is_blocked=d.get('isBlock', 0) == 1,
            is_active=d.get('isActive', 1) == 1,
            created_time=created_str,
            last_online=last_online_str,
            avatar=high_res if high_res else raw_avatar if raw_avatar else None,
            account_type=acct_label,
            last_update_time=update_time_str,
            raw_data=d
        )

    @property
    def gender_display(self) -> str:
        return Gender.to_display_string(self.gender)

    def to_card(self) -> str:
        lines = ['[THÔNG TIN NGƯỜI DÙNG]', f'• Tên hiển thị : {self.display_name}']
        if self.alias:
            lines.append(f'• Biệt danh     : {self.alias}')
        lines.append(f'• User ID (UID) : {self.user_id}')
        if self.global_id:
            lines.append(f'• Global ID     : {self.global_id}')
        if self.username:
            lines.append(f'• Username      : @{self.username}')
        if self.bio:
            lines.append(f'• Tiểu sử (Bio) : {self.bio}')
        lines.append(f'• Giới tính     : {Gender.to_display_string(self.gender)}')
        lines.append(f"• Ngày sinh     : {self.dob or 'Không công khai'}")
        lines.append(f"• Số điện thoại : {self.phone or 'Không công khai'}")
        lines.append(f"• Quan hệ       : {('Bạn bè' if self.is_friend else 'Người lạ / Thành viên nhóm')}")
        if self.created_time:
            lines.append(f'• Tạo tài khoản : {self.created_time}')
        if self.last_update_time:
            lines.append(f'• Cập nhật gần  : {self.last_update_time}')
        if self.last_online:
            lines.append(f'• Lần cuối onl  : {self.last_online}')
        if self.account_type:
            lines.append(f'• Loại tài khoản: {self.account_type}')
        lines.append(f"• Trạng thái    : {('Bị chặn' if self.is_blocked else 'Bình thường')}")
        if self.avatar:
            lines.append(f'• Ảnh đại diện  : {self.avatar}')
        if self.cover:
            lines.append(f'• Ảnh bìa       : {self.cover}')
        return '\n'.join(lines)

    def __getitem__(self, item: str) -> Any:
        if item in self.raw_data:
            return self.raw_data[item]
        if hasattr(self, item):
            return getattr(self, item)
        if item in ('userId', 'uid'):
            return self.user_id
        if item in ('displayName', 'dpn'):
            return self.display_name
        raise KeyError(item)

    def get(self, item: str, default: Any = None) -> Any:
        try:
            return self[item]
        except KeyError:
            return default
