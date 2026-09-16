import os
import json
import time
import logging
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Tuple, Union
TZ_VN = timezone(timedelta(hours=7))
from core.models.user import UserProfile
from core.utils.helpers import sign_params, API_KEY, API_SECRET, CLIENT_TYPE, CLIENT_VERSION, USER_AGENT
logger = logging.getLogger('core.api.user')
CACHE_TTL_SECONDS = 300

class UserAPI:

    def __init__(self, session_path: Optional[Union[str, Dict[str, Any]]]=None):
        self.session_path = session_path
        self._cache: Dict[int, Tuple[float, Dict[str, Any]]] = {}
        self._aliases: Dict[int, str] = {}
        self._seen_users: Dict[int, Dict[str, Any]] = {}
        self._last_friend_fetch = 0.0

    def _extract_session_fields(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(data, dict):
            return None
        sk = data.get('session_key') or (data.get('data') or {}).get('sessionKey')
        sign = data.get('sign') or ''
        uid = data.get('uid') or (data.get('data') or {}).get('userId') or 0
        if sk:
            return {'session_key': sk, 'sign': sign, 'uid': int(uid)}
        return None

    def _load_session(self) -> Optional[Dict[str, Any]]:
        if isinstance(self.session_path, dict):
            return self._extract_session_fields(self.session_path)
        search_paths = []
        if isinstance(self.session_path, str) and self.session_path:
            search_paths.append(self.session_path)
        search_paths.extend([os.path.join(os.getcwd(), 'fresh_session.json'), 'fresh_session.json', os.path.expanduser('~/.zalo/fresh_session.json'), '/root/zalo/fresh_session.json', '/sdcard/Download/Zalo/zm/fresh_session.json', '/sdcard/Download/Zalo/active_session.json'])
        for p in search_paths:
            if p and os.path.exists(p):
                try:
                    with open(p, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        res = self._extract_session_fields(data)
                        if res:
                            return res
                except Exception as ex:
                    logger.warning(f'Lỗi đọc session từ {p}: {ex}')
        return None

    def _call_api(self, url: str, extra_params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        sess = self._load_session()
        if not sess:
            return None
        p: Dict[str, Any] = {'api_key': API_KEY, 'session_key': sess['session_key'], 'sign': sess['sign'], 'ts': str(int(time.time())), 'clientType': CLIENT_TYPE, 'clientVersion': CLIENT_VERSION, **extra_params}
        p['sig'] = sign_params(p)
        full_url = f'{url}?{urllib.parse.urlencode(p)}'
        req = urllib.request.Request(full_url, headers={'User-Agent': USER_AGENT, 'Accept': '*/*'})
        try:
            with urllib.request.urlopen(req, timeout=6) as resp:
                if resp.status == 200:
                    raw = resp.read().decode('utf-8')
                    return json.loads(raw)
        except Exception as e:
            logger.warning(f'API request lỗi [{url}]: {e}')
        return None

    def register_seen_user(self, uid: int | str, display_name: Optional[str]=None, avatar: Optional[str]=None):
        try:
            u_int = int(uid)
        except (ValueError, TypeError):
            return
        if u_int not in self._seen_users:
            self._seen_users[u_int] = {'userId': u_int, 'displayName': display_name or f'Thành viên {u_int}', 'avatar': avatar or '', 'last_seen': int(time.time())}
        else:
            if display_name and (not display_name.startswith('Thành viên ')):
                self._seen_users[u_int]['displayName'] = display_name
            if avatar:
                self._seen_users[u_int]['avatar'] = avatar
            self._seen_users[u_int]['last_seen'] = int(time.time())

    def refresh_friends_cache(self) -> bool:
        now = time.time()
        res_friends = self._call_api('https://friend.talk.zing.vn/api/friend/loginfriend', {'avatarSize': '160', 'actiontime': '1', 'isSorted': '1'})
        if not res_friends or res_friends.get('error_code') != 0:
            return False
        res_alias = self._call_api('https://alias.api.zaloapp.com/api/list-v2', {'page': '1'})
        if res_alias and res_alias.get('error_code') == 0:
            alias_list = (res_alias.get('data') or {}).get('aliases', [])
            for a in alias_list:
                uid_val = a.get('userId')
                alias_name = a.get('alias')
                if uid_val and alias_name:
                    self._aliases[int(uid_val)] = str(alias_name)
        friends_data = res_friends.get('data') or []
        for u in friends_data:
            uid = u.get('userId')
            if uid:
                u_int = int(uid)
                if u_int in self._aliases:
                    u['alias'] = self._aliases[u_int]
                self._cache[u_int] = (now, u)
                self.register_seen_user(u_int, u.get('displayName'), u.get('avatar'))
        self._last_friend_fetch = now
        return True

    def get_user_profile(self, target_uid: int | str, force_refresh: bool=False, fallback_name: Optional[str]=None, fallback_avatar: Optional[str]=None) -> Optional[UserProfile]:
        try:
            uid = int(target_uid)
        except (ValueError, TypeError):
            return None
        now = time.time()
        if fallback_name or fallback_avatar:
            self.register_seen_user(uid, fallback_name, fallback_avatar)
        if not force_refresh and uid in self._cache:
            cached_at, data = self._cache[uid]
            if now - cached_at < CACHE_TTL_SECONDS:
                return UserProfile.from_dict(data)
        if force_refresh or (now - self._last_friend_fetch > 30 and (not self._cache)):
            self.refresh_friends_cache()
        if uid in self._cache:
            return UserProfile.from_dict(self._cache[uid][1])
        seen = self._seen_users.get(uid, {})
        d_name = seen.get('displayName') or fallback_name or self._aliases.get(uid) or f'Thành viên {uid}'
        ava = seen.get('avatar') or fallback_avatar or ''
        stranger_dict = {'userId': uid, 'displayName': d_name, 'alias': self._aliases.get(uid, ''), 'avatar': ava, 'gender': 2, 'sdob': '', 'dob': 0, 'phoneNumber': '', 'isFr': 0, 'isBlock': 0, 'isActive': 1, 'uname': '', 'is_friend': False}
        self._cache[uid] = (now, stranger_dict)
        return UserProfile.from_dict(stranger_dict)

    def get_all_friends(self, force_refresh: bool=False) -> List[UserProfile]:
        if force_refresh or not self._cache:
            self.refresh_friends_cache()
        friends = []
        for uid, (ts, d) in self._cache.items():
            if d.get('isFr', 0) == 1:
                friends.append(UserProfile.from_dict(d))
        return friends

    def get_aliases(self) -> Dict[int, str]:
        return dict(self._aliases)

    def discover_contacts(self, phones: List[str]) -> Optional[Dict[str, Any]]:
        sess = self._load_session()
        if not sess:
            return None
        p = {'api_key': API_KEY, 'session_key': sess['session_key'], 'sign': sess['sign'], 'ts': str(int(time.time())), 'clientType': CLIENT_TYPE, 'clientVersion': CLIENT_VERSION, 'phones': json.dumps(phones)}
        p['sig'] = sign_params(p)
        req = urllib.request.Request('https://tapi.api.zaloapp.com/api/contact/discoverContact', data=urllib.parse.urlencode(p).encode('utf-8'), headers={'User-Agent': USER_AGENT, 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': '*/*'})
        try:
            with urllib.request.urlopen(req, timeout=6) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except Exception as ex:
            logger.warning(f'discoverContact lỗi: {ex}')
            return None
    get_info = get_user_profile

    @staticmethod
    def format_user_info(user_obj: Union[UserProfile, Dict[str, Any]]) -> str:
        if isinstance(user_obj, UserProfile):
            d = user_obj.raw_data or {}
            uid = user_obj.user_id
            display_name = user_obj.display_name
            alias = user_obj.alias
            uname = user_obj.username
            gender_code = user_obj.gender.value if hasattr(user_obj.gender, 'value') else user_obj.gender
            sdob = user_obj.dob or ''
            phone = user_obj.phone or ''
            is_fr = user_obj.is_friend
            is_block = user_obj.is_blocked
            avatar_url = user_obj.avatar or ''
            type_str = user_obj.account_type
            created_str = user_obj.created_time
            last_onl_str = user_obj.last_online
        else:
            d = user_obj
            uid = d.get('userId', 0)
            display_name = d.get('displayName') or 'Chưa đặt tên'
            alias = d.get('alias')
            uname = d.get('uname')
            gender_code = d.get('gender')
            sdob = d.get('sdob') or ''
            dob = d.get('dob', 0)
            if not sdob and dob:
                try:
                    sdob = datetime.fromtimestamp(int(dob), tz=TZ_VN).strftime('%d/%m/%Y')
                except Exception:
                    sdob = ''
            phone = d.get('phoneNumber') or ''
            is_fr = d.get('isFr', 0) == 1 or d.get('is_friend', False)
            is_block = d.get('isBlock', 0) == 1
            avatar_url = d.get('avatar') or ''
            account_type = d.get('business_account')
            type_str = None
            if account_type and isinstance(account_type, dict):
                type_str = account_type.get('label_name', 'Business')
            from core.utils.helpers import estimate_account_creation, get_high_res_avatar
            created_str = d.get('created_time') or estimate_account_creation(uid)
            last_onl_str = d.get('last_online')
            if not last_onl_str and d.get('last_seen'):
                try:
                    last_onl_str = datetime.fromtimestamp(int(d['last_seen']), tz=TZ_VN).strftime('%d/%m/%Y %H:%M:%S')
                except Exception:
                    last_onl_str = None
            if not last_onl_str:
                last_onl_str = datetime.now(TZ_VN).strftime('%d/%m/%Y %H:%M:%S')
            avatar_url = get_high_res_avatar(avatar_url) or avatar_url
        if gender_code == 0:
            gender_str = 'Nam'
        elif gender_code == 1:
            gender_str = 'Nữ'
        else:
            gender_str = 'Không công khai'
        dob_str = sdob if sdob else 'Không công khai'
        phone_str = phone if phone else 'Không công khai'
        friend_str = 'Bạn bè' if is_fr else 'Người lạ / Thành viên nhóm'
        status_str = 'Bị chặn' if is_block else 'Bình thường'
        lines = ['[THÔNG TIN NGƯỜI DÙNG]', f'• Tên hiển thị : {display_name}']
        if alias:
            lines.append(f'• Biệt danh     : {alias}')
        lines.append(f'• User ID (UID) : {uid}')
        if uname:
            lines.append(f'• Username      : @{uname}')
        lines.append(f'• Giới tính     : {gender_str}')
        lines.append(f'• Ngày sinh     : {dob_str}')
        lines.append(f'• Số điện thoại : {phone_str}')
        lines.append(f'• Quan hệ       : {friend_str}')
        if created_str:
            lines.append(f'• Tạo tài khoản : {created_str}')
        if last_onl_str:
            lines.append(f'• Lần cuối onl  : {last_onl_str}')
        if type_str:
            lines.append(f'• Loại tài khoản: {type_str}')
        lines.append(f'• Trạng thái    : {status_str}')
        if avatar_url:
            lines.append(f'• Ảnh đại diện  : {avatar_url}')
        return '\n'.join(lines)
