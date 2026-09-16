import re
import json
import logging
import urllib.request
import urllib.parse
from typing import Union, Optional, Tuple, Dict, Any
from core.api.common import BaseAPI
from core.utils.helpers import sign_params, API_KEY, CLIENT_TYPE, CLIENT_VERSION, USER_AGENT
logger = logging.getLogger('core.api.group.info')

class GroupInfoAPI(BaseAPI):

    @staticmethod
    def parse_group_target(target: Union[str, int]) -> Tuple[str, Optional[int], Optional[str]]:
        if isinstance(target, int):
            return ('id', target, None)
        target_str = str(target).strip()
        m_link = re.search('(?:https?://)?(?:(?:www\\.|chat\\.)?zalo\\.me)/g/([a-zA-Z0-9_\\-]+)', target_str)
        link_code = m_link.group(1) if m_link else None
        found_gid = None
        digits_matches = re.findall('\\b(\\d{6,15})\\b', target_str)
        if digits_matches:
            found_gid = int(digits_matches[0])
        if link_code:
            return ('link', found_gid, link_code)
        if target_str.isdigit() or found_gid:
            return ('id', found_gid or int(target_str), None)
        if re.match('^[a-zA-Z0-9_\\-]+$', target_str):
            return ('link', None, target_str)
        return ('unknown', None, None)

    def get_group_info_by_link(self, link_or_code: str) -> Optional[Dict[str, Any]]:
        _, _, code = self.parse_group_target(link_or_code)
        link_code = code or str(link_or_code).strip()
        sess = self._load_session()
        if not sess:
            return None
        p: Dict[str, Any] = {'api_key': API_KEY, 'session_key': sess['session_key'], 'sign': sess['sign'], 'clientType': CLIENT_TYPE, 'clientVersion': CLIENT_VERSION, 'linkId': link_code, 'grid': link_code, 'source': '0'}
        p['sig'] = sign_params(p)
        try:
            url = f'https://group.api.zaloapp.com/group/info?{urllib.parse.urlencode(p)}'
            req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT, 'Accept': '*/*'})
            with urllib.request.urlopen(req, timeout=8) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode('utf-8'))
        except Exception as e:
            logger.warning(f'Lỗi tra cứu thông tin nhóm qua link [{link_code}]: {e}')
        return None

    def resolve_group_id_from_link(self, link_or_code: str) -> Optional[int]:
        t_type, gid, code = self.parse_group_target(link_or_code)
        if gid:
            return int(gid)
        link_code = code or str(link_or_code).strip()
        if self._socket and hasattr(self._socket, 'known_groups'):
            for cached_gid, gdata in self._socket.known_groups.items():
                if gdata.get('link_code') == link_code or str(cached_gid) == link_code:
                    return int(cached_gid)
        if self._socket and getattr(self._socket, 'is_connected', False):
            try:
                if hasattr(self._socket, 'request_group_link_info') and callable(getattr(self._socket, 'request_group_link_info')):
                    s_gid = self._socket.request_group_link_info(link_code, timeout=2.5)
                    if isinstance(s_gid, int) and s_gid > 0 and (not isinstance(s_gid, bool)):
                        return s_gid
                    elif isinstance(s_gid, str) and s_gid.isdigit():
                        return int(s_gid)
            except Exception as e:
                logger.warning(f'Lỗi phân giải link nhóm qua socket: {e}')
        info = self.get_group_info_by_link(link_code)
        if info and isinstance(info, dict):
            data = info.get('data')
            if isinstance(data, dict):
                r_gid = data.get('groupId') or data.get('grid') or data.get('id')
                if r_gid and isinstance(r_gid, (int, str)):
                    try:
                        val = int(r_gid)
                        if val > 0:
                            return val
                    except (ValueError, TypeError):
                        pass
        return None

    @staticmethod
    def format_relative_created_time(created_time_ms: Union[int, float, str]) -> str:
        if not created_time_ms:
            return ''
        try:
            ts = float(created_time_ms)
            if ts < 100000000000.0:
                ts = ts * 1000.0
            import time
            now_ms = time.time() * 1000.0
            diff = max(0.0, now_ms - ts)
            ONE_DAY_MS = 86400000.0
            ONE_MONTH_MS = 2635200000.0
            ONE_YEAR_MS = 31536000000.0
            if diff < ONE_DAY_MS:
                return 'Vừa tạo hôm nay'
            elif diff < ONE_MONTH_MS:
                days = max(1, int(diff / ONE_DAY_MS))
                return f'Đã tạo {days} ngày trước'
            elif diff < ONE_YEAR_MS:
                months = max(1, int(diff / (30.0 * ONE_DAY_MS)))
                return f'Đã tạo {months} tháng trước'
            else:
                years = max(1, int(diff / ONE_YEAR_MS))
                return f'Đã tạo hơn {years} năm trước'
        except Exception:
            return ''

    def preview_group_link(self, link_or_code: str) -> Dict[str, Any]:
        raw = str(link_or_code).strip()
        _, gid, code = self.parse_group_target(raw)
        link_code = code or (raw.split('zalo.me/g/')[-1].split('?')[0].strip() if 'zalo.me/g/' in raw else raw)
        link_full = f'https://zalo.me/g/{link_code}' if not raw.startswith('http') else raw
        sock_res = None
        if self._socket and getattr(self._socket, 'is_connected', False):
            try:
                if hasattr(self._socket, 'preview_link_901') and callable(getattr(self._socket, 'preview_link_901')):
                    res = self._socket.preview_link_901(link_full, wait_response=True, timeout=3.0)
                    if isinstance(res, dict) and (not getattr(res, '_mock_name', None)):
                        sock_res = res
            except Exception as e:
                logger.debug(f'Lỗi preview socket 901: {e}')
        http_res = self.get_group_info_by_link(link_code) or {}
        http_data = http_res.get('data') if isinstance(http_res.get('data'), dict) else http_res if isinstance(http_res, dict) else {}
        res_gid = gid or (sock_res.get('group_id') if isinstance(sock_res, dict) else None) or http_data.get('groupId') or http_data.get('grid') or http_data.get('id')
        name = http_data.get('name') or http_data.get('groupName') or http_data.get('gname') or f'Nhóm {res_gid or link_code}'
        creator_name = http_data.get('creatorName') or http_data.get('ownerName') or http_data.get('creator_name') or 'Trưởng nhóm'
        creator_id = http_data.get('creatorId') or http_data.get('ownerId') or http_data.get('creator_id') or 0
        total_member = http_data.get('totalMember') or http_data.get('totalMembers') or http_data.get('member_count') or 0
        desc = http_data.get('desc') or http_data.get('description') or ''
        avatar = http_data.get('avt') or http_data.get('avatar') or ''
        is_community = bool(http_data.get('isCommunity') or http_data.get('is_community') or http_data.get('community'))
        requires_approval = bool(isinstance(http_data.get('setting'), dict) and http_data['setting'].get('joinAppr') or http_data.get('requireApproval') or http_data.get('needApprove'))
        question = http_data.get('question') or http_data.get('joinQuestion') or ''
        created_time = http_data.get('createdTime') or http_data.get('created_time') or http_data.get('createdDate') or 0
        created_time_str = self.format_relative_created_time(created_time)
        created_date_str = ''
        if created_time:
            try:
                import datetime
                ts = float(created_time)
                if ts > 100000000000.0:
                    ts = ts / 1000.0
                dt = datetime.datetime.fromtimestamp(ts)
                created_date_str = dt.strftime('%d/%m/%Y')
            except Exception:
                created_date_str = str(created_time)
        warning_text = http_data.get('warningText') or http_data.get('warning_text') or ''
        friends_in_group = http_data.get('friendsInGroup') or http_data.get('friends_in_group') or []
        type_str = 'Cộng đồng' if is_community else 'Nhóm'
        lines = [f'🏷️ [{type_str.upper()} ZALO] {name}', f'🔗 Liên kết: {link_full}']
        if res_gid:
            lines.append(f'🆔 Group ID: {res_gid}')
        if creator_name:
            lines.append(f'👑 {type_str} của: {creator_name}' + (f' (UID: {creator_id})' if creator_id else ''))
        if created_time_str:
            lines.append(f'📅 {created_time_str}' + (f' ({created_date_str})' if created_date_str else ''))
        elif created_date_str:
            lines.append(f'📅 Đã tạo ngày: {created_date_str}')
        if total_member:
            lines.append(f'👥 Số thành viên: {total_member}')
        if friends_in_group:
            lines.append(f'🤝 Bạn trong nhóm: {len(friends_in_group)} bạn')
        if desc:
            lines.append(f'📝 Giới thiệu: {desc}')
        if warning_text:
            lines.append(f' Cảnh báo: {warning_text}')
        if requires_approval:
            lines.append(f'🔒 Chế độ duyệt: Cần phê duyệt' + (f" (Câu hỏi: '{question}')" if question else ''))
        else:
            lines.append(f'🔓 Chế độ duyệt: Tham gia tự do')
        lines.append(f'👉 Thao tác: [THAM GIA]')
        formatted_preview = '\n'.join(lines)
        return {'success': bool(res_gid or http_data or (sock_res and sock_res.get('sent'))), 'group_id': int(res_gid) if res_gid else None, 'name': name, 'desc': desc, 'avatar': avatar, 'creator_name': creator_name, 'creator_id': creator_id, 'created_time': created_time, 'created_time_str': created_time_str, 'created_date_str': created_date_str, 'total_member': total_member, 'friends_in_group': friends_in_group, 'warning_text': warning_text, 'is_community': is_community, 'requires_approval': requires_approval, 'question': question, 'link_url': link_full, 'link_code': link_code, 'formatted_preview': formatted_preview, 'raw_data': http_data or sock_res}
    get_group_preview = preview_group_link
