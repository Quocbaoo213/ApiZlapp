import re
import json
import time
import logging
import urllib.request
import urllib.parse
from typing import Union, Optional, Tuple, Dict, Any, List
from core.api.common import BaseAPI
from core.utils.helpers import sign_params, API_KEY, CLIENT_TYPE, CLIENT_VERSION, USER_AGENT
logger = logging.getLogger('core.api.group.info')

class GroupInfoAPI(BaseAPI):

    def __init__(self, session_path: Optional[Union[str, Dict[str, Any]]]=None, socket_client=None):
        super().__init__(session_path=session_path, socket_client=socket_client)
        self._groups_cache: List[Dict[str, Any]] = []
        self._last_groups_fetch: float = 0.0

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
        if link_code:
            cached_groups = self._groups_cache or self.get_all_groups()
            for g in cached_groups:
                link_info = (g.get('extraInfo') or {}).get('groupLinkInfo') or {}
                l_url = link_info.get('link') or ''
                if link_code in l_url:
                    gid_val = g.get('groupId')
                    if gid_val:
                        return int(gid_val)
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
        matching_group = None
        if link_code:
            cached_groups = self._groups_cache or self.get_all_groups()
            for g in cached_groups:
                link_info = (g.get('extraInfo') or {}).get('groupLinkInfo') or {}
                l_url = link_info.get('link') or ''
                if link_code in l_url:
                    matching_group = g
                    break
        sock_res = None
        if self._socket and getattr(self._socket, 'is_connected', False):
            try:
                if hasattr(self._socket, 'preview_link_901') and callable(getattr(self._socket, 'preview_link_901')):
                    res = self._socket.preview_link_901(link_full, wait_response=True, timeout=3.5)
                    if isinstance(res, dict) and (not getattr(res, '_mock_name', None)):
                        sock_res = res
            except Exception as e:
                logger.debug(f'Lỗi preview socket 901: {e}')
        sock_ack = (sock_res.get('ack_result') or {}) if (isinstance(sock_res, dict) and not getattr(sock_res, '_mock_name', None)) else {}
        if not isinstance(sock_ack, dict) or getattr(sock_ack, '_mock_name', None):
            sock_ack = {}
        sock_jd = (sock_ack.get('json_data') or {}) if isinstance(sock_ack, dict) else {}
        if not isinstance(sock_jd, dict) or getattr(sock_jd, '_mock_name', None):
            sock_jd = {}
        sock_item = (sock_jd.get('data') or {}).get('item') if isinstance(sock_jd.get('data'), dict) else (sock_jd.get('item') if isinstance(sock_jd.get('item'), dict) else {})
        if not isinstance(sock_item, dict) or getattr(sock_item, '_mock_name', None):
            sock_item = {}
        sock_ginfo = sock_item.get('ginfo') if isinstance(sock_item, dict) else {}
        if (not sock_ginfo or not isinstance(sock_ginfo, dict) or getattr(sock_ginfo, '_mock_name', None)) and isinstance(sock_res, dict):
            sock_ginfo = sock_res.get('ginfo') or {}
        if not isinstance(sock_ginfo, dict) or getattr(sock_ginfo, '_mock_name', None):
            sock_ginfo = {}
        http_res = self.get_group_info_by_link(link_code) or {}
        http_data = http_res.get('data') if isinstance(http_res.get('data'), dict) else http_res if isinstance(http_res, dict) else {}
        if matching_group and not http_data:
            http_data = matching_group
        res_gid = gid or (sock_res.get('group_id') if (isinstance(sock_res, dict) and not getattr(sock_res.get('group_id'), '_mock_name', None)) else None) or (sock_item.get('gid') if (isinstance(sock_item, dict) and not getattr(sock_item.get('gid'), '_mock_name', None)) else None) or (matching_group.get('groupId') if matching_group else None) or http_data.get('groupId') or http_data.get('grid') or http_data.get('id')
        known_g: Dict[str, Any] = {}
        if res_gid and self._socket and hasattr(self._socket, 'known_groups') and isinstance(getattr(self._socket, 'known_groups', None), dict):
            known_g = self._socket.known_groups.get(str(res_gid), {})
            if not isinstance(known_g, dict) or getattr(known_g, '_mock_name', None):
                known_g = {}
        group_detail = None
        if res_gid:
            if not matching_group:
                group_detail = self.get_group_detail(res_gid)
                if not group_detail:
                    for g in (self._groups_cache or []):
                        if int(g.get('groupId', 0)) == int(res_gid):
                            group_detail = g
                            break
                if not group_detail and (not sock_ginfo or not sock_ginfo.get('name')):
                    try:
                        all_g = self.get_all_groups(force_refresh=True)
                        for g in all_g:
                            if int(g.get('groupId', 0)) == int(res_gid):
                                group_detail = g
                                break
                    except Exception:
                        pass
            else:
                group_detail = matching_group
        name_candidates = [
            sock_ginfo.get('name') if isinstance(sock_ginfo, dict) else None,
            sock_res.get('group_name') if isinstance(sock_res, dict) else None,
            group_detail.get('name') if isinstance(group_detail, dict) else None,
            known_g.get('group_name') if isinstance(known_g, dict) else None,
            known_g.get('name') if isinstance(known_g, dict) else None,
            http_data.get('name') if isinstance(http_data, dict) else None,
            http_data.get('groupName') if isinstance(http_data, dict) else None,
            http_data.get('gname') if isinstance(http_data, dict) else None,
        ]
        name = None
        for cand in name_candidates:
            if cand and isinstance(cand, str) and (not getattr(cand, '_mock_name', None)):
                name = cand
                break
        if not name:
            name = f'Nhóm {res_gid or link_code}'
        creator_id_candidates = [
            sock_ginfo.get('creatorId') if isinstance(sock_ginfo, dict) else None,
            sock_res.get('creator_id') if isinstance(sock_res, dict) else None,
            group_detail.get('creatorId') if isinstance(group_detail, dict) else None,
            group_detail.get('ownerId') if isinstance(group_detail, dict) else None,
            known_g.get('creator_id') if isinstance(known_g, dict) else None,
            http_data.get('creatorId') if isinstance(http_data, dict) else None,
            http_data.get('ownerId') if isinstance(http_data, dict) else None,
            http_data.get('creator_id') if isinstance(http_data, dict) else None,
        ]
        creator_id = 0
        for cand in creator_id_candidates:
            if cand and isinstance(cand, (int, str)) and (not getattr(cand, '_mock_name', None)):
                try:
                    creator_id = int(cand)
                    if creator_id:
                        break
                except (ValueError, TypeError):
                    pass
        current_mems = (sock_ginfo.get('currentMems') if isinstance(sock_ginfo, dict) else None) or (sock_res.get('current_mems') if isinstance(sock_res, dict) else None) or known_g.get('current_mems') or []
        admins = (group_detail.get('admins') if isinstance(group_detail, dict) else None) or (sock_ginfo.get('admins') if isinstance(sock_ginfo, dict) else None) or (sock_res.get('admins') if isinstance(sock_res, dict) else None) or known_g.get('admins') or http_data.get('admins') or []
        admin_names = [a.get('dName', str(a.get('id', ''))) for a in admins if isinstance(a, dict) and a.get('dName') and isinstance(a.get('dName'), str) and (not getattr(a.get('dName'), '_mock_name', None))]
        creator_name = ''
        if creator_id and isinstance(current_mems, list):
            for m in current_mems:
                if isinstance(m, dict) and int(m.get('id', 0)) == int(creator_id) and m.get('dName') and isinstance(m.get('dName'), str) and (not getattr(m.get('dName'), '_mock_name', None)):
                    creator_name = m['dName']
                    break
        if not creator_name and creator_id and isinstance(admins, list):
            for a in admins:
                if isinstance(a, dict) and int(a.get('id', 0)) == int(creator_id) and a.get('dName') and isinstance(a.get('dName'), str) and (not getattr(a.get('dName'), '_mock_name', None)):
                    creator_name = a['dName']
                    break
        if not creator_name:
            c_cand = http_data.get('creatorName') or http_data.get('ownerName') or http_data.get('creator_name') or known_g.get('creator_name') or ''
            if c_cand and isinstance(c_cand, str) and (not getattr(c_cand, '_mock_name', None)):
                creator_name = c_cand
        if (not creator_name or creator_name == 'Trưởng nhóm') and creator_id:
            try:
                from core.api.user import UserAPI
                u_api = UserAPI(self.session_path)
                prof = u_api.get_user_profile(creator_id)
                if prof and prof.display_name and isinstance(prof.display_name, str) and (not prof.display_name.startswith('Thành viên ')):
                    creator_name = prof.display_name
            except Exception:
                pass
        if not creator_name:
            creator_name = 'Trưởng nhóm'
        total_member_candidates = [
            sock_ginfo.get('totalMembers') if isinstance(sock_ginfo, dict) else None,
            sock_res.get('total_member') if isinstance(sock_res, dict) else None,
            group_detail.get('totalMembers') if isinstance(group_detail, dict) else None,
            known_g.get('total_member') if isinstance(known_g, dict) else None,
            http_data.get('totalMember') if isinstance(http_data, dict) else None,
            http_data.get('totalMembers') if isinstance(http_data, dict) else None,
            http_data.get('member_count') if isinstance(http_data, dict) else None,
        ]
        total_member = 0
        for cand in total_member_candidates:
            if cand and isinstance(cand, (int, str)) and (not getattr(cand, '_mock_name', None)):
                try:
                    total_member = int(cand)
                    if total_member:
                        break
                except (ValueError, TypeError):
                    pass
        desc_candidates = [
            sock_ginfo.get('desc') if isinstance(sock_ginfo, dict) else None,
            sock_res.get('desc') if isinstance(sock_res, dict) else None,
            group_detail.get('desc') if isinstance(group_detail, dict) else None,
            known_g.get('desc') if isinstance(known_g, dict) else None,
            http_data.get('desc') if isinstance(http_data, dict) else None,
            http_data.get('description') if isinstance(http_data, dict) else None,
        ]
        desc = ''
        for cand in desc_candidates:
            if cand and isinstance(cand, str) and (not getattr(cand, '_mock_name', None)):
                desc = cand
                break
        avatar_candidates = [
            sock_ginfo.get('fullAvt') if isinstance(sock_ginfo, dict) else None,
            sock_ginfo.get('avt') if isinstance(sock_ginfo, dict) else None,
            sock_res.get('avatar') if isinstance(sock_res, dict) else None,
            group_detail.get('fullAvt') if isinstance(group_detail, dict) else None,
            group_detail.get('avt') if isinstance(group_detail, dict) else None,
            known_g.get('avatar') if isinstance(known_g, dict) else None,
            http_data.get('avt') if isinstance(http_data, dict) else None,
            http_data.get('avatar') if isinstance(http_data, dict) else None,
        ]
        avatar = ''
        for cand in avatar_candidates:
            if cand and isinstance(cand, str) and (not getattr(cand, '_mock_name', None)):
                avatar = cand
                break
        setting_data = (sock_ginfo.get('setting') if isinstance(sock_ginfo, dict) else None) or (group_detail.get('setting') if isinstance(group_detail, dict) else None) or (sock_res.get('setting') if isinstance(sock_res, dict) else None) or http_data.get('setting') or {}
        is_community = bool(http_data.get('isCommunity') or http_data.get('is_community') or http_data.get('community') or (group_detail.get('type') == 2 if group_detail else False))
        requires_approval = bool(isinstance(setting_data, dict) and setting_data.get('joinAppr') or http_data.get('requireApproval') or http_data.get('needApprove'))
        question = sock_ginfo.get('joinQuestion') or (group_detail.get('joinQuestion') if group_detail else None) or http_data.get('question') or http_data.get('joinQuestion') or ''
        created_time = (group_detail.get('createTime') if group_detail else None) or http_data.get('createdTime') or http_data.get('created_time') or http_data.get('createdDate') or 0
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
        lines = [f'[{type_str.upper()} ZALO] {name}', f'Liên kết: {link_full}']
        if res_gid:
            lines.append(f'Group ID: {res_gid}')
        if creator_name and creator_name != 'Trưởng nhóm':
            lines.append(f'{type_str} của: {creator_name}' + (f' (UID: {creator_id})' if creator_id else ''))
        elif creator_id:
            lines.append(f'{type_str} của: UID {creator_id}')
        else:
            lines.append(f'{type_str} của: Trưởng nhóm')
        if admin_names:
            lines.append(f'Phó nhóm: {", ".join(admin_names)}')
        if total_member:
            lines.append(f'Số thành viên: {total_member}')
        if friends_in_group:
            lines.append(f'Bạn bè trong nhóm: {len(friends_in_group)} bạn')
        if desc:
            lines.append(f'Giới thiệu: {desc}')
        if created_time_str:
            lines.append(f'Tạo lúc: {created_time_str}' + (f' ({created_date_str})' if created_date_str else ''))
        elif created_date_str:
            lines.append(f'Đã tạo ngày: {created_date_str}')
        if warning_text:
            lines.append(f'Cảnh báo: {warning_text}')
        if requires_approval:
            lines.append(f'Chế độ duyệt: Cần phê duyệt' + (f" (Câu hỏi: '{question}')" if question else ''))
        else:
            lines.append(f'Chế độ duyệt: Tham gia tự do')
        lines.append(f'Thao tác: [THAM GIA]')
        formatted_preview = '\n'.join(lines)
        if res_gid and self._socket and hasattr(self._socket, 'known_groups'):
            kg_rec = self._socket.known_groups.get(str(res_gid), {})
            kg_rec['group_id'] = int(res_gid)
            kg_rec['name'] = name
            kg_rec['group_name'] = name
            kg_rec['creator_id'] = creator_id
            kg_rec['creator_name'] = creator_name
            kg_rec['total_member'] = total_member
            kg_rec['desc'] = desc
            kg_rec['avatar'] = avatar
            kg_rec['admins'] = admins
            kg_rec['admin_names'] = admin_names
            kg_rec['link_code'] = link_code
            kg_rec['link_url'] = link_full
            kg_rec['ts'] = time.time()
            self._socket.known_groups[str(res_gid)] = kg_rec
        return {'success': bool(res_gid or http_data or (sock_res and sock_res.get('sent'))), 'group_id': int(res_gid) if res_gid else None, 'name': name, 'desc': desc, 'avatar': avatar, 'creator_name': creator_name, 'creator_id': creator_id, 'admins': admins, 'admin_names': admin_names, 'created_time': created_time, 'created_time_str': created_time_str, 'created_date_str': created_date_str, 'total_member': total_member, 'friends_in_group': friends_in_group, 'warning_text': warning_text, 'is_community': is_community, 'requires_approval': requires_approval, 'question': question, 'link_url': link_full, 'link_code': link_code, 'formatted_preview': formatted_preview, 'raw_data': http_data or sock_res}
    get_group_preview = preview_group_link

    def get_group_list(self, page: int=1, last_group_id: Union[int, str]=0, avatar_size: int=160) -> Optional[Dict[str, Any]]:
        sess = self._load_session()
        if not sess:
            return None
        p: Dict[str, Any] = {
            'api_key': API_KEY,
            'session_key': sess['session_key'],
            'sign': sess['sign'],
            'ts': str(int(time.time())),
            'clientType': CLIENT_TYPE,
            'clientVersion': CLIENT_VERSION,
            'client_type': CLIENT_TYPE,
            'client_version': sess.get('app_version') or '23.08.01',
            'last_group_id': str(last_group_id or 0),
            'avatar_size': str(avatar_size),
            'page': str(page)
        }
        p['sig'] = sign_params(p)
        try:
            url = f'https://group.api.zaloapp.com/group/list?{urllib.parse.urlencode(p)}'
            req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT, 'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode('utf-8'))
        except Exception as e:
            logger.warning(f'Lỗi tải danh sách nhóm trang {page}: {e}')
        return None

    def get_all_groups(self, force_refresh: bool=False) -> List[Dict[str, Any]]:
        now = time.time()
        if not force_refresh and self._groups_cache and (now - self._last_groups_fetch < 300):
            return list(self._groups_cache)
        all_groups: List[Dict[str, Any]] = []
        page = 1
        last_group_id: Union[int, str] = 0
        while True:
            resp = self.get_group_list(page=page, last_group_id=last_group_id)
            if not resp or resp.get('error_code') != 0:
                break
            data = resp.get('data') or {}
            groups = data.get('data') or data.get('groups') or []
            all_groups.extend(groups)
            has_more = bool(data.get('hasMoreList', False))
            if not has_more or not groups:
                break
            page += 1
            last_group_id = data.get('lastGroupId') or groups[-1].get('groupId') or 0
        self._groups_cache = all_groups
        self._last_groups_fetch = now
        return all_groups

    def get_group_detail(self, group_id: Union[int, str], force_refresh: bool=False) -> Optional[Dict[str, Any]]:
        try:
            gid_int = int(group_id)
        except (ValueError, TypeError):
            return None
        groups = self.get_all_groups(force_refresh=force_refresh)
        for g in groups:
            if int(g.get('groupId', 0)) == gid_int:
                return g
        return None

    @staticmethod
    def format_group_item(group_data: Dict[str, Any]) -> str:
        gid = group_data.get('groupId', 0)
        name = group_data.get('name') or f'Nhóm {gid}'
        total_mems = group_data.get('totalMembers', 0)
        creator_id = group_data.get('creatorId', 0)
        admins = group_data.get('admins') or []
        admin_names = [a.get('dName', str(a.get('id', ''))) for a in admins if isinstance(a, dict)]
        link_info = (group_data.get('extraInfo') or {}).get('groupLinkInfo') or {}
        link_url = link_info.get('link', '')
        lines = [
            f'[THÔNG TIN NHÓM] {name}',
            f'• Group ID: {gid}',
            f'• Thành viên: {total_mems}',
            f'• Người tạo: UID {creator_id}'
        ]
        if admin_names:
            lines.append(f'• Phó nhóm: {", ".join(admin_names)}')
        if link_url:
            lines.append(f'• Liên kết: {link_url}')
        return '\n'.join(lines)

    format_created_time = format_relative_created_time
    format_group = format_group_item
    preview = preview_group_link
    preview_group = preview_group_link
    resolve_group_id = resolve_group_id_from_link
    list_groups = get_group_list
    get_group = get_group_detail
