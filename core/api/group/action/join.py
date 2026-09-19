import logging
from typing import Union, Dict, Any, Optional
from core.api.common import BaseAPI
from core.api.group.info import GroupInfoAPI
logger = logging.getLogger('core.api.group.action.join')

class JoinAPI(BaseAPI):
    parse_group_target = staticmethod(GroupInfoAPI.parse_group_target)

    def join_group_by_id(self, group_id: Union[int, str], msg: str='', source: int=1) -> Dict[str, Any]:
        gid = int(group_id)
        socket_sent = False
        if self._socket and getattr(self._socket, 'is_connected', False):
            try:
                s1 = self._socket.join_group(group_id=gid, source=source)
                s2 = self._socket.request_join_group(group_id=gid, link_url='', msg=msg, source=source)
                socket_sent = bool(s1 or s2)
            except Exception as e:
                logger.warning(f'Lỗi gửi socket join group by id: {e}')
        res_http = self._call_group_api('join', {'grid': gid, 'groupId': gid}) if hasattr(self, '_call_group_api') else None
        return {'success': socket_sent or bool(res_http and res_http.get('error_code') == 0), 'type': 'id', 'group_id': gid, 'status': 'Đã gửi yêu cầu tham gia nhóm qua ID thành công' if socket_sent or res_http else 'Gửi yêu cầu thất bại', 'socket_sent': socket_sent}

    def join_group_by_link(self, link_or_code: str, msg: str='', source: int=1, group_id: Union[int, str]=0) -> Dict[str, Any]:
        raw = str(link_or_code).strip()
        m_code = None
        if hasattr(self, 'parse_group_target'):
            _, _, m_code = self.parse_group_target(raw)
        link_code = m_code or (raw.split('zalo.me/g/')[-1].split('?')[0].strip() if 'zalo.me/g/' in raw else raw)
        link_full = f'https://zalo.me/g/{link_code}' if not raw.startswith('http') else raw
        gid = 0
        if group_id:
            gid = int(group_id)
        elif hasattr(self, 'parse_group_target'):
            try:
                _, g, _ = self.parse_group_target(raw)
                gid = int(g or 0)
            except Exception:
                gid = 0
        preview_data = None
        socket_sent = False
        res_gid = gid or None
        err_code = None
        err_msg = None
        res_901 = None
        res_244 = None
        if self._socket and getattr(self._socket, 'is_connected', False):
            try:
                res_901 = self._socket.join_group_by_link(link_url=link_full, group_id=gid, msg=msg, source=source, wait_response=True, timeout=3.0)
                if isinstance(res_901, dict):
                    socket_sent = res_901.get('sent', False) or socket_sent
                    res_gid = res_901.get('group_id') or res_gid
                    if res_gid:
                        gid = int(res_gid)
            except Exception as s_err:
                logger.warning(f'Lỗi gửi socket request join group fast path: {s_err}')
        if not gid and hasattr(self, 'preview_group_link'):
            try:
                preview_data = self.preview_group_link(link_full)
                if preview_data and preview_data.get('group_id'):
                    gid = int(preview_data['group_id'])
                    res_gid = gid
            except Exception as e:
                logger.debug(f'Lỗi preview link trước khi join: {e}')
        if not gid and hasattr(self, 'resolve_group_id_from_link'):
            try:
                gid = self.resolve_group_id_from_link(link_full) or 0
                if gid:
                    res_gid = gid
            except Exception:
                gid = 0
        is_pending = False
        if self._socket and getattr(self._socket, 'is_connected', False):
            try:
                res_244 = self._socket.request_join_group(group_id=gid or 0, link_url=link_full, msg=msg, source=source, wait_response=True, timeout=3.0)
                if isinstance(res_244, dict):
                    socket_sent = res_244.get('sent', False) or socket_sent
                    res_gid = res_244.get('group_id') or res_gid
                    ack_res = res_244.get('ack_result') or {}
                    jd = ack_res.get('json_data') or {}
                    data_obj = jd.get('data') or {}
                    if data_obj.get('isPendingList') == 1:
                        is_pending = True
                    if res_244.get('group_error_code'):
                        err_code = res_244['group_error_code']
                        err_msg = res_244.get('error_message')
                if gid:
                    self._socket.join_group(group_id=gid, source=source)
            except Exception as s_err:
                logger.warning(f'Lỗi gửi socket request join group (CMD 244 & 246 & 2000): {s_err}')
        res_http = self._call_group_api('join', {'link': link_full, 'grid': gid or link_full}) if hasattr(self, '_call_group_api') else None
        if not res_gid and res_http and isinstance(res_http, dict):
            data = res_http.get('data') if isinstance(res_http.get('data'), dict) else res_http
            res_gid = data.get('groupId') or data.get('grid') or data.get('id')
        has_gid = bool(res_gid or gid)
        is_already_member = bool(err_code in (17009, 18004))
        is_success = bool(has_gid and (is_already_member or socket_sent or (res_http and res_http.get('error_code') == 0))) and (not (err_code and err_code not in (0, 17009, 18004)))
        if not has_gid:
            status_text = 'Không thể phân giải Group ID từ liên kết (liên kết có thể đã hết hạn hoặc bị thu hồi)'
        elif is_already_member:
            status_text = 'Tài khoản đã là thành viên của nhóm này rồi (18004)'
        elif is_pending:
            status_text = 'Nhóm đang bật phê duyệt thành viên. Đã gửi yêu cầu tham gia vào danh sách chờ duyệt'
        else:
            status_text = err_msg if err_msg else 'Đã tham gia nhóm thành công qua liên kết' if is_success else 'Gửi yêu cầu thất bại'
        sock_res_ret = res_244 if isinstance(res_244, dict) else (res_901 if isinstance(res_901, dict) else None)
        out = {'success': is_success, 'type': 'link', 'link': link_full, 'link_code': link_code, 'status': status_text, 'error_code': err_code, 'error_message': err_msg, 'socket_sent': bool(socket_sent), 'socket_response': sock_res_ret, 'is_pending': is_pending, 'already_member': is_already_member}
        if res_gid:
            out['group_id'] = int(res_gid)
        if preview_data and preview_data.get('name'):
            out['group_name'] = preview_data['name']
            out['is_community'] = preview_data.get('is_community', False)
            out['requires_approval'] = preview_data.get('requires_approval', False)
        return out

    def join_group(self, target: Union[str, int], msg: str='', source: int=1) -> Dict[str, Any]:
        target_str = str(target).strip()
        t_type, gid, code = self.parse_group_target(target_str) if hasattr(self, 'parse_group_target') else ('unknown', None, None)
        if t_type == 'id' or (gid and (not code)):
            return self.join_group_by_id(gid or int(target_str), msg=msg, source=source)
        if code or 'zalo.me/g/' in target_str:
            return self.join_group_by_link(target_str, msg=msg, source=source, group_id=gid or 0)
        if target_str.isdigit():
            return self.join_group_by_id(int(target_str), msg=msg, source=source)
        return self.join_group_by_link(target_str, msg=msg, source=source)
