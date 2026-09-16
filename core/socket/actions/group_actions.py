import logging
import time
from typing import Union, Dict, Any, List, Optional
from core.socket.protocol import CMD_REMOVE_MEMBER, CMD_KICK_MEMBER, CMD_ADD_MEMBER, CMD_JOIN_GROUP, SUB_JOIN_GROUP, CMD_JOIN_GROUP_INVITE, SUB_JOIN_GROUP_INVITE, CMD_REQUEST_JOIN_GROUP, SUB_REQUEST_JOIN_GROUP, CMD_LEAVE_GROUP_225, CMD_LEAVE_GROUP_239, CMD_DISBAND_GROUP, compute_checksum, build_outer_frame, build_remove_member_packet, build_kick_member_packet, build_add_member_packet, build_join_group_packet, build_join_group_2000_packet, build_join_group_invite_packet, build_request_join_group_packet, build_preview_link_901_packet, build_query_group_906_packet, build_join_group_by_link_901_packet, build_leave_group_225_packet, build_leave_group_packet, build_cmd_1705_packet, build_disband_242_packet
logger = logging.getLogger('core.socket.actions.group_actions')

class GroupActionsMixin:

    def send_group_event_1705(self, group_id: int, owner_uid: int=0, wait_ack: bool=False, timeout: float=5.0) -> Dict[str, Any]:
        if not self.is_connected or not self.sock:
            return {'sent': False, 'error': 'Socket not connected'}
        try:
            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(1705, 0, seq, self.uid, bb=0, ty=1, ver=3)
            inner = build_cmd_1705_packet(uid=self.uid, group_id=int(group_id), field_8byte=int(owner_uid or 0), seq=seq, ck_val=ck)
            outer = build_outer_frame(inner, self.dk)
            with self.ack_lock:
                self.general_ack_event.clear()
                self.last_ack_result = {}
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            result = {'sent': True, 'group_id': int(group_id), 'owner_uid': int(owner_uid or 0), 'seq': seq}
            if wait_ack:
                got_ack = self.general_ack_event.wait(timeout=timeout)
                with self.ack_lock:
                    result['got_response'] = got_ack
                    result['ack_result'] = dict(self.last_ack_result) if got_ack else None
            return result
        except Exception as e:
            logger.error(f'[!] Lỗi gửi CMD 1705: {e}')
            return {'sent': False, 'error': str(e)}
    send_cmd_1705 = send_group_event_1705

    def disband_group_242(self, group_id: int, wait_response: bool=False, timeout: float=8.0) -> Union[bool, Dict[str, Any]]:
        if not self.is_connected or not self.sock:
            return {'sent': False, 'error': 'Not connected'} if wait_response else False
        try:
            seq, cmsg, _ = self._get_next_counters()
            inner = build_disband_242_packet(uid=self.uid, group_id=int(group_id), seq=seq, ck_val=0, vercode=getattr(self, 'vercode', 260802903))
            outer = build_outer_frame(inner, self.dk)
            if wait_response:
                self._prepare_cmd_ack(CMD_DISBAND_GROUP)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f'[✔] Đã gửi lệnh giải tán Group {group_id} qua Socket (CMD 242 SUB 0, Seq={seq})')
            if wait_response:
                got_ack, ack_res = self._wait_cmd_ack(CMD_DISBAND_GROUP, timeout=timeout)
                status = ack_res.get('status_code', -1) if got_ack else -1
                return {'sent': True, 'got_response': got_ack, 'success': got_ack and status == 0, 'status_code': status, 'ack_result': ack_res}
            return True
        except Exception as e:
            logger.error(f'[!] Lỗi giải tán nhóm: {e}')
            return {'sent': False, 'error': str(e)} if wait_response else False
    disband_group = disband_group_242
    disband = disband_group_242

    def remove_member(self, group_id: int, member_uids: int | str | List[int | str]) -> bool:
        if not self.is_connected or not self.sock:
            return False
        try:
            if isinstance(member_uids, (int, str)):
                uids = [int(member_uids)]
            else:
                uids = [int(u) for u in member_uids]
            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(CMD_REMOVE_MEMBER, 0, seq, self.uid, bb=0, ty=1, ver=3)
            inner = build_remove_member_packet(uid=self.uid, group_id=int(group_id), member_uids=uids, seq=seq, ck_val=ck)
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f'[✔] Đã gửi lệnh xoá {uids} khỏi Group {group_id} (CMD 228)')
            return True
        except Exception as e:
            logger.error(f'[!] Lỗi xoá member: {e}')
            return False

    def kick_member(self, group_id: int, member_uids: int | str | List[int | str], is_block: bool=False) -> bool:
        if not is_block:
            return self.remove_member(group_id=group_id, member_uids=member_uids)
        if not self.is_connected or not self.sock:
            return False
        try:
            if isinstance(member_uids, (int, str)):
                uids = [int(member_uids)]
            else:
                uids = [int(u) for u in member_uids]
            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(CMD_KICK_MEMBER, 0, seq, self.uid, bb=0, ty=1, ver=3)
            inner = build_kick_member_packet(uid=self.uid, group_id=int(group_id), member_uids=uids, is_block=is_block, seq=seq, ck_val=ck)
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f'[✔] Đã gửi lệnh ban (chặn vào lại) thành viên {uids} khỏi Group {group_id} qua Socket (CMD 234)')
            return True
        except Exception as e:
            logger.error(f'[!] Lỗi kick/ban thành viên: {e}')
            return False

    def block_group_member(self, group_id: int, member_uids: int | str | List[int | str]) -> bool:
        return self.kick_member(group_id=group_id, member_uids=member_uids, is_block=True)

    def leave_group(self, group_id: int | str, new_owner_id: int=0, silent: bool=False, block_readd: bool=False, wait_response: bool=False, timeout: float=5.0) -> Union[bool, Dict[str, Any]]:
        if not self.is_connected or not self.sock:
            return {'sent': False, 'error': 'Not connected'} if wait_response else False
        try:
            gid = int(group_id)
            seq_225, _, _ = self._get_next_counters()
            seq_239, _, _ = self._get_next_counters()
            inner_225 = build_leave_group_225_packet(uid=self.uid, group_id=gid, seq=seq_225, ck_val=0, vercode=getattr(self, 'vercode', 260802903))
            outer_225 = build_outer_frame(inner_225, self.dk)
            inner_239 = build_leave_group_packet(uid=self.uid, group_id=gid, new_owner_id=int(new_owner_id) if new_owner_id else 0, is_silent=silent, is_block_readd=block_readd, seq=seq_239, ck_val=0, vercode=getattr(self, 'vercode', 260802903))
            outer_239 = build_outer_frame(inner_239, self.dk)
            if wait_response:
                self._prepare_cmd_ack(CMD_LEAVE_GROUP_225)
                self._prepare_cmd_ack(CMD_LEAVE_GROUP_239)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer_225)
                    self.sock.sendall(outer_239)
            self.last_traffic = time.time()
            logger.info(f'[✔] Đã gửi yêu cầu rời Group {gid} qua Socket (CMD 225 SUB 3 & CMD 239 SUB 1)')
            if wait_response:
                got_ack, ack_res = self._wait_cmd_ack(CMD_LEAVE_GROUP_225, timeout=timeout)
                if not got_ack:
                    got_ack, ack_res = self._wait_cmd_ack(CMD_LEAVE_GROUP_239, timeout=timeout)
                status_code = ack_res.get('status_code', 0 if got_ack else -1) if got_ack else -1
                is_success = got_ack and (status_code == 0 or status_code == -1)
                return {'sent': True, 'got_response': got_ack, 'success': is_success, 'status_code': status_code, 'ack_result': ack_res}
            return True
        except Exception as e:
            logger.error(f'[!] Lỗi rời nhóm: {e}')
            return {'sent': False, 'error': str(e)} if wait_response else False

    def add_member(self, group_id: int, member_uids: int | str | List[int | str], is_invite: bool=False) -> bool:
        if not self.is_connected or not self.sock:
            return False
        try:
            if isinstance(member_uids, (int, str)):
                uids = [int(member_uids)]
            else:
                uids = [int(u) for u in member_uids]
            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(CMD_ADD_MEMBER, 0, seq, self.uid, bb=0, ty=1, ver=3)
            inner = build_add_member_packet(uid=self.uid, group_id=int(group_id), member_uids=uids, is_invite=is_invite, seq=seq, ck_val=ck)
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f'[✔] Đã gửi lệnh thêm thành viên {uids} vào Group {group_id}')
            return True
        except Exception as e:
            logger.error(f'[!] Lỗi thêm thành viên: {e}')
            return False

    def join_group(self, group_id: int | str, source: int=1) -> bool:
        if not self.is_connected or not self.sock:
            return False
        try:
            gid = int(group_id)
            seq, cmsg, _ = self._get_next_counters()
            try:
                inner_2000 = build_join_group_2000_packet(uid=self.uid, group_id=gid, flag_byte=0, seq=seq, ck_val=0, vercode=getattr(self, 'vercode', 260802903))
                outer_2000 = build_outer_frame(inner_2000, self.dk)
                with self.send_lock:
                    if self.sock:
                        self.sock.sendall(outer_2000)
            except Exception as e_2000:
                logger.debug(f'Lỗi gửi CMD 2000 join group: {e_2000}')
            seq2, _, _ = self._get_next_counters()
            ck = compute_checksum(CMD_JOIN_GROUP, SUB_JOIN_GROUP, seq2, self.uid, bb=0, ty=1, ver=3)
            inner = build_join_group_packet(uid=self.uid, group_id=gid, source=source, seq=seq2, ck_val=ck, vercode=getattr(self, 'vercode', 260802903))
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f'[✔] Đã gửi yêu cầu tham gia Group {gid} qua Socket (CMD 2000 & 246)')
            return True
        except Exception as e:
            logger.error(f'[!] Lỗi tham gia nhóm qua socket: {e}')
            return False

    def preview_link_901(self, link_url: str, wait_response: bool=True, timeout: float=6.0) -> Union[bool, Dict[str, Any]]:
        if not self.is_connected or not self.sock:
            return {'sent': False, 'error': 'Not connected'} if wait_response else False
        try:
            link_clean = str(link_url).strip()
            if link_clean.startswith('http'):
                full_url = link_clean
            else:
                full_url = f'https://zalo.me/g/{link_clean}'
            seq, cmsg, _ = self._get_next_counters()
            inner = build_preview_link_901_packet(uid=self.uid, link_url=full_url, seq=seq, ck_val=0, vercode=getattr(self, 'vercode', 260802903))
            outer = build_outer_frame(inner, self.dk)
            if wait_response:
                self._prepare_cmd_ack(901)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f"[✔] Đã gửi yêu cầu Preview link '{link_url}' qua Socket (CMD 901 SUB 3)")
            if wait_response:
                got_ack, ack_res = self._wait_cmd_ack(901, timeout=timeout)
                return {'sent': True, 'got_response': got_ack, 'group_id': ack_res.get('group_id') if got_ack else None, 'ack_result': ack_res}
            return True
        except Exception as e:
            logger.error(f'[!] Lỗi preview link 901: {e}')
            return {'sent': False, 'error': str(e)} if wait_response else False

    def query_group_906(self, group_id: int | str, wait_response: bool=False, timeout: float=5.0) -> Union[bool, Dict[str, Any]]:
        if not self.is_connected or not self.sock:
            return {'sent': False, 'error': 'Not connected'} if wait_response else False
        try:
            seq, cmsg, _ = self._get_next_counters()
            gid = int(group_id)
            inner = build_query_group_906_packet(uid=self.uid, group_id=gid, seq=seq, ck_val=0)
            outer = build_outer_frame(inner, self.dk)
            if wait_response:
                self._prepare_cmd_ack(906)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            if wait_response:
                got_ack, ack_res = self._wait_cmd_ack(906, timeout=timeout)
                return {'sent': True, 'got_response': got_ack, 'ack_result': ack_res}
            return True
        except Exception as e:
            logger.error(f'[!] Lỗi truy vấn nhóm 906: {e}')
            return {'sent': False, 'error': str(e)} if wait_response else False

    def join_group_by_link(self, link_url: str, group_id: int | str=0, msg: str='', source: int=1, wait_response: bool=True, timeout: float=10.0) -> Union[bool, Dict[str, Any]]:
        if not self.is_connected or not self.sock:
            return {'sent': False, 'error': 'Not connected'} if wait_response else False
        try:
            link_clean = str(link_url).strip()
            if link_clean.startswith('http'):
                full_url = link_clean
            else:
                full_url = f'https://zalo.me/g/{link_clean}'
            seq, _, _ = self._get_next_counters()
            inner = build_join_group_by_link_901_packet(uid=self.uid, link_url=full_url, seq=seq)
            outer = build_outer_frame(inner, self.dk)
            if wait_response:
                self._prepare_cmd_ack(901)
                self._prepare_cmd_ack(902)
            groups_before = set(getattr(self, 'known_groups', {}).keys())
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f"[✔] CMD 901 SUB 3: Gửi join nhóm qua link '{full_url}'")
            if not wait_response:
                return True
            got_902, res_902 = self._wait_cmd_ack(902, timeout=timeout)
            result_gid = int(group_id or 0)
            if got_902:
                ec = res_902.get('status_code', -1)
                is_success = ec == 0
                if res_902.get('group_id'):
                    result_gid = int(res_902['group_id'])
                if is_success and (not result_gid):
                    deadline = time.time() + 3.0
                    while time.time() < deadline:
                        time.sleep(0.1)
                        new_groups = set(getattr(self, 'known_groups', {}).keys()) - groups_before
                        if new_groups:
                            result_gid = int(next(iter(new_groups)))
                            break
                logger.info(f"[*] CMD 902: Join {('THÀNH CÔNG' if is_success else 'THẤT BẠI')} (error_code={ec}), GID={result_gid or 'N/A'}")
                return {'sent': True, 'got_response': True, 'success': is_success, 'status_code': ec, 'group_id': result_gid or None, 'cmd': 902, 'ack_result': res_902}
            deadline = time.time() + 2.0
            while time.time() < deadline:
                time.sleep(0.1)
                new_groups = set(getattr(self, 'known_groups', {}).keys()) - groups_before
                if new_groups:
                    result_gid = int(next(iter(new_groups)))
                    break
            got_901, res_901 = (False, {})
            with self.ack_lock:
                if 901 in self.cmd_ack_results:
                    got_901 = True
                    res_901 = self.cmd_ack_results[901]
            ec_901 = res_901.get('status_code', -1) if got_901 else -1
            if got_901 and ec_901 == 0:
                return {'sent': True, 'got_response': True, 'success': True, 'status_code': 0, 'group_id': result_gid or None, 'cmd': 901, 'note': 'Join request gửi OK (ec=0).'}
            return {'sent': True, 'got_response': bool(got_901), 'success': bool(result_gid), 'status_code': ec_901, 'group_id': result_gid or None, 'cmd': 901, 'note': 'Không nhận được CMD 902'}
        except Exception as e:
            logger.error(f'[!] Lỗi join_group_by_link CMD 901: {e}')
            return {'sent': False, 'error': str(e)} if wait_response else False

    def join_group_invite(self, group_id: int | str, inviter_uid: int=0) -> bool:
        if not self.is_connected or not self.sock:
            return False
        try:
            gid = int(group_id)
            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(CMD_JOIN_GROUP_INVITE, SUB_JOIN_GROUP_INVITE, seq, self.uid, bb=0, ty=1, ver=3)
            inner = build_join_group_invite_packet(uid=self.uid, group_id=gid, inviter_uid=inviter_uid, seq=seq, ck_val=ck)
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f'[✔] Đã gửi yêu cầu chấp nhận lời mời Group {gid} qua Socket (CMD 250)')
            return True
        except Exception as e:
            logger.error(f'[!] Lỗi chấp nhận lời mời nhóm qua socket: {e}')
            return False

    def request_join_group(self, group_id: int | str=0, link_url: str='', msg: str='', source: int=1, sub_source: int=0, wait_response: bool=False, timeout: float=8.0) -> Union[bool, Dict[str, Any]]:
        if not self.is_connected or not self.sock:
            return {'sent': False, 'error': 'Not connected'} if wait_response else False
        try:
            gid = int(group_id or 0)
            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(CMD_REQUEST_JOIN_GROUP, SUB_REQUEST_JOIN_GROUP, seq, self.uid, bb=0, ty=1, ver=3)
            inner = build_request_join_group_packet(uid=self.uid, group_id=gid, msg=msg, link_url=link_url, source=source, sub_source=sub_source, seq=seq, ck_val=ck)
            outer = build_outer_frame(inner, self.dk)
            if wait_response:
                self._prepare_cmd_ack(CMD_REQUEST_JOIN_GROUP)
            groups_before = set(getattr(self, 'known_groups', {}).keys())
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f"[✔] Đã gửi yêu cầu tham gia/link Group (GID={gid}, Link='{link_url}') qua Socket (CMD 244 SUB 4)")
            if wait_response:
                got_ack, ack_res = self._wait_cmd_ack(CMD_REQUEST_JOIN_GROUP, timeout=timeout)
                result_gid = ack_res.get('group_id')
                status_code = ack_res.get('status_code', -1) if got_ack else -1
                group_ec = ack_res.get('group_error_code', 0)
                group_msg = ack_res.get('group_error_msg')
                if group_ec and group_ec != 0:
                    is_success = False
                else:
                    is_success = got_ack and status_code == 0
                if is_success and (not result_gid):
                    deadline = time.time() + 3.0
                    while time.time() < deadline:
                        time.sleep(0.1)
                        new_groups = set(getattr(self, 'known_groups', {}).keys()) - groups_before
                        if new_groups:
                            result_gid = int(next(iter(new_groups)))
                            break
                return {'sent': True, 'got_response': got_ack, 'success': is_success, 'status_code': group_ec if group_ec else status_code, 'group_error_code': group_ec, 'error_message': group_msg if group_ec else None, 'ack_result': ack_res, 'group_id': result_gid}
            return True
        except Exception as e:
            logger.error(f'[!] Lỗi gửi yêu cầu tham gia/link nhóm qua socket: {e}')
            return {'sent': False, 'error': str(e)} if wait_response else False

    def request_group_link_info(self, link_url: str, source: int=1, sub_source: int=0, timeout: float=8.0) -> Optional[int]:
        res = self.preview_link_901(link_url=link_url, wait_response=True, timeout=timeout)
        if isinstance(res, dict) and res.get('group_id'):
            return int(res['group_id'])
        res2 = self.request_join_group(group_id=0, link_url=link_url, msg='', source=source, sub_source=sub_source, wait_response=True, timeout=timeout)
        if isinstance(res2, dict) and res2.get('group_id'):
            return int(res2['group_id'])
        return None
