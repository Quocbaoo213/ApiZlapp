import logging
import time
from typing import Union, Optional, Dict, Any
from core.socket.protocol import build_query_user_profile_151_packet, build_outer_frame

logger = logging.getLogger('core.socket.actions.user_actions')

class UserActionsMixin:

    def query_user_profile_151(self, target_uid: Union[int, str], wait_response: bool=True, timeout: float=6.0) -> Union[bool, Dict[str, Any]]:
        if not self.is_connected or not self.sock:
            return {'sent': False, 'error': 'Not connected'} if wait_response else False
        try:
            t_uid = int(target_uid)
            seq, cmsg, _ = self._get_next_counters()
            seq_raw = seq & 0xffffffff
            seq_i = seq_raw if seq_raw < 0x80000000 else seq_raw - 0x100000000
            inner = build_query_user_profile_151_packet(
                uid=self.uid,
                target_uid=t_uid,
                seq=seq_i,
                ck_val=0,
                vercode=getattr(self, 'vercode', 260802903),
                version=0
            )
            outer = build_outer_frame(inner, self.dk)
            if wait_response:
                self._prepare_cmd_ack(151)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f"Đã gửi yêu cầu tra cứu Profile User {t_uid} qua Socket (CMD 151 SUB 4)")
            if wait_response:
                got_ack, ack_res = self._wait_cmd_ack(151, timeout=timeout)
                return {
                    'sent': True,
                    'got_response': got_ack,
                    'user_id': t_uid,
                    'data': ack_res.get('user_profile') or (ack_res.get('json_data', {}).get('data') if isinstance(ack_res.get('json_data'), dict) else {}),
                    'ack_result': ack_res
                }
            return True
        except Exception as e:
            logger.error(f'Lỗi tra cứu user profile 151: {e}')
            return {'sent': False, 'error': str(e)} if wait_response else False

    query_user_profile = query_user_profile_151
    get_profile = query_user_profile_151
    fetch_profile = query_user_profile_151
