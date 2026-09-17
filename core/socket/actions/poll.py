import logging
import time
from typing import List, Optional
from core.socket.protocol import build_create_poll_packet, build_outer_frame
logger = logging.getLogger('core.socket.actions.poll')

class PollActionMixin:

    def create_poll(self, group_id: int | str, question: str, options: List[str], expired_time: int=0, multi_choice: bool=True, allow_add_option: bool=True, is_anonymous: bool=False, hide_vote_result: bool=False, allow_share: bool=True) -> bool:
        if not self.is_connected or not self.sock:
            return False
        try:
            gid = int(group_id)
            seq, cmsg, _ = self._get_next_counters()
            inner = build_create_poll_packet(uid=self.uid, group_id=gid, question=question, options=options, expired_time=expired_time, multi_choice=multi_choice, allow_add_option=allow_add_option, is_anonymous=is_anonymous, hide_vote_result=hide_vote_result, allow_share=allow_share, seq=seq, ck_val=0)
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.debug(f"Đã gửi lệnh tạo Poll trong nhóm {gid}: '{question}' ({len(options)} lựa chọn)")
            return True
        except Exception as e:
            logger.error(f'Lỗi khi tạo bình chọn trong nhóm {group_id}: {e}')
            return False
