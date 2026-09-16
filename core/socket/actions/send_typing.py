import logging
import time
from core.socket.protocol import CMD_GROUP_TYPING, CMD_1TO1_TYPING, SUB_GROUP_TYPING, compute_checksum, build_typing_packet, build_outer_frame
logger = logging.getLogger('core.socket.actions.send_typing')

class SendTypingActionMixin:

    def send_typing(self, target_id: int, is_group: bool=True) -> bool:
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            cmd = CMD_GROUP_TYPING if is_group else CMD_1TO1_TYPING
            tt = 3
            ck = compute_checksum(cmd, SUB_GROUP_TYPING, seq, self.uid, target=int(target_id), target_type=tt, cmsg=cmsg, bb=1, ty=2, ver=3)
            inner = build_typing_packet(self.uid, int(target_id), is_group, seq, ck, cmsg)
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            return True
        except Exception as e:
            logger.error(f'Lỗi gửi typing: {e}')
            return False
