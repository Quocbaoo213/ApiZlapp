import logging
import time
from core.socket.protocol import CMD_BLOCK_USER_1TO1, CMD_UNBLOCK_USER_1TO1, compute_checksum, build_block_user_packet, build_outer_frame
logger = logging.getLogger('core.socket.actions.block_user')

class BlockUserActionMixin:

    def block_user(self, target_uid: int | str, is_block: bool=True) -> bool:
        if not self.is_connected or not self.sock:
            return False
        try:
            t_uid = int(target_uid)
            seq, cmsg, _ = self._get_next_counters()
            cmd = CMD_BLOCK_USER_1TO1 if is_block else CMD_UNBLOCK_USER_1TO1
            ck = compute_checksum(cmd, 0, seq, self.uid, bb=0, ty=1, ver=3)
            inner = build_block_user_packet(uid=self.uid, target_uid=t_uid, is_block=is_block, seq=seq, ck_val=ck)
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f"Đã gửi lệnh {('chặn' if is_block else 'bỏ chặn')} User {t_uid} qua Socket (CMD {cmd} SUB 0)")
            return True
        except Exception as e:
            logger.error(f'Lỗi chặn user: {e}')
            return False

    def unblock_user(self, target_uid: int | str) -> bool:
        return self.block_user(target_uid, is_block=False)
