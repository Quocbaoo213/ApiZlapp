import logging
import time
from core.socket.protocol import build_recall_message_packet, build_delete_message_packet, build_outer_frame
logger = logging.getLogger('core.socket.actions.undo_message')

class UndoMessageActionMixin:

    def recall_message(self, target_id: int | str, global_msg_id: int=0, cli_msg_id: int=0, is_group: bool=True) -> bool:
        if not self.is_connected or not self.sock:
            return False
        try:
            tid = int(target_id)
            seq, cmsg, _ = self._get_next_counters()
            inner = build_recall_message_packet(uid=self.uid, target_id=tid, global_msg_id=int(global_msg_id or 0), cli_msg_id=int(cli_msg_id or 0), is_group=is_group, seq=seq, ck_val=0)
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.debug(f"Đã gửi lệnh thu hồi tin nhắn ({('Group' if is_group else 'User')} ID={tid}, MsgID={global_msg_id or cli_msg_id})")
            return True
        except Exception as e:
            logger.error(f'Lỗi khi thu hồi tin nhắn: {e}')
            return False

    def delete_message(self, target_id: int | str, global_msg_id: int=0, cli_msg_id: int=0, owner_id: int=0, is_group: bool=True) -> bool:
        if not self.is_connected or not self.sock:
            return False
        try:
            tid = int(target_id)
            seq, cmsg, _ = self._get_next_counters()
            inner = build_delete_message_packet(uid=self.uid, target_id=tid, global_msg_id=int(global_msg_id or 0), cli_msg_id=int(cli_msg_id or 0), owner_id=int(owner_id or self.uid), is_group=is_group, seq=seq, ck_val=0)
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.debug(f"Đã gửi lệnh xóa tin nhắn ({('Group' if is_group else 'User')} ID={tid}, MsgID={global_msg_id or cli_msg_id})")
            return True
        except Exception as e:
            logger.error(f'Lỗi khi xóa tin nhắn: {e}')
            return False
