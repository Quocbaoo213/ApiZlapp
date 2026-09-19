import logging
import time
from typing import Union, Dict, Any
from core.socket.protocol import build_pin_topic_packet, build_unpin_topic_packet, build_fetch_pinned_topics_packet, build_outer_frame
logger = logging.getLogger('core.socket.actions.pin_topic')

class PinTopicActionMixin:

    def pin_message(self, group_id: int, title: str='', cli_msg_id: int=0, global_msg_id: int=0, sender_name: str='Member', sender_uid: int=0) -> bool:
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            inner = build_pin_topic_packet(uid=self.uid, group_id=int(group_id), title=title, cli_msg_id=int(cli_msg_id or 0), global_msg_id=int(global_msg_id or 0), sender_name=sender_name, sender_uid=int(sender_uid or 0), seq=seq, ck_val=0)
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.debug(f'Đã gửi yêu cầu ghim tin nhắn (GID={group_id}, MsgID={global_msg_id or cli_msg_id}) qua Socket (CMD 1752 SUB 2)')
            return True
        except Exception as e:
            logger.error(f'Lỗi ghim tin nhắn: {e}')
            return False

    def unpin_message(self, group_id: int | str, topic_id: int=0, global_msg_id: int=0, cli_msg_id: int=0) -> bool:
        if not self.is_connected or not self.sock:
            return False
        try:
            gid = int(group_id)
            seq, cmsg, _ = self._get_next_counters()
            tid = int(topic_id or global_msg_id or 0)
            inner = build_unpin_topic_packet(uid=self.uid, group_id=gid, topic_id=tid, global_msg_id=tid, cli_msg_id=int(cli_msg_id or 0), seq=seq, ck_val=0)
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.debug(f'Đã gửi yêu cầu bỏ ghim tin nhắn (GID={gid}, TopicID={tid}) qua Socket (CMD 1708 SUB 0)')
            return True
        except Exception as e:
            logger.error(f'Lỗi bỏ ghim tin nhắn: {e}')
            return False

    def fetch_pinned_topics(self, group_id: int | str, wait_response: bool=True, timeout: float=3.0) -> Union[bool, Dict[str, Any]]:
        if not self.is_connected or not self.sock:
            return {'sent': False, 'error': 'Not connected'} if wait_response else False
        try:
            gid = int(group_id)
            seq, cmsg, _ = self._get_next_counters()
            inner = build_fetch_pinned_topics_packet(uid=self.uid, group_id=gid, seq=seq, ck_val=0)
            outer = build_outer_frame(inner, self.dk)
            if wait_response and hasattr(self, '_prepare_cmd_ack'):
                self._prepare_cmd_ack(1703)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.debug(f'Đã gửi yêu cầu lấy danh sách ghim nhóm {gid} qua Socket (CMD 1703 SUB 0)')
            if not wait_response:
                return True
            if hasattr(self, '_wait_cmd_ack'):
                got_ack, ack_res = self._wait_cmd_ack(1703, timeout=timeout)
                if got_ack and ack_res:
                    return ack_res
            else:
                time.sleep(min(timeout, 0.5))
            return {'sent': True, 'group_id': gid, 'status': 'sent'}
        except Exception as e:
            logger.error(f'Lỗi lấy danh sách tin nhắn ghim: {e}')
            return {'sent': False, 'error': str(e)} if wait_response else False
