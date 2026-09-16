import logging
import struct
import time
from typing import Optional, Union, Dict, Any, List
from core.socket.protocol import CMD_GROUP_MSG, SUB_GROUP_MSG, CMD_1TO1_MSG, SUB_1TO1_MSG, compute_checksum, build_group_message_packet, build_1to1_message_packet, build_outer_frame
logger = logging.getLogger('core.socket.actions.send_message')

class SendMessageActionMixin:

    def send_group_message(self, group_id: int, text: str, ttl_ms: int=0, ttl: Optional[int]=None, quote_data: Optional[dict]=None, mentions: Optional[list]=None, style_id: Optional[int]=None, size: Optional[int]=None, color: Optional[str]=None, bold: bool=False, italic: bool=False, underline: bool=False, strike: bool=False, fontsize: Optional[int]=None, list_type: Optional[int]=None, rtf_mode: str='fwd', attach: Optional[Union[dict, str]]=None) -> bool:
        if ttl is not None and ttl_ms == 0:
            ttl_ms = ttl * 1000 if ttl < 100000 else ttl
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(CMD_GROUP_MSG, SUB_GROUP_MSG, seq, self.uid, target=int(group_id), target_type=4, cmsg=cmsg, bb=1, ty=2, ver=3)
            inner = build_group_message_packet(uid=self.uid, group_id=int(group_id), text=text, seq=seq, ck_val=ck, cmsg_id=cmsg, ttl_ms=ttl_ms, quote_data=quote_data, mentions=mentions, style_id=style_id, size=size, color=color, bold=bold, italic=italic, underline=underline, strike=strike, fontsize=fontsize, list_type=list_type, rtf_mode=rtf_mode, attach=attach)
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            return True
        except Exception as e:
            logger.error(f'Lỗi gửi group message: {e}')
            return False

    def send_1to1_message(self, target_uid: int, text: str, ttl_ms: int=0, ttl: Optional[int]=None, quote_data: Optional[dict]=None, style_id: Optional[int]=None, size: Optional[int]=None, color: Optional[str]=None, bold: bool=False, italic: bool=False, underline: bool=False, strike: bool=False, fontsize: Optional[int]=None, list_type: Optional[int]=None, rtf_mode: str='fwd', attach: Optional[Union[dict, str]]=None) -> bool:
        if ttl is not None and ttl_ms == 0:
            ttl_ms = ttl * 1000 if ttl < 100000 else ttl
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(CMD_1TO1_MSG, SUB_1TO1_MSG, seq, self.uid, target=int(target_uid), target_type=3, cmsg=cmsg, bb=1, ty=2, ver=3)
            inner = build_1to1_message_packet(uid=self.uid, target_uid=int(target_uid), text=text, cryptkey=self.cryptkey, seq=seq, ck_val=ck, cmsg_id=cmsg, ttl_ms=ttl_ms, quote_data=quote_data, style_id=style_id, size=size, color=color, bold=bold, italic=italic, underline=underline, strike=strike, fontsize=fontsize, list_type=list_type, rtf_mode=rtf_mode, attach=attach)
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            return True
        except Exception as e:
            logger.error(f'Lỗi gửi 1-1 message: {e}')
            return False

    def set_conversation_ttl(self, target_id: int, ttl_seconds: int, is_group: bool=True) -> bool:
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(2060, 0, seq, self.uid, target=0, target_type=0, cmsg=0, bb=1, ty=0, ver=3)
            target_type_byte = 2 if is_group else 1
            params = bytes([1]) + struct.pack('<I', 0) + struct.pack('<H', 0) + struct.pack('<I', 1) + bytes([target_type_byte]) + struct.pack('<I', int(target_id)) + struct.pack('<Q', int(ttl_seconds))
            inner = struct.pack('<IBBiIBHB', ck, 1, 0, seq, self.uid, 3, 2060, 0) + params
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            return True
        except Exception as e:
            logger.error(f'Lỗi cài đặt TTL: {e}')
            return False
