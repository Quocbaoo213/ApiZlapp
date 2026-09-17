import logging
import time
from typing import Optional, Union, Dict, Any
from core.socket.protocol import SUB_STICKER_MSG, build_outer_frame
from core.socket.tcp.send_sticker import build_sticker_message_packet
logger = logging.getLogger('core.socket.actions.send_sticker')

class SendStickerActionMixin:

    def send_sticker(self, target_id: int, cat_id: Union[int, str], sticker_id: Union[int, str], is_group: bool=True, sticker_type: int=7, text: str='', ttl_ms: int=0, ttl: Optional[int]=None, quote_data: Optional[dict]=None, thread_type: Optional[Any]=None, sub_type: int=SUB_STICKER_MSG, **kwargs) -> bool:
        if thread_type is not None:
            is_group = thread_type == 2 or thread_type == 4 or str(thread_type).lower() in ('group', 'threadtype.group')
        if ttl is not None and ttl_ms == 0:
            ttl_ms = ttl * 1000 if ttl < 100000 else ttl
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            inner = build_sticker_message_packet(uid=self.uid, target_id=int(target_id), cat_id=cat_id, sticker_id=sticker_id, seq=seq, cmsg_id=cmsg, is_group=is_group, sticker_type=sticker_type, text=text, ttl_ms=ttl_ms, quote_data=quote_data, cryptkey=self.cryptkey if not is_group else None, sub_type=sub_type)
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            return True
        except Exception as e:
            logger.error(f'Lỗi gửi sticker tới {target_id}: {e}')
            return False

    def send_group_sticker(self, group_id: int, cat_id: Union[int, str], sticker_id: Union[int, str], sticker_type: int=7, text: str='', ttl_ms: int=0, ttl: Optional[int]=None, quote_data: Optional[dict]=None, **kwargs) -> bool:
        return self.send_sticker(target_id=group_id, cat_id=cat_id, sticker_id=sticker_id, is_group=True, sticker_type=sticker_type, text=text, ttl_ms=ttl_ms, ttl=ttl, quote_data=quote_data, **kwargs)

    def send_1to1_sticker(self, target_uid: int, cat_id: Union[int, str], sticker_id: Union[int, str], sticker_type: int=7, text: str='', ttl_ms: int=0, ttl: Optional[int]=None, quote_data: Optional[dict]=None, **kwargs) -> bool:
        return self.send_sticker(target_id=target_uid, cat_id=cat_id, sticker_id=sticker_id, is_group=False, sticker_type=sticker_type, text=text, ttl_ms=ttl_ms, ttl=ttl, quote_data=quote_data, **kwargs)

    sendSticker = send_sticker
