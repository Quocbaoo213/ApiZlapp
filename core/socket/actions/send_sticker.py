import logging
from typing import Optional, Union, Dict, Any
from core.socket.protocol import build_sticker_attach
logger = logging.getLogger('core.socket.actions.send_sticker')

class SendStickerActionMixin:

    def send_sticker(self, target_id: int, cat_id: Union[int, str], sticker_id: Union[int, str], is_group: bool=True, sticker_type: int=7, ttl_ms: int=0, ttl: Optional[int]=None, quote_data: Optional[dict]=None, thread_type: Optional[Any]=None, **kwargs) -> bool:
        if thread_type is not None:
            is_group = thread_type == 2 or thread_type == 4 or str(thread_type).lower() in ('group', 'threadtype.group')
        attach_obj = build_sticker_attach(cat_id=cat_id, sticker_id=sticker_id, sticker_type=sticker_type)
        if is_group:
            return self.send_group_message(group_id=target_id, text='', ttl_ms=ttl_ms, ttl=ttl, quote_data=quote_data, attach=attach_obj, **kwargs)
        else:
            return self.send_1to1_message(target_uid=target_id, text='', ttl_ms=ttl_ms, ttl=ttl, quote_data=quote_data, attach=attach_obj, **kwargs)

    def send_group_sticker(self, group_id: int, cat_id: Union[int, str], sticker_id: Union[int, str], sticker_type: int=7, ttl_ms: int=0, ttl: Optional[int]=None, quote_data: Optional[dict]=None, **kwargs) -> bool:
        return self.send_sticker(target_id=group_id, cat_id=cat_id, sticker_id=sticker_id, is_group=True, sticker_type=sticker_type, ttl_ms=ttl_ms, ttl=ttl, quote_data=quote_data, **kwargs)

    def send_1to1_sticker(self, target_uid: int, cat_id: Union[int, str], sticker_id: Union[int, str], sticker_type: int=7, ttl_ms: int=0, ttl: Optional[int]=None, quote_data: Optional[dict]=None, **kwargs) -> bool:
        return self.send_sticker(target_id=target_uid, cat_id=cat_id, sticker_id=sticker_id, is_group=False, sticker_type=sticker_type, ttl_ms=ttl_ms, ttl=ttl, quote_data=quote_data, **kwargs)

    sendSticker = send_sticker
