from typing import Optional, Dict, Any
from core.models.enums import ThreadType
from core.models.message import Quote

class MessageAPI:

    def __init__(self, socket_client):
        self._socket = socket_client

    def send(self, target_id: int, text: str, thread_type: ThreadType=ThreadType.GROUP, ttl_seconds: int=0, quote: Optional[Quote | Dict[str, Any]]=None) -> bool:
        if not self._socket or not self._socket.is_connected:
            raise ConnectionError('Socket chưa được kết nối.')
        ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
        q_dict = quote.to_dict() if isinstance(quote, Quote) else quote
        if thread_type == ThreadType.GROUP or thread_type == 'group':
            return self.send_group(group_id=target_id, text=text, ttl_seconds=ttl_seconds, quote=quote)
        else:
            return self.send_1to1(target_uid=target_id, text=text, ttl_seconds=ttl_seconds, quote=quote)

    def send_group(self, group_id: int, text: str, ttl_seconds: int=0, quote: Optional[Quote | Dict[str, Any]]=None) -> bool:
        if not self._socket or not self._socket.is_connected:
            raise ConnectionError('Socket chưa được kết nối.')
        ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
        q_dict = quote.to_dict() if isinstance(quote, Quote) else quote
        return self._socket.send_group_message(group_id=group_id, text=text, ttl_ms=ttl_ms, quote_data=q_dict)

    def send_1to1(self, target_uid: int, text: str, ttl_seconds: int=0, quote: Optional[Quote | Dict[str, Any]]=None) -> bool:
        if not self._socket or not self._socket.is_connected:
            raise ConnectionError('Socket chưa được kết nối.')
        ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
        q_dict = quote.to_dict() if isinstance(quote, Quote) else quote
        return self._socket.send_1to1_message(target_uid=target_uid, text=text, ttl_ms=ttl_ms, quote_data=q_dict)

    def send_styled(self, target_uid: int, text: str, color: Optional[str]=None, bold: bool=False, italic: bool=False, underline: bool=False, strike: bool=False, fontsize: Optional[int]=None, style_id: Optional[int]=None, ttl_seconds: int=0, quote: Optional[Quote | Dict[str, Any]]=None) -> bool:
        if not self._socket or not self._socket.is_connected:
            raise ConnectionError('Socket chưa được kết nối.')
        ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
        q_dict = quote.to_dict() if isinstance(quote, Quote) else quote
        return self._socket.send_1to1_message(target_uid=target_uid, text=text, ttl_ms=ttl_ms, quote_data=q_dict, style_id=style_id, color=color, bold=bold, italic=italic, underline=underline, strike=strike, fontsize=fontsize)

    def send_typing(self, target_id: int, is_group: bool=True) -> bool:
        if not self._socket:
            return False
        return self._socket.send_typing(target_id=target_id, is_group=is_group)

    def send_sticker(self, target_id: int, cat_id: int | str, sticker_id: int | str, thread_type: ThreadType=ThreadType.GROUP, sticker_type: int=7, ttl_seconds: int=0, quote: Optional[Quote | Dict[str, Any]]=None, **kwargs) -> bool:
        if not self._socket or not self._socket.is_connected:
            raise ConnectionError('Socket chưa được kết nối.')
        ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
        q_dict = quote.to_dict() if isinstance(quote, Quote) else quote
        is_grp = thread_type == ThreadType.GROUP or thread_type == 'group'
        return self._socket.send_sticker(target_id=target_id, cat_id=cat_id, sticker_id=sticker_id, is_group=is_grp, sticker_type=sticker_type, ttl_ms=ttl_ms, quote_data=q_dict, **kwargs)

    def send_group_sticker(self, group_id: int, cat_id: int | str, sticker_id: int | str, sticker_type: int=7, ttl_seconds: int=0, quote: Optional[Quote | Dict[str, Any]]=None, **kwargs) -> bool:
        return self.send_sticker(target_id=group_id, cat_id=cat_id, sticker_id=sticker_id, thread_type=ThreadType.GROUP, sticker_type=sticker_type, ttl_seconds=ttl_seconds, quote=quote, **kwargs)

    def send_1to1_sticker(self, user_id: int, cat_id: int | str, sticker_id: int | str, sticker_type: int=7, ttl_seconds: int=0, quote: Optional[Quote | Dict[str, Any]]=None, **kwargs) -> bool:
        return self.send_sticker(target_id=user_id, cat_id=cat_id, sticker_id=sticker_id, thread_type=ThreadType.USER, sticker_type=sticker_type, ttl_seconds=ttl_seconds, quote=quote, **kwargs)

    sendSticker = send_sticker
