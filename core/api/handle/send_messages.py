import logging
from typing import Optional, List, Dict, Any, Union
from core.api.common import BaseAPI
from core.models.enums import ThreadType
logger = logging.getLogger('core.api.handle.send_messages')

class SendMessagesAPI(BaseAPI):

    def send_message(self, thread_id: Union[int, str, Any] = 0, text: Union[str, Any] = "", thread_type: Union[ThreadType, int, str] = ThreadType.GROUP, quote_data: Optional[Dict[str, Any]] = None, mentions: Optional[List[Dict[str, Any]]] = None, style_id: Optional[int] = None, size: Optional[int] = None, color: Optional[str] = None, bold: bool = False, italic: bool = False, underline: bool = False, strike: bool = False, fontsize: Optional[int] = None, list_type: Optional[int] = None, ttl: int = 0, styles: Optional[List[Dict[str, Any]]] = None, **kwargs) -> bool:
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning('Socket client chưa kết nối để gửi tin nhắn.')
            return False
        if not thread_id and 'target_id' in kwargs:
            thread_id = kwargs.pop('target_id')
        if not text and 'message' in kwargs:
            text = kwargs.pop('message')
        if isinstance(thread_id, dict) or (hasattr(thread_id, 'text') and not isinstance(thread_id, (int, float))):
            thread_id, text = text, thread_id
        elif isinstance(thread_id, str) and not thread_id.isdigit():
            if isinstance(text, int) or (isinstance(text, str) and text.isdigit()):
                thread_id, text = text, thread_id
        if not quote_data and 'quote' in kwargs:
            q_val = kwargs.pop('quote')
            quote_data = q_val.to_dict() if hasattr(q_val, 'to_dict') else (q_val if isinstance(q_val, dict) else None)
        if ttl == 0 and 'ttl_seconds' in kwargs:
            ttl = int(kwargs.pop('ttl_seconds'))
        t_id = int(thread_id)
        is_group = thread_type == ThreadType.GROUP or thread_type in ('group', 'GROUP', 2, 4)
        try:
            if is_group:
                return self._socket.send_group_message(group_id=t_id, text=str(text), ttl=ttl, quote_data=quote_data, mentions=mentions, style_id=style_id, size=size, color=color, bold=bold, italic=italic, underline=underline, strike=strike, fontsize=fontsize, list_type=list_type, styles=styles, **kwargs)
            else:
                return self._socket.send_1to1_message(target_uid=t_id, text=str(text), ttl=ttl, quote_data=quote_data, style_id=style_id, size=size, color=color, bold=bold, italic=italic, underline=underline, strike=strike, fontsize=fontsize, list_type=list_type, styles=styles, **kwargs)
        except Exception as e:
            logger.error(f'Lỗi khi gửi tin nhắn tới {t_id}: {e}')
            return False

    def send_group_message(self, group_id: Union[int, str], text: str, **kwargs) -> bool:
        return self.send_message(thread_id=group_id, text=text, thread_type=ThreadType.GROUP, **kwargs)

    def send_1to1_message(self, to_uid: Union[int, str], text: str, **kwargs) -> bool:
        return self.send_message(thread_id=to_uid, text=text, thread_type=ThreadType.USER, **kwargs)
