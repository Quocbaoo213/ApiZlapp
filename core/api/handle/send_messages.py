import logging
from typing import Optional, List, Dict, Any, Union
from core.api.common import BaseAPI
from core.models.enums import ThreadType
logger = logging.getLogger('core.api.handle.send_messages')

class SendMessagesAPI(BaseAPI):

    def send_message(self, thread_id: Union[int, str], text: str, thread_type: Union[ThreadType, int]=ThreadType.GROUP, quote_data: Optional[Dict[str, Any]]=None, mentions: Optional[List[Dict[str, Any]]]=None, style_id: Optional[int]=None, size: Optional[int]=None, color: Optional[str]=None, bold: bool=False, italic: bool=False, underline: bool=False, strike: bool=False, fontsize: Optional[int]=None, list_type: Optional[int]=None, ttl: int=0) -> bool:
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning('Socket client chưa kết nối để gửi tin nhắn.')
            return False
        t_id = int(thread_id)
        is_group = thread_type == ThreadType.GROUP or thread_type in ('group', 'GROUP', 2, 4)
        try:
            if is_group:
                return self._socket.send_group_message(group_id=t_id, text=text, ttl=ttl, quote_data=quote_data, mentions=mentions, style_id=style_id, size=size, color=color, bold=bold, italic=italic, underline=underline, strike=strike, fontsize=fontsize, list_type=list_type)
            else:
                return self._socket.send_1to1_message(to_uid=t_id, text=text, ttl=ttl, quote_data=quote_data, mentions=mentions, style_id=style_id, size=size, color=color, bold=bold, italic=italic, underline=underline, strike=strike, fontsize=fontsize, list_type=list_type)
        except Exception as e:
            logger.error(f'[!] Lỗi khi gửi tin nhắn tới {t_id}: {e}')
            return False

    def send_group_message(self, group_id: Union[int, str], text: str, **kwargs) -> bool:
        return self.send_message(thread_id=group_id, text=text, thread_type=ThreadType.GROUP, **kwargs)

    def send_1to1_message(self, to_uid: Union[int, str], text: str, **kwargs) -> bool:
        return self.send_message(thread_id=to_uid, text=text, thread_type=ThreadType.USER, **kwargs)
