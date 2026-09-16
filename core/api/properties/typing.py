import logging
from typing import Union
from core.api.common import BaseAPI
logger = logging.getLogger('core.api.properties.typing')

class TypingAPI(BaseAPI):

    def set_typing(self, thread_id: Union[int, str], is_group: bool=True) -> bool:
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            return False
        try:
            return self._socket.send_typing_notification(target_id=int(thread_id), is_group=is_group)
        except Exception as e:
            logger.error(f'[!] Lỗi gửi typing notification tới {thread_id}: {e}')
            return False
