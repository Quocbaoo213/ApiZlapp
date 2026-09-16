import logging
from typing import Union
from core.api.common import BaseAPI
logger = logging.getLogger('core.api.handle.send_typing')

class SendTypingAPI(BaseAPI):

    def send_typing(self, target_id: Union[int, str], is_group: bool=True) -> bool:
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            return False
        try:
            return self._socket.send_typing(target_id=int(target_id), is_group=is_group)
        except Exception as e:
            logger.error(f'[!] Lỗi gửi typing tới {target_id}: {e}')
            return False
