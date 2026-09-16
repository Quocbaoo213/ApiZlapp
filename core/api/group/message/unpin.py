import logging
from typing import Union
from core.api.common import BaseAPI
logger = logging.getLogger('core.api.group.message.unpin')

class UnpinAPI(BaseAPI):

    def unpin_message(self, group_id: Union[int, str], global_msg_id: Union[int, str]=0, cli_msg_id: Union[int, str]=0) -> bool:
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning('Socket client chưa kết nối để bỏ ghim tin nhắn.')
            return False
        try:
            return self._socket.unpin_message(group_id=int(group_id), global_msg_id=int(global_msg_id or 0), cli_msg_id=int(cli_msg_id or 0))
        except Exception as e:
            logger.error(f'Lỗi khi bỏ ghim tin nhắn trong Group {group_id}: {e}')
            return False
