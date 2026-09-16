import logging
from typing import Optional, Union, Dict, Any
from core.api.common import BaseAPI
logger = logging.getLogger('core.api.handle.undo_message')

class UndoMessageAPI(BaseAPI):

    def delete_message(self, group_id: Union[int, str], cli_msg_id: Union[int, str], global_msg_id: Union[int, str]='', owner_id: Optional[Union[int, str]]=None, is_group: bool=True, only_me: bool=False) -> bool:
        g_id = int(group_id)
        if self._socket and getattr(self._socket, 'is_connected', False):
            try:
                return self._socket.delete_message(group_id=g_id, cli_msg_id=cli_msg_id, global_msg_id=global_msg_id, owner_id=owner_id, is_group=is_group, only_me=only_me)
            except Exception as e:
                logger.warning(f'Lỗi gửi socket delete message: {e}')
                return False
        logger.warning('Socket client chưa kết nối để xóa tin nhắn.')
        return False

    def recall_message(self, group_id: Union[int, str], cli_msg_id: Union[int, str], global_msg_id: Union[int, str]=0, owner_id: Optional[Union[int, str]]=None, is_group: bool=True) -> bool:
        g_id = int(group_id)
        if self._socket and getattr(self._socket, 'is_connected', False):
            try:
                return self._socket.recall_message(group_id=g_id, cli_msg_id=cli_msg_id, global_msg_id=global_msg_id, owner_id=owner_id, is_group=is_group)
            except Exception as e:
                logger.warning(f'Lỗi gửi socket recall message: {e}')
                return False
        logger.warning('Socket client chưa kết nối để thu hồi tin nhắn.')
        return False
