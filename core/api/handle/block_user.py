import logging
from typing import Union
from core.api.common import BaseAPI
logger = logging.getLogger('core.api.handle.block_user')

class BlockUserAPI(BaseAPI):

    def block_user(self, target_uid: Union[int, str], is_block: bool=True) -> bool:
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning('Socket client chưa kết nối để chặn user.')
            return False
        try:
            return self._socket.block_user(target_uid=target_uid, is_block=is_block)
        except Exception as e:
            logger.error(f'Lỗi chặn user {target_uid}: {e}')
            return False

    def unblock_user(self, target_uid: Union[int, str]) -> bool:
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning('Socket client chưa kết nối để bỏ chặn user.')
            return False
        try:
            return self._socket.unblock_user(target_uid=target_uid)
        except Exception as e:
            logger.error(f'Lỗi bỏ chặn user {target_uid}: {e}')
            return False
