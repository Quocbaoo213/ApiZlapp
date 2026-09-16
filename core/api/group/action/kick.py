import logging
from typing import Union, List
from core.api.common import BaseAPI
logger = logging.getLogger('core.api.group.action.kick')

class KickAPI(BaseAPI):

    def remove_member(self, group_id: Union[int, str], member_uids: Union[int, str, List[Union[int, str]]]) -> bool:
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning('Socket client chưa kết nối để xoá thành viên.')
            return False
        try:
            return bool(self._socket.remove_member(group_id=int(group_id), member_uids=member_uids))
        except Exception as e:
            logger.error(f'Lỗi xoá thành viên khỏi nhóm {group_id}: {e}')
            return False

    def kick_member(self, group_id: Union[int, str], member_uids: Union[int, str, List[Union[int, str]]], is_block: bool=False) -> bool:
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning('Socket client chưa kết nối để kick/xoá thành viên.')
            return False
        try:
            return bool(self._socket.kick_member(group_id=int(group_id), member_uids=member_uids, is_block=is_block))
        except Exception as e:
            logger.error(f'Lỗi kick/ban thành viên khỏi nhóm {group_id}: {e}')
            return False
