import logging
from typing import Union, List
from core.api.common import BaseAPI
logger = logging.getLogger('core.api.group.action.ban')

class BanAPI(BaseAPI):

    def block_group_member(self, group_id: Union[int, str], member_uids: Union[int, str, List[Union[int, str]]]) -> bool:
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning('Socket client chưa kết nối để block thành viên nhóm.')
            return False
        try:
            if hasattr(self._socket, 'block_group_member'):
                return self._socket.block_group_member(group_id=int(group_id), member_uids=member_uids)
            return self._socket.kick_member(group_id=int(group_id), member_uids=member_uids, is_block=True)
        except Exception as e:
            logger.error(f'[!] Lỗi block thành viên khỏi nhóm {group_id}: {e}')
            return False

    def ban_member(self, group_id: Union[int, str], member_uids: Union[int, str, List[Union[int, str]]]) -> bool:
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning('Socket client chưa kết nối để ban thành viên nhóm.')
            return False
        try:
            return self._socket.kick_member(group_id=int(group_id), member_uids=member_uids, is_block=True)
        except Exception as e:
            logger.error(f'[!] Lỗi ban thành viên khỏi nhóm {group_id}: {e}')
            return False
