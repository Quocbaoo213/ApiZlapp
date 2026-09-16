import logging
from typing import Union, List
from core.api.common import BaseAPI
logger = logging.getLogger('core.api.group.action.add')

class AddAPI(BaseAPI):

    def add_member(self, group_id: Union[int, str], member_uids: Union[int, str, List[Union[int, str]]], is_invite: bool=False) -> bool:
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning('Socket client chưa kết nối để thêm thành viên.')
            return False
        try:
            return self._socket.add_member(group_id=int(group_id), member_uids=member_uids, is_invite=is_invite)
        except Exception as e:
            logger.error(f'[!] Lỗi thêm thành viên vào nhóm {group_id}: {e}')
            return False

    def invite_member(self, group_id: Union[int, str], member_uids: Union[int, str, List[Union[int, str]]]) -> bool:
        return self.add_member(group_id=group_id, member_uids=member_uids, is_invite=True)
