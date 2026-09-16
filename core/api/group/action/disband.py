import logging
from typing import Union, Dict, Any
from core.api.common import BaseAPI
logger = logging.getLogger('core.api.group.action.disband')

class DisbandAPI(BaseAPI):

    def disband_group_242(self, group_id: Union[int, str]) -> bool:
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning('Socket client chưa kết nối để giải tán nhóm.')
            return False
        try:
            fn = getattr(self._socket, 'disband_group', None) or getattr(self._socket, 'disband_group_242', None)
            if fn:
                res = fn(group_id=int(group_id))
                return bool(res if isinstance(res, bool) else res.get('sent', False) if isinstance(res, dict) else bool(res))
            return False
        except Exception as e:
            logger.error(f'Lỗi giải tán nhóm {group_id}: {e}')
            return False

    def send_group_event_1705(self, group_id: Union[int, str], owner_uid: int=0) -> bool:
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning('Socket client chưa kết nối để gửi event 1705.')
            return False
        try:
            fn = getattr(self._socket, 'send_group_event_1705', None)
            if fn:
                res = fn(group_id=int(group_id), owner_uid=owner_uid)
                return bool(res.get('sent', False)) if isinstance(res, dict) else bool(res)
            return False
        except Exception as e:
            logger.error(f'Lỗi gửi event 1705 nhóm {group_id}: {e}')
            return False
    disband_group = disband_group_242
    disband = disband_group_242
