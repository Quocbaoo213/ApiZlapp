import logging
from typing import Union, Optional, Dict, Any
from core.api.common import BaseAPI
logger = logging.getLogger('core.api.group.message.pin')

class PinAPI(BaseAPI):

    def pin_message(self, group_id: Union[int, str], title: str='', cli_msg_id: Union[int, str]=0, global_msg_id: Union[int, str]=0, sender_uid: Optional[int]=None, sender_name: str='Bot') -> bool:
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning('Socket client chưa kết nối để ghim tin nhắn.')
            return False
        try:
            return self._socket.pin_message(group_id=int(group_id), title=title, cli_msg_id=int(cli_msg_id or 0), global_msg_id=int(global_msg_id or 0), sender_name=sender_name)
        except Exception as e:
            logger.error(f'[!] Lỗi khi ghim tin nhắn trong Group {group_id}: {e}')
            return False

    def get_pinned_topics(self, group_id: Union[int, str]) -> Dict[str, Any]:
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning('Socket client chưa kết nối để lấy danh sách bài ghim.')
            return {'success': False, 'error': 'Not connected'}
        try:
            res = self._socket.fetch_pinned_topics(group_id=int(group_id), wait_response=True)
            return res if isinstance(res, dict) else {'success': bool(res)}
        except Exception as e:
            logger.error(f'[!] Lỗi lấy danh sách bài ghim: {e}')
            return {'success': False, 'error': str(e)}
