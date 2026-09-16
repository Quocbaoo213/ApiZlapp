import os
import json
import logging
from typing import Optional, Dict, Any, Union
from core.utils.helpers import sign_params, API_KEY, API_SECRET, CLIENT_TYPE, CLIENT_VERSION, USER_AGENT
logger = logging.getLogger('core.api.common')

class BaseAPI:

    def __init__(self, session_path: Optional[Union[str, Dict[str, Any]]]=None, socket_client=None):
        self.session_path = session_path
        self._socket = socket_client

    def set_socket_client(self, socket_client):
        self._socket = socket_client

    @property
    def is_connected(self) -> bool:
        return bool(self._socket and getattr(self._socket, 'is_connected', False))

    @property
    def uid(self) -> int:
        if self._socket and getattr(self._socket, 'uid', None):
            return int(self._socket.uid)
        sess = self._load_session()
        return int(sess.get('uid', 0)) if sess else 0

    def _extract_session_fields(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(data, dict):
            return None
        sk = data.get('session_key') or (data.get('data') or {}).get('sessionKey')
        sign = data.get('sign') or ''
        uid = data.get('uid') or (data.get('data') or {}).get('userId') or 0
        cryptkey = data.get('cryptkey') or data.get('secret_key') or ''
        ksid = data.get('ksid') or ''
        if sk:
            return {'session_key': sk, 'sign': sign, 'uid': int(uid), 'cryptkey': cryptkey, 'ksid': ksid}
        return None

    def _load_session(self) -> Optional[Dict[str, Any]]:
        if isinstance(self.session_path, dict):
            return self._extract_session_fields(self.session_path)
        search_paths = []
        if isinstance(self.session_path, str) and self.session_path:
            search_paths.append(self.session_path)
        search_paths.extend([os.path.join(os.getcwd(), 'fresh_session.json'), 'fresh_session.json', os.path.expanduser('~/.zalo/fresh_session.json'), '/root/zalo/fresh_session.json', '/sdcard/Download/Zalo/zm/fresh_session.json', '/sdcard/Download/Zalo/active_session.json'])
        for p in search_paths:
            if p and os.path.exists(p):
                try:
                    with open(p, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        res = self._extract_session_fields(data)
                        if res:
                            return res
                except Exception as ex:
                    logger.warning(f'Lỗi đọc session từ {p}: {ex}')
        return None
