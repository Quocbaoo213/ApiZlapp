import logging
from typing import Union
from core.api.common import BaseAPI
logger = logging.getLogger('core.api.group.message.unpin')

class UnpinAPI(BaseAPI):

    def unpin_message(self, group_id: Union[int, str], topic_id: Union[int, str]=0, global_msg_id: Union[int, str]=0, cli_msg_id: Union[int, str]=0, **kwargs) -> bool:
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning('Socket client chưa kết nối để bỏ ghim tin nhắn.')
            return False
        try:
            gid = int(group_id)
            tid = int(topic_id or 0)
            g_msg = int(global_msg_id or 0)
            c_msg = int(cli_msg_id or 0)

            # Nếu topic_id được truyền là global_msg_id hoặc cli_msg_id (> 2^31 - 1), lưu lại để tra cứu và reset topic_id
            target_msg_id = tid if tid > 2147483647 else 0
            if target_msg_id:
                if not g_msg:
                    g_msg = target_msg_id
                tid = 0

            if not tid:
                try:
                    res = self._socket.fetch_pinned_topics(group_id=gid, wait_response=True)
                    topics = (res.get('topics') or res.get('ack_result', {}).get('topics') or []) if isinstance(res, dict) else []
                    for item in topics:
                        item_tid = int(item.get('id') or item.get('topicId') or 0)
                        params = item.get('params') or {}
                        if isinstance(params, str) and params.strip().startswith('{'):
                            try:
                                import json
                                params = json.loads(params)
                            except Exception:
                                pass
                        item_gmi = int(params.get('global_msg_id') or item.get('globalMsgId') or 0)
                        item_cmi = int(params.get('client_msg_id') or item.get('cliMsgId') or 0)
                        if (g_msg and item_gmi == g_msg) or (c_msg and item_cmi == c_msg) or (target_msg_id and (item_gmi == target_msg_id or item_cmi == target_msg_id)):
                            tid = item_tid
                            break
                    if not tid and topics:
                        tid = int(topics[0].get('id') or topics[0].get('topicId') or 0)
                except Exception as ex:
                    logger.debug(f'Tra cứu topic_id từ bài ghim thất bại: {ex}')

            if not tid and (target_msg_id or g_msg):
                tid = target_msg_id or g_msg

            return self._socket.unpin_message(group_id=gid, topic_id=tid, global_msg_id=g_msg or tid, cli_msg_id=c_msg)
        except Exception as e:
            logger.error(f'Lỗi khi bỏ ghim tin nhắn trong Group {group_id}: {e}')
            return False
