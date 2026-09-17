from core.api.group.action.api import GroupActionAPI
from core.api.group.message.api import GroupMessageAPI
from core.api.group.info import GroupInfoAPI
from core.api.handle.send_reaction import SendReactionAPI
from core.api.handle.undo_message import UndoMessageAPI

class GroupAPI(GroupActionAPI, GroupMessageAPI, GroupInfoAPI, SendReactionAPI, UndoMessageAPI):

    def ban(self, group_id, member_uids):
        return self.ban_member(group_id=group_id, member_uids=member_uids)

    def block_user(self, target_uid, is_block: bool=True) -> bool:
        if self._socket and getattr(self._socket, 'is_connected', False):
            return self._socket.block_user(target_uid=target_uid, is_block=is_block)
        return False

    def send_sticker(self, group_id: int, cat_id, sticker_id, sticker_type: int=7, ttl_seconds: int=0, quote=None, **kwargs) -> bool:
        if self._socket and getattr(self._socket, 'is_connected', False):
            ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
            q_dict = quote.to_dict() if hasattr(quote, 'to_dict') else quote
            return self._socket.send_group_sticker(group_id=int(group_id), cat_id=cat_id, sticker_id=sticker_id, sticker_type=sticker_type, ttl_ms=ttl_ms, quote_data=q_dict, **kwargs)
        return False

    sendSticker = send_sticker

    def _call_group_api(self, endpoint: str, params: dict) -> dict:
        link_id = params.get('linkId') or params.get('grid') or ''
        return self.get_group_info_by_link(str(link_id)) or {}
__all__ = ['GroupAPI', 'GroupActionAPI', 'GroupMessageAPI', 'GroupInfoAPI']
