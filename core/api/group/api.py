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

    def _call_group_api(self, endpoint: str, params: dict) -> dict:
        link_id = params.get('linkId') or params.get('grid') or ''
        return self.get_group_info_by_link(str(link_id)) or {}
__all__ = ['GroupAPI', 'GroupActionAPI', 'GroupMessageAPI', 'GroupInfoAPI']
