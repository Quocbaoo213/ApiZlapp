#!/usr/bin/env python3
"""
core/api/group/__init__.py — GroupAPI: Tổng hợp tất cả các dịch vụ Nhóm (Action, Message Board, Info).
Tương ứng Go reference: internal/api/group/
"""

from core.api.group.action import GroupActionAPI
from core.api.group.message import GroupMessageAPI
from core.api.group.info import GroupInfoAPI
from core.api.handle.send_reaction import SendReactionAPI
from core.api.handle.undo_message import UndoMessageAPI


class GroupAPI(GroupActionAPI, GroupMessageAPI, GroupInfoAPI, SendReactionAPI, UndoMessageAPI):
    """
    Facade API quản lý toàn diện các tính năng Nhóm:
    - Quản trị: Kick, Ban, Add, Leave, Join, Disband
    - Bảng tin: Pin, Unpin, Poll
    - Thông tin: Tra cứu Link, Resolve Group ID
    - Tương tác: Thả reaction, Xóa/Thu hồi tin nhắn
    """

    def ban(self, group_id, member_uids):
        """Alias cho ban_member (CMD 234 SUB 0 với is_block=True)."""
        return self.ban_member(group_id=group_id, member_uids=member_uids)

    def block_user(self, target_uid, is_block: bool = True) -> bool:
        """Chặn / bỏ chặn người dùng 1-1 qua Socket (CMD 382/383 SUB 0)."""
        if self._socket and getattr(self._socket, 'is_connected', False):
            return self._socket.block_user(target_uid=target_uid, is_block=is_block)
        return False

    def _call_group_api(self, endpoint: str, params: dict) -> dict:
        """Helper gọi Group HTTP API (tương thích backward compatibility)."""
        link_id = params.get('linkId') or params.get('grid') or ''
        return self.get_group_info_by_link(str(link_id)) or {}


__all__ = [
    "GroupAPI",
    "GroupActionAPI",
    "GroupMessageAPI",
    "GroupInfoAPI"
]

