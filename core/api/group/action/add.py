#!/usr/bin/env python3
"""
core/api/group/action/add.py — Thêm / mời thành viên vào nhóm chat.
Tương ứng Go reference: internal/api/group/action/action-methods.go (AddMembers)
"""

import logging
from typing import Union, List

from core.api.common import BaseAPI

logger = logging.getLogger("core.api.group.action.add")


class AddAPI(BaseAPI):
    """Quản lý thêm / mời thành viên vào nhóm qua Socket (CMD 235 SUB 0)."""

    def add_member(
        self,
        group_id: Union[int, str],
        member_uids: Union[int, str, List[Union[int, str]]],
        is_invite: bool = False
    ) -> bool:
        """Thêm hoặc mời thành viên vào nhóm chat (CMD 235 SUB 0, bb=1, ty=1)."""
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning("Socket client chưa kết nối để thêm thành viên.")
            return False

        try:
            return self._socket.add_member(
                group_id=int(group_id),
                member_uids=member_uids,
                is_invite=is_invite
            )
        except Exception as e:
            logger.error(f"[!] Lỗi thêm thành viên vào nhóm {group_id}: {e}")
            return False

    def invite_member(
        self,
        group_id: Union[int, str],
        member_uids: Union[int, str, List[Union[int, str]]]
    ) -> bool:
        """Gửi lời mời tham gia nhóm tới thành viên."""
        return self.add_member(group_id=group_id, member_uids=member_uids, is_invite=True)
