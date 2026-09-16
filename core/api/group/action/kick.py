#!/usr/bin/env python3
"""
core/api/group/action/kick.py — Kick / xóa thành viên khỏi nhóm chat.
Tương ứng Go reference: internal/api/group/action/action-methods.go (KickUsers)
"""

import logging
from typing import Union, List

from core.api.common import BaseAPI

logger = logging.getLogger("core.api.group.action.kick")


class KickAPI(BaseAPI):
    """Xoá member: toggle TẮT = 228 (du/b.r), toggle BẬT = 234 flag 1 (pn/g0.k)."""

    def remove_member(
        self,
        group_id: Union[int, str],
        member_uids: Union[int, str, List[Union[int, str]]],
    ) -> bool:
        """Xoá khỏi nhóm KHÔNG block (CMD 228 SUB 0)."""
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning("Socket client chưa kết nối để xoá thành viên.")
            return False
        try:
            return bool(self._socket.remove_member(group_id=int(group_id), member_uids=member_uids))
        except Exception as e:
            logger.error(f"[!] Lỗi xoá thành viên khỏi nhóm {group_id}: {e}")
            return False

    def kick_member(
        self,
        group_id: Union[int, str],
        member_uids: Union[int, str, List[Union[int, str]]],
        is_block: bool = False
    ) -> bool:
        """Xóa/kick (CMD 228 khi is_block=False) hoặc block (CMD 234 flag 1 khi is_block=True)."""
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning("Socket client chưa kết nối để kick/xoá thành viên.")
            return False
        try:
            return bool(self._socket.kick_member(
                group_id=int(group_id),
                member_uids=member_uids,
                is_block=is_block
            ))
        except Exception as e:
            logger.error(f"[!] Lỗi kick/ban thành viên khỏi nhóm {group_id}: {e}")
            return False
