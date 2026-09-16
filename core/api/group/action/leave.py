#!/usr/bin/env python3
"""
core/api/group/action/leave.py — Rời / thoát khỏi nhóm chat.
Tương ứng Go reference: internal/api/group/action/action-methods.go (LeaveGroup)
"""

import logging
from typing import Union, Dict, Any

from core.api.common import BaseAPI

logger = logging.getLogger("core.api.group.action.leave")


class LeaveAPI(BaseAPI):
    """Quản lý rời nhóm chat qua Socket (CMD 239 SUB 1)."""

    def leave_group(
        self,
        group_id: Union[int, str],
        new_owner_id: Union[int, str] = 0,
        silent: bool = False,
        block_readd: bool = False,
        wait_response: bool = True,
        timeout: float = 5.0
    ) -> Union[bool, Dict[str, Any]]:
        """Rời khỏi nhóm chat (CMD 239 SUB 1, bb=0, ty=1).
        
        Tham số:
          - group_id: ID nhóm chat
          - new_owner_id: UID chủ nhóm mới (nếu chuyển nhượng quyền creator)
          - silent: Rời nhóm trong im lặng (chỉ báo admin)
          - block_readd: Chặn không cho mời lại vào nhóm này
          - wait_response: Chờ server trả về ACK xác nhận thành công
        """
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning("Socket client chưa kết nối để rời nhóm.")
            return {'sent': False, 'error': 'Socket not connected'} if wait_response else False

        try:
            return self._socket.leave_group(
                group_id=int(group_id),
                new_owner_id=int(new_owner_id) if new_owner_id else 0,
                silent=silent,
                block_readd=block_readd,
                wait_response=wait_response,
                timeout=timeout
            )
        except Exception as e:
            logger.error(f"[!] Lỗi khi rời nhóm {group_id}: {e}")
            return {'sent': False, 'error': str(e)} if wait_response else False
