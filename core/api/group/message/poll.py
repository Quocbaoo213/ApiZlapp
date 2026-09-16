#!/usr/bin/env python3
"""
core/api/group/message/poll.py — Tạo cuộc bình chọn (Poll) trong nhóm chat.
Tương ứng Go reference: internal/api/group/action/action-methods.go (CreatePoll, VotePoll, LockPoll)
"""

import logging
from typing import Union, List

from core.api.common import BaseAPI

logger = logging.getLogger("core.api.group.message.poll")


class PollAPI(BaseAPI):
    """Quản lý tạo và điều khiển cuộc bình chọn (Poll) qua Socket (CMD 1640 SUB 3)."""

    def create_poll(
        self,
        group_id: Union[int, str],
        question: str,
        options: List[str]
    ) -> bool:
        """Tạo cuộc bình chọn trong nhóm chat (CMD 1640 SUB 3)."""
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning("Socket client chưa kết nối để tạo bình chọn.")
            return False

        try:
            return self._socket.create_poll(
                group_id=int(group_id),
                question=question,
                options=options
            )
        except Exception as e:
            logger.error(f"[!] Lỗi khi tạo bình chọn trong Group {group_id}: {e}")
            return False
