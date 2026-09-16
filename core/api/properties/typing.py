#!/usr/bin/env python3
"""
core/api/properties/typing.py — Báo trạng thái đang soạn tin nhắn (Typing indicator).
Tương ứng Go reference: internal/api/properties/set-typing.go
"""

import logging
from typing import Union

from core.api.common import BaseAPI

logger = logging.getLogger("core.api.properties.typing")


class TypingAPI(BaseAPI):
    """Quản lý trạng thái đang soạn tin (CMD 206 SUB 1 cho Group, CMD 106 SUB 1 cho 1-1)."""

    def set_typing(self, thread_id: Union[int, str], is_group: bool = True) -> bool:
        """Gửi thông báo đang gõ phím."""
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            return False

        try:
            return self._socket.send_typing_notification(
                target_id=int(thread_id),
                is_group=is_group
            )
        except Exception as e:
            logger.error(f"[!] Lỗi gửi typing notification tới {thread_id}: {e}")
            return False
