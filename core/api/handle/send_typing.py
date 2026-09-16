#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/api/handle/send_typing.py — API gửi trạng thái đang soạn tin (Typing).
"""

import logging
from typing import Union

from core.api.common import BaseAPI

logger = logging.getLogger("core.api.handle.send_typing")


class SendTypingAPI(BaseAPI):
    """API chuyên biệt cho Typing indicator."""

    def send_typing(self, target_id: Union[int, str], is_group: bool = True) -> bool:
        """Gửi trạng thái đang soạn tin nhắn."""
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            return False
        try:
            return self._socket.send_typing(target_id=int(target_id), is_group=is_group)
        except Exception as e:
            logger.error(f"[!] Lỗi gửi typing tới {target_id}: {e}")
            return False
