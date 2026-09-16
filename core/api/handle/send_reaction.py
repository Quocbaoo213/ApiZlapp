#!/usr/bin/env python3
"""
core/api/handle/send_reaction.py — API thả cảm xúc vào tin nhắn (Reaction).
Tương ứng Go reference: internal/api/handle/send-reaction.go, send-multi-reaction.go
"""

import logging
from typing import Union

from core.api.common import BaseAPI
from core.models.enums import ReactionIcon

logger = logging.getLogger("core.api.handle.send_reaction")


class SendReactionAPI(BaseAPI):
    """Quản lý thả cảm xúc vào tin nhắn qua Socket (CMD 1785 / 1780 SUB 0)."""

    def send_reaction(
        self,
        target_id: Union[int, str],
        cli_msg_id: Union[int, str],
        global_msg_id: Union[int, str] = 0,
        icon: str = "❤️",
        is_group: bool = True
    ) -> bool:
        """Thả cảm xúc (❤️, 👍, 😂, 😮, 😭, 😡, 💔) vào tin nhắn."""
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning("Socket client chưa kết nối để gửi reaction.")
            return False

        icon_str = ReactionIcon.from_str(icon)
        t_id = int(target_id)
        cmsg = int(cli_msg_id)
        gmsg = int(global_msg_id or 0)

        try:
            return self._socket.send_reaction(
                target_id=t_id,
                cli_msg_id=cmsg,
                global_msg_id=gmsg,
                icon=icon_str,
                is_group=is_group
            )
        except Exception as e:
            logger.error(f"[!] Lỗi gửi socket reaction: {e}")
            return False
