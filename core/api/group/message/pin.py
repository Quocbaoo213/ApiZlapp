#!/usr/bin/env python3
"""
core/api/group/message/pin.py — Ghim tin nhắn & Xem danh sách tin nhắn đã ghim trong nhóm.
Tương ứng Go reference: internal/api/group/message/message-methods.go (PinMessage)
"""

import logging
from typing import Union, Optional, Dict, Any

from core.api.common import BaseAPI

logger = logging.getLogger("core.api.group.message.pin")


class PinAPI(BaseAPI):
    """Quản lý ghim tin nhắn & xem danh sách ghim qua Socket (CMD 1752 SUB 2 & CMD 1703 SUB 0)."""

    def pin_message(
        self,
        group_id: Union[int, str],
        title: str = "",
        cli_msg_id: Union[int, str] = 0,
        global_msg_id: Union[int, str] = 0,
        sender_uid: Optional[int] = None,
        sender_name: str = "Bot"
    ) -> bool:
        """Ghim tin nhắn / Tạo Topic quan trọng trong nhóm chat (CMD 1752 SUB 2)."""
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning("Socket client chưa kết nối để ghim tin nhắn.")
            return False

        try:
            return self._socket.pin_message(
                group_id=int(group_id),
                title=title,
                cli_msg_id=int(cli_msg_id or 0),
                global_msg_id=int(global_msg_id or 0),
                sender_name=sender_name
            )
        except Exception as e:
            logger.error(f"[!] Lỗi khi ghim tin nhắn trong Group {group_id}: {e}")
            return False

    def get_pinned_topics(self, group_id: Union[int, str]) -> Dict[str, Any]:
        """Lấy danh sách các tin nhắn / topic đã ghim trong nhóm (CMD 1703 SUB 0)."""
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning("Socket client chưa kết nối để lấy danh sách bài ghim.")
            return {'success': False, 'error': 'Not connected'}

        try:
            res = self._socket.fetch_pinned_topics(group_id=int(group_id), wait_response=True)
            return res if isinstance(res, dict) else {'success': bool(res)}
        except Exception as e:
            logger.error(f"[!] Lỗi lấy danh sách bài ghim: {e}")
            return {'success': False, 'error': str(e)}
