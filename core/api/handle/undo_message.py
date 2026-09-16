#!/usr/bin/env python3
"""
core/api/handle/undo_message.py — Xóa và thu hồi tin nhắn (Recall / Delete).
Tách riêng hoàn toàn logic giữa Xóa tin nhắn (Delete CMD 205) và Thu hồi tin nhắn (Recall CMD 204).
Tương ứng Go reference: internal/api/properties/undo-message.go & internal/api/group/message/message-methods.go
"""

import logging
from typing import Optional, Union, Dict, Any

from core.api.common import BaseAPI

logger = logging.getLogger("core.api.handle.undo_message")


class UndoMessageAPI(BaseAPI):
    """Quản lý xóa tin nhắn (CMD 205 SUB 3) & thu hồi tin nhắn (CMD 204 SUB 2)."""

    def delete_message(
        self,
        group_id: Union[int, str],
        cli_msg_id: Union[int, str],
        global_msg_id: Union[int, str] = "",
        owner_id: Optional[Union[int, str]] = None,
        is_group: bool = True,
        only_me: bool = False
    ) -> bool:
        """
        Xóa tin nhắn qua Socket (CMD 205 SUB 3):
        - only_me=True: Xóa chỉ ở phía mình (t_type=3 cho group / 1 cho 1-1, il=2)
        - only_me=False: Xóa tin nhắn khỏi cuộc trò chuyện
        """
        g_id = int(group_id)
        if self._socket and getattr(self._socket, 'is_connected', False):
            try:
                return self._socket.delete_message(
                    group_id=g_id,
                    cli_msg_id=cli_msg_id,
                    global_msg_id=global_msg_id,
                    owner_id=owner_id,
                    is_group=is_group,
                    only_me=only_me
                )
            except Exception as e:
                logger.warning(f"Lỗi gửi socket delete message: {e}")
                return False

        logger.warning("Socket client chưa kết nối để xóa tin nhắn.")
        return False

    def recall_message(
        self,
        group_id: Union[int, str],
        cli_msg_id: Union[int, str],
        global_msg_id: Union[int, str] = 0,
        owner_id: Optional[Union[int, str]] = None,
        is_group: bool = True
    ) -> bool:
        """
        Thu hồi tin nhắn (Undo/Recall) cho tất cả mọi người (CMD 204 SUB 2).
        Độc lập hoàn toàn, không phụ thuộc hay ảnh hưởng đến delete_message.
        """
        g_id = int(group_id)
        if self._socket and getattr(self._socket, 'is_connected', False):
            try:
                return self._socket.recall_message(
                    group_id=g_id,
                    cli_msg_id=cli_msg_id,
                    global_msg_id=global_msg_id,
                    owner_id=owner_id,
                    is_group=is_group
                )
            except Exception as e:
                logger.warning(f"Lỗi gửi socket recall message: {e}")
                return False

        logger.warning("Socket client chưa kết nối để thu hồi tin nhắn.")
        return False
