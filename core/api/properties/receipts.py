#!/usr/bin/env python3
"""
core/api/properties/receipts.py — Báo cáo đã nhận và đã đọc tin nhắn (Delivery / Read receipts).
Tương ứng Go reference: internal/api/properties/mark-as-delivered.go, mark-as-read.go
"""

import logging
from typing import Union

from core.api.common import BaseAPI

logger = logging.getLogger("core.api.properties.receipts")


class ReceiptsAPI(BaseAPI):
    """Quản lý thông báo đã nhận / đã xem tin nhắn qua Socket (CMD 202 SUB 3)."""

    def mark_as_delivered(
        self,
        group_id: Union[int, str],
        sender_uid: Union[int, str],
        cli_msg_id: Union[int, str],
        global_msg_id: Union[int, str]
    ) -> bool:
        """Gửi ACK đã nhận tin nhắn trong nhóm."""
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            return False

        try:
            return self._socket.send_delivery_receipt(
                group_id=int(group_id),
                sender_uid=int(sender_uid),
                cli_msg_id=int(cli_msg_id),
                global_msg_id=int(global_msg_id)
            )
        except Exception as e:
            logger.error(f"[!] Lỗi gửi delivery receipt: {e}")
            return False
