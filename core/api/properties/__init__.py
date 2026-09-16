#!/usr/bin/env python3
"""
core/api/properties/__init__.py — PropertiesAPI: Quản lý trạng thái và thuộc tính tin nhắn / phiên.
Tương ứng Go reference: internal/api/properties/
"""

from core.api.properties.typing import TypingAPI
from core.api.properties.receipts import ReceiptsAPI
from core.api.handle.undo_message import UndoMessageAPI


class PropertiesAPI(TypingAPI, ReceiptsAPI, UndoMessageAPI):
    """Facade service cho các thuộc tính tin nhắn và trạng thái người dùng."""
    pass


__all__ = [
    "PropertiesAPI",
    "TypingAPI",
    "ReceiptsAPI",
    "UndoMessageAPI"
]
