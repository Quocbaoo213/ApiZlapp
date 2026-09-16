#!/usr/bin/env python3
"""
core/api/__init__.py — Khởi tạo package API cho Zalo SDK.
Tổ chức kiến trúc module theo chuẩn Go platform reference:
- handle: Gửi tin nhắn, reaction, xóa tin nhắn, chặn người dùng
- group:
  - action: Kick, Ban, Add, Leave, Join, Disband
  - message: Pin, Unpin, Poll
  - info: Link info, ID resolver
- properties: Typing, Receipts, Undo
- user / message / group facade
"""

from core.api.common import BaseAPI
from core.api.handle import SendAPI, SendMessagesAPI, SendReactionAPI, UndoMessageAPI, BlockUserAPI
from core.api.group import GroupAPI, GroupActionAPI, GroupMessageAPI, GroupInfoAPI
from core.api.properties import PropertiesAPI, TypingAPI, ReceiptsAPI
from core.api.user import UserAPI
from core.api.message import MessageAPI

__all__ = [
    "BaseAPI",
    "SendAPI",
    "SendMessagesAPI",
    "SendReactionAPI",
    "UndoMessageAPI",
    "BlockUserAPI",
    "GroupAPI",
    "GroupActionAPI",
    "GroupMessageAPI",
    "GroupInfoAPI",
    "PropertiesAPI",
    "TypingAPI",
    "ReceiptsAPI",
    "UserAPI",
    "MessageAPI"
]
