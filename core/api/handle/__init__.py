#!/usr/bin/env python3
"""
core/api/handle/__init__.py — SendAPI: Tổng hợp các tính năng gửi tin nhắn và tương tác.
Tương ứng Go reference: internal/api/handle/
"""

from core.api.handle.send_messages import SendMessagesAPI
from core.api.handle.send_image import SendImageAPI
from core.api.handle.send_video import SendVideoAPI
from core.api.handle.send_doodle import SendDoodleAPI
from core.api.handle.send_typing import SendTypingAPI
from core.api.handle.send_reaction import SendReactionAPI
from core.api.handle.undo_message import UndoMessageAPI
from core.api.handle.block_user import BlockUserAPI


class SendAPI(SendMessagesAPI, SendImageAPI, SendVideoAPI, SendDoodleAPI, SendTypingAPI, SendReactionAPI, UndoMessageAPI, BlockUserAPI):
    """Facade service tập hợp tất cả các API gửi tin nhắn, ảnh, video, doodle, reaction, typing, xóa tin, chặn user."""
    pass


__all__ = [
    "SendAPI",
    "SendMessagesAPI",
    "SendImageAPI",
    "SendVideoAPI",
    "SendDoodleAPI",
    "SendTypingAPI",
    "SendReactionAPI",
    "UndoMessageAPI",
    "BlockUserAPI"
]
