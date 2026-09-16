#!/usr/bin/env python3
"""
core/models — Định nghĩa cấu trúc dữ liệu cho Zalo App Core SDK.
"""

from .enums import ThreadType, Gender, MessageType, ReactionIcon, ZaloGroupErrorCode
from .user import UserProfile
from .message import Message, Quote

__all__ = [
    "ThreadType",
    "Gender",
    "MessageType",
    "ReactionIcon",
    "ZaloGroupErrorCode",
    "UserProfile",
    "Message",
    "Quote",
]
