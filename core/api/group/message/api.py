#!/usr/bin/env python3
"""
core/api/group/message/api.py — GroupMessageAPI: Tổng hợp các tính năng bảng tin & tin nhắn nhóm.
Tương ứng Go reference: internal/api/group/message/
"""

from core.api.group.message.pin import PinAPI
from core.api.group.message.unpin import UnpinAPI
from core.api.group.message.poll import PollAPI


class GroupMessageAPI(PinAPI, UnpinAPI, PollAPI):
    """Facade service cho các tính năng bảng tin nhóm (Ghim, Bỏ ghim, Bình chọn)."""
    pass


__all__ = [
    "GroupMessageAPI",
    "PinAPI",
    "UnpinAPI",
    "PollAPI"
]
