#!/usr/bin/env python3
"""
Zalo App Core SDK
Hệ thống thư viện Python toàn diện, chuyên biệt cho Zalo Mobile App (TCP Socket PROV + D3 & HTTP Mobile APIs).
Kiến trúc modular hóa theo chuẩn Go platform reference.
"""

from .client import ZaloClient, ZaloAPI
from .socket import ZaloSocketClient
from .login import ZaloLoginClient, DeviceProfile, SessionManager
from .models import ThreadType, Gender, MessageType, ReactionIcon, UserProfile, Message, Quote
from .api import (
    BaseAPI,
    SendAPI,
    GroupAPI,
    GroupActionAPI,
    GroupMessageAPI,
    GroupInfoAPI,
    PropertiesAPI,
    UserAPI,
    MessageAPI
)
from .utils import sign_params, parse_ttl_duration, utf16_len, extract_target_uid

__all__ = [
    "ZaloClient",
    "ZaloAPI",
    "ZaloSocketClient",
    "ZaloLoginClient",
    "DeviceProfile",
    "SessionManager",
    "ThreadType",
    "Gender",
    "MessageType",
    "ReactionIcon",
    "UserProfile",
    "Message",
    "Quote",
    "BaseAPI",
    "SendAPI",
    "GroupAPI",
    "GroupActionAPI",
    "GroupMessageAPI",
    "GroupInfoAPI",
    "PropertiesAPI",
    "UserAPI",
    "MessageAPI",
    "sign_params",
    "parse_ttl_duration",
    "utf16_len",
    "extract_target_uid"
]
