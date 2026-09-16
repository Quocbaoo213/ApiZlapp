#!/usr/bin/env python3
"""
core/utils — Tiện ích dùng chung cho Zalo App Core SDK.
"""

from .helpers import (
    sign_params,
    parse_ttl_duration,
    utf16_len,
    extract_target_uid,
    API_KEY,
    API_SECRET,
    CLIENT_TYPE,
    CLIENT_VERSION,
    USER_AGENT
)

__all__ = [
    "sign_params",
    "parse_ttl_duration",
    "utf16_len",
    "extract_target_uid",
    "API_KEY",
    "API_SECRET",
    "CLIENT_TYPE",
    "CLIENT_VERSION",
    "USER_AGENT"
]
