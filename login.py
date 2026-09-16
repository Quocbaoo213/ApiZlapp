#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
login.py — Entrypoint CLI Đăng nhập Zalo (Số điện thoại + Mật khẩu).
Dựa trên kiến trúc đảo ngược từ zalo_login_v10.py:
- Tự động giải Captcha trượt (Slide Captcha correlation matching)
- Xác thực 2 lớp qua SMS / Email / Cuộc gọi / Tổng đài OTP
- Xác thực qua danh sách bạn bè gần đây (Auto-match hoặc Chọn thủ công)
- Đọc DK trực tiếp từ tệp zaloprefs SQLite (--zaloprefs <path> --uid <UID>)
- Thử nghiệm kết nối Socket PROV Handshake tức thì (<60s)
"""

import sys
from core.login.__main__ import main
from core.login import ZaloLoginClient
from core.login.device import HAR_LONG as DEFAULT_DEVICE_PARAMS

__all__ = ["main", "ZaloLoginClient", "DEFAULT_DEVICE_PARAMS"]

if __name__ == "__main__":
    main()

