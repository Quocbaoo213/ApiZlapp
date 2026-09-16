#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
examples/04_login_and_auth.py
------------------------------
Ví dụ về quy trình xác thực và quản lý phiên làm việc (Session Management):
1. Đăng nhập 2 bước qua Số điện thoại + Mật khẩu với ZaloLoginClient
2. Xử lý phản hồi và lưu trữ Session JSON
3. Sử dụng Session dạng Dictionary trực tiếp trong bộ nhớ (In-Memory Session)
   (Phù hợp khi triển khai Cloud / Docker / Serverless / Redis / Cơ sở dữ liệu)
"""

import os
import json
from core.login.client import ZaloLoginClient
from core.login.session import SessionManager
from core.client import ZaloClient
from core.models.enums import ThreadType


def login_with_phone_password():
    """Đăng nhập bằng tài khoản và mật khẩu Zalo."""
    phone = input("📱 Nhập số điện thoại Zalo (VD: 0993903236): ").strip()
    password = input("🔑 Nhập mật khẩu Zalo: ").strip()

    if not phone or not password:
        print("[!] Số điện thoại và mật khẩu không được để trống.")
        return None

    # Khởi tạo client đăng nhập
    login_client = ZaloLoginClient()

    try:
        # Thực hiện quy trình đăng nhập 2 bước (Verify phone -> Active account with password)
        session_data = login_client.login(
            phone=phone,
            password=password,
            out_session_path="fresh_session.json"
        )
        print("\n🎉 Đăng nhập thành công!")
        print(f"• User ID  : {session_data.get('uid')}")
        print(f"• KeySetId : {session_data.get('ksid')}")
        return session_data

    except PermissionError as pe:
        # Bắt các thử thách Captcha hoặc 2FA Checkpoint
        print(f"\n[!] Thử thách bảo mật từ Zalo: {pe}")
        return None
    except ValueError as ve:
        print(f"\n[!] Lỗi xác thực: {ve}")
        return None
    except Exception as ex:
        print(f"\n[!] Lỗi không xác định khi đăng nhập: {ex}")
        return None


def run_with_in_memory_session(session_dict: dict):
    """
    Sử dụng Session dạng dictionary trực tiếp trong RAM mà không cần đọc từ ổ cứng.
    Rất hữu ích khi session được lưu trữ trong Redis, MongoDB, PostgreSQL hoặc biến môi trường.
    """
    print("\n[*] Đang khởi tạo ZaloClient từ Session trong bộ nhớ (In-Memory)...")
    client = ZaloClient(session=session_dict, debug=False)

    if client.start():
        print(f"[✔] Khởi tạo thành công phiên làm việc cho UID: {client.uid}")
        
        # Thử gửi tin nhắn kiểm tra
        print("[*] Gửi tin nhắn test...")
        # client.send.send_text(target_id=123456789, text="Test từ in-memory session!", thread_type=ThreadType.USER)
        
        time_elapsed = 2.0
        print(f"[✔] Phiên hoạt động ổn định. Đóng kết nối.")
        client.stop()


def main():
    print("="*60)
    print("ZALO CORE SDK — AUTHENTICATION & SESSION MANAGEMENT")
    print("="*60)

    # Kiểm tra xem đã có session sẵn chưa
    if os.path.exists("fresh_session.json"):
        print("[*] Đã tìm thấy session có sẵn tại fresh_session.json.")
        session_data = SessionManager.load("fresh_session.json")
        print(f"• UID đã lưu: {session_data.get('uid')}")
        
        # Chạy thử với Session Dict trong bộ nhớ
        run_with_in_memory_session(session_data)
    else:
        print("[*] Chưa có session. Bắt đầu quy trình đăng nhập...")
        session_data = login_with_phone_password()
        if session_data:
            run_with_in_memory_session(session_data)


if __name__ == "__main__":
    main()
