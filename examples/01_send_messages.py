#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
examples/01_send_messages.py
-----------------------------
Ví dụ cơ bản về gửi tin nhắn với Zalo SDK:
- Tin nhắn văn bản 1-1 và Nhóm
- Tin nhắn định dạng chữ (Rich Text / Typography: Đậm, Nghiêng, Gạch chân, Màu sắc, Kích cỡ)
- Tin nhắn trích dẫn (Quote Reply)
- Thả cảm xúc (Reaction: Like, Love, Haha, Wow, Sad, Angry)
- Trạng thái đang soạn tin nhắn (Typing Indicator) và Tin nhắn tự xóa (TTL)
"""

import time
from core import ZaloClient, ThreadType, ReactionIcon


def main():
    # 1. Khởi tạo client (Tự động nạp session từ fresh_session.json hoặc ~/.zalo/fresh_session.json)
    client = ZaloClient(debug=False)

    # 2. Kết nối Socket Gateway và kích hoạt phiên
    print("[*] Đang kết nối Socket Gateway...")
    if not client.start():
        print("[!] Không thể kết nối tới Socket Gateway.")
        return

    print(f"[✔] Đã kết nối thành công với UID: {client.uid}")

    TARGET_GROUP_ID = 700852067  # Thay bằng ID nhóm của bạn
    TARGET_USER_UID = 123456789  # Thay bằng UID người nhận 1-1

    try:
        # 3. Gửi trạng thái đang soạn tin (Typing Indicator)
        print("\n[*] Gửi typing indicator...")
        client.properties.send_typing(target_id=TARGET_GROUP_ID, thread_type=ThreadType.GROUP, is_typing=True)
        time.sleep(1.5)

        # 4. Gửi tin nhắn văn bản thông thường vào nhóm
        print(f"[*] Gửi tin nhắn text tới nhóm {TARGET_GROUP_ID}...")
        res = client.send.send_text(
            target_id=TARGET_GROUP_ID,
            text="Xin chào mọi người từ Zalo Python Core SDK! 🚀",
            thread_type=ThreadType.GROUP
        )
        print(f" -> Kết quả: {res}")

        # 5. Gửi tin nhắn văn bản có định dạng chữ (Rich Text / Typography)
        print("\n[*] Gửi tin nhắn Rich Text (Màu sắc + In đậm + Cỡ chữ lớn)...")
        res_style = client.send.send_text(
            target_id=TARGET_GROUP_ID,
            text="THÔNG BÁO QUAN TRỌNG: Hệ thống SDK đã chuẩn hóa 100%!",
            thread_type=ThreadType.GROUP,
            color="#FF3B30",        # Màu đỏ nổi bật
            bold=True,              # In đậm
            italic=False,
            font_size="18px"        # Cỡ chữ lớn
        )
        print(f" -> Kết quả: {res_style}")

        # 6. Gửi tin nhắn trích dẫn (Quote Reply)
        print("\n[*] Gửi tin nhắn trích dẫn (Quote Reply)...")
        quote_info = {
            "msg_id": 1001,
            "owner_id": 99999999,
            "text": "Nội dung tin nhắn gốc cần trích dẫn",
            "type": 1
        }
        res_quote = client.send.send_text(
            target_id=TARGET_GROUP_ID,
            text="Đây là câu trả lời trích dẫn lại tin nhắn trên.",
            thread_type=ThreadType.GROUP,
            quote_msg=quote_info
        )
        print(f" -> Kết quả: {res_quote}")

        # 7. Thả cảm xúc tin nhắn (Reaction)
        print("\n[*] Thả Reaction LIKE (Icon 2)...")
        res_react = client.send.send_reaction(
            target_id=TARGET_GROUP_ID,
            server_msg_id="1234567890",
            reaction_icon=ReactionIcon.LIKE,
            thread_type=ThreadType.GROUP
        )
        print(f" -> Kết quả: {res_react}")

        # 8. Cài đặt tin nhắn tự xóa (Auto-TTL 30 giây)
        print("\n[*] Gửi tin nhắn tự hủy sau 30 giây...")
        client.properties.set_conversation_ttl(
            target_id=TARGET_GROUP_ID,
            thread_type=ThreadType.GROUP,
            ttl_seconds=30
        )
        client.send.send_text(
            target_id=TARGET_GROUP_ID,
            text="Tin nhắn này sẽ tự động biến mất sau 30 giây.",
            thread_type=ThreadType.GROUP
        )

        # 9. Tắt typing
        client.properties.send_typing(target_id=TARGET_GROUP_ID, thread_type=ThreadType.GROUP, is_typing=False)

    finally:
        # Ngắt kết nối socket sạch sẽ
        print("\n[*] Đang đóng kết nối Socket...")
        client.stop()
        print("[✔] Hoàn tất.")


if __name__ == "__main__":
    main()
