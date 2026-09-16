#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
examples/03_bot_engine.py
--------------------------
Ví dụ xây dựng Bot Tự Động Phản Hồi (Interactive Real-time Bot) với Zalo SDK:
- Lắng nghe tin nhắn thời gian thực qua TCP Socket Push Gateway
- Hỗ trợ các tiền tố lệnh linh hoạt (Prefix: ., /, !)
- Trích xuất thông tin người gửi, tên hiển thị, quote reply
- Tự động gắn thẻ @tag người dùng khi phản hồi trong nhóm
- Bộ lệnh mẫu:
  • .ping           : Kiểm tra độ trễ và trạng thái bot
  • .uid            : Xem UID cá nhân / UID nhóm / UID đối tượng
  • .profile [@tag] : Tra cứu hồ sơ chi tiết (Tên, Giới tính, Ngày sinh, Avatar)
  • .echo <text>    : Phản hồi lại văn bản
  • .calc <math>    : Tính toán biểu thức toán học
  • .join <link>    : Yêu cầu bot tham gia nhóm qua liên kết
  • .leave          : Yêu cầu bot rời khỏi nhóm hiện tại
  • .help           : Xem menu trợ giúp
"""

import time
import math
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

from core.client import ZaloClient
from core.models.message import Message
from core.models.enums import ThreadType
from core.utils.helpers import extract_target_uid

VN_TZ = timezone(timedelta(hours=7))


class ZaloBotEngine:
    """Động cơ điều khiển Bot Zalo thông minh."""

    def __init__(self, prefixes=("*", ".", "/", "!")):
        self.prefixes = prefixes
        self.client = ZaloClient(debug=False)
        self.bot_uid = 0
        self.start_time = time.time()

    def start(self):
        print("[*] Đang khởi động Bot Socket Engine...")
        if not self.client.start():
            print("[!] Không thể kết nối Socket Gateway.")
            return

        self.bot_uid = self.client.uid
        print(f"[✔] Bot đã trực tuyến! Bot UID: {self.bot_uid}")

        # Đăng ký hàm nhận tin nhắn thời gian thực
        self.client.on_message(self.handle_incoming_message)

        print("[*] Đang lắng nghe tin nhắn... Nhấn Ctrl+C để dừng.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Đang dừng Bot...")
            self.client.stop()
            print("[✔] Đã tắt Bot an toàn.")

    def handle_incoming_message(self, msg: Message):
        """Callback xử lý mỗi khi có tin nhắn mới đến."""
        # 1. Bỏ qua tin nhắn do chính Bot gửi để tránh vòng lặp (Anti-loop)
        if msg.from_uid == self.bot_uid:
            return

        text = (msg.content or "").strip()
        if not text:
            return

        # 2. Kiểm tra xem tin nhắn có bắt đầu bằng tiền tố lệnh không
        matched_prefix = None
        for p in self.prefixes:
            if text.startswith(p):
                matched_prefix = p
                break

        if not matched_prefix:
            return

        raw_cmd = text[len(matched_prefix):].strip()
        parts = raw_cmd.split()
        if not parts:
            return

        cmd = parts[0].lower()
        args = parts[1:]
        arg_text = " ".join(args)

        print(f"📩 [Nhận lệnh] Từ UID {msg.from_uid} ({'Group ' + str(msg.thread_id) if msg.is_group else '1-1'}): {text}")

        # 3. Điều hướng thực thi lệnh
        self.dispatch_command(cmd, args, arg_text, msg)

    def dispatch_command(self, cmd: str, args: list, arg_text: str, msg: Message):
        """Phân tích và thực thi từng lệnh."""
        reply_text = None

        if cmd == "ping":
            uptime_sec = int(time.time() - self.start_time)
            reply_text = f"Pong! 🏓\n• Trạng thái: Trực tuyến\n• Thời gian hoạt động: {uptime_sec} giây"

        elif cmd == "uid":
            reply_text = (
                f"📋 THÔNG TIN ĐỊNH DANH (UID):\n"
                f"• UID của bạn: {msg.from_uid}\n"
                f"• ID Hội thoại: {msg.thread_id}\n"
                f"• UID Bot: {self.bot_uid}"
            )

        elif cmd in ("profile", "info"):
            target_uid = extract_target_uid(arg_text, msg.raw_data) or msg.from_uid
            user_info = self.client.users.get_user_info(target_uid)
            if user_info:
                reply_text = (
                    f"👤 HỒ SƠ NGƯỜI DÙNG [{target_uid}]\n"
                    f"• Tên hiển thị : {user_info.display_name}\n"
                    f"• Tên Zalo     : {user_info.zalo_name}\n"
                    f"• Giới tính    : {user_info.gender_str}\n"
                    f"• Ngày sinh    : {user_info.dob or 'Ẩn'}\n"
                    f"• Điện thoại   : {user_info.phone or 'Bảo mật'}"
                )
            else:
                reply_text = f"Không tìm thấy thông tin cho UID: {target_uid}"

        elif cmd == "echo":
            reply_text = arg_text if arg_text else "Vui lòng nhập nội dung muốn echo!"

        elif cmd == "calc":
            if not arg_text:
                reply_text = "Cú pháp: .calc <biểu thức> (VD: .calc 2 + 2 * 5)"
            else:
                try:
                    # Tính toán biểu thức an toàn
                    allowed_names = {"sqrt": math.sqrt, "pi": math.pi, "pow": pow, "abs": abs}
                    res = eval(arg_text, {"__builtins__": {}}, allowed_names)
                    reply_text = f"Kết quả: {arg_text} = {res}"
                except Exception as ex:
                    reply_text = f"Lỗi tính toán: {ex}"

        elif cmd == "join":
            if not arg_text:
                reply_text = "Cú pháp: .join <liên kết nhóm zalo.me/g/... hoặc ID nhóm>"
            else:
                res = self.client.group.join_group(arg_text)
                if res.get("success"):
                    reply_text = f"Đã gửi yêu cầu tham gia nhóm thành công! (ID: {res.get('group_id') or 'N/A'})"
                else:
                    reply_text = f"Không thể tham gia nhóm. Vui lòng kiểm tra lại liên kết."

        elif cmd == "leave":
            if not msg.is_group:
                reply_text = "Lệnh .leave chỉ có thể thực hiện trong nhóm chat!"
            else:
                self.client.send.send_text(
                    target_id=msg.thread_id,
                    text="Chào tạm biệt mọi người! Bot rời nhóm theo yêu cầu.",
                    thread_type=ThreadType.GROUP
                )
                time.sleep(0.5)
                self.client.group_action.leave_group(msg.thread_id)
                return

        elif cmd in ("img", "photo", "image", "anh"):
            if not arg_text:
                reply_text = "Cú pháp: .img <liên kết ảnh> [chú thích]\nVí dụ: .img https://picsum.photos/400/300 Ảnh test"
            else:
                parts = arg_text.split(" ", 1)
                img_url = parts[0].strip()
                caption = parts[1].strip() if len(parts) > 1 else ""
                ok = self.client.send_photo(
                    target_id=msg.thread_id,
                    photo_url_or_path=img_url,
                    thread_type=msg.thread_type,
                    caption=caption
                )
                if not ok:
                    reply_text = "Không thể gửi ảnh. Vui lòng kiểm tra lại liên kết ảnh."
                else:
                    return

        elif cmd == "help":
            reply_text = (
                "🤖 DANH SÁCH LỆNH BOT ZALO:\n"
                "• .ping            : Kiểm tra trạng thái kết nối\n"
                "• .uid             : Xem UID của bạn và nhóm\n"
                "• .profile [@tag]  : Tra cứu hồ sơ người dùng\n"
                "• .img <link>      : Gửi hình ảnh vào cuộc trò chuyện\n"
                "• .echo <text>     : Lặp lại văn bản\n"
                "• .calc <math>     : Tính toán biểu thức\n"
                "• .join <link/id>  : Cho bot vào nhóm mới\n"
                "• .leave           : Cho bot rời nhóm hiện tại\n"
                "• .help            : Xem bảng trợ giúp này"
            )

        # 4. Gửi phản hồi lại hội thoại
        if reply_text:
            # Gắn thẻ người dùng nếu đang ở trong nhóm
            if msg.is_group and msg.sender_name:
                tagged_text = f"@{msg.sender_name} {reply_text}"
                mentions = [{"uid": msg.from_uid, "pos": 0, "len": len(msg.sender_name) + 1}]
            else:
                tagged_text = reply_text
                mentions = None

            self.client.send.send_text(
                target_id=msg.thread_id,
                text=tagged_text,
                thread_type=msg.thread_type,
                mentions=mentions
            )


if __name__ == "__main__":
    bot = ZaloBotEngine()
    bot.start()
