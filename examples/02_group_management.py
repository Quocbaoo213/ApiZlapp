#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
examples/02_group_management.py
--------------------------------
Ví dụ về quản lý và điều hành nhóm chat Zalo toàn diện:
- Tham gia nhóm qua link (zalo.me/g/...) hoặc qua Group ID
- Rời khỏi nhóm (Leave Group)
- Xóa thành viên (Kick) & Chặn thành viên (Ban)
- Mời/thêm thành viên mới (Add Member)
- Ghim tin nhắn (Pin Topic) & Bỏ ghim (Unpin)
- Tạo bình chọn / biểu quyết (Poll)
- Giải tán nhóm (Disband Group)
"""

import time
from core import ZaloClient


def main():
    # 1. Khởi tạo client
    client = ZaloClient(debug=False)
    if not client.start():
        print("[!] Không thể kết nối Socket Gateway.")
        return

    print(f"[✔] Đã kết nối Zalo với UID: {client.uid}")

    INVITE_LINK = "https://zalo.me/g/wrrzniqqwideocuiclly"
    SAMPLE_GROUP_ID = 700852067
    SAMPLE_MEMBER_UID = 999999999

    try:
        # ── 1. Tham gia nhóm qua Link mời ──
        print(f"\n[*] 1. Tham gia nhóm qua liên kết: {INVITE_LINK}")
        join_res = client.group.join_group(target=INVITE_LINK, msg="Xin chào, cho mình vào nhóm nhé!")
        print(f" -> Kết quả Join Link: {join_res}")
        if join_res.get("group_id"):
            SAMPLE_GROUP_ID = join_res["group_id"]

        # ── 2. Ghim tin nhắn / Topic nhóm ──
        print(f"\n[*] 2. Ghim thông báo nhóm {SAMPLE_GROUP_ID}...")
        pin_res = client.group_message.pin_topic(
            group_id=SAMPLE_GROUP_ID,
            content="Nội quy nhóm: Vui lòng tôn trọng các thành viên khác!",
            creator_uid=client.uid
        )
        print(f" -> Kết quả Ghim tin: {pin_res}")

        # ── 3. Tạo bình chọn (Poll) trong nhóm ──
        print(f"\n[*] 3. Tạo cuộc bình chọn mới trong nhóm...")
        poll_res = client.group_message.create_poll(
            group_id=SAMPLE_GROUP_ID,
            question="Hôm nay các bạn muốn ăn gì?",
            options=["Cơm tấm", "Bún bò Huế", "Phở bò", "Pizza"],
            allow_multiple=False,
            allow_add_options=True
        )
        print(f" -> Kết quả Tạo Poll: {poll_res}")

        # ── 4. Bỏ ghim tin nhắn nhóm ──
        print(f"\n[*] 4. Bỏ ghim topic...")
        unpin_res = client.group_message.unpin_topic(group_id=SAMPLE_GROUP_ID)
        print(f" -> Kết quả Bỏ ghim: {unpin_res}")

        # ── 5. Thêm thành viên vào nhóm (Add Member) ──
        print(f"\n[*] 5. Thêm thành viên vào nhóm...")
        add_res = client.group_action.add_member(
            group_id=SAMPLE_GROUP_ID,
            members=[SAMPLE_MEMBER_UID]
        )
        print(f" -> Kết quả Add Member: {add_res}")

        # ── 6. Xóa thành viên khỏi nhóm (Kick Member) ──
        print(f"\n[*] 6. Xóa thành viên {SAMPLE_MEMBER_UID} khỏi nhóm...")
        kick_res = client.group_action.kick_member(
            group_id=SAMPLE_GROUP_ID,
            member_uid=SAMPLE_MEMBER_UID
        )
        print(f" -> Kết quả Kick Member: {kick_res}")

        # ── 7. Chặn thành viên khỏi nhóm (Ban Member) ──
        print(f"\n[*] 7. Chặn thành viên {SAMPLE_MEMBER_UID}...")
        ban_res = client.group_action.ban_member(
            group_id=SAMPLE_GROUP_ID,
            member_uid=SAMPLE_MEMBER_UID
        )
        print(f" -> Kết quả Ban Member: {ban_res}")

        # ── 8. Rời khỏi nhóm (Leave Group) ──
        print(f"\n[*] 8. Rời khỏi nhóm chat {SAMPLE_GROUP_ID}...")
        leave_res = client.group_action.leave_group(group_id=SAMPLE_GROUP_ID)
        print(f" -> Kết quả Leave Group: {leave_res}")

    finally:
        client.stop()
        print("\n[✔] Đã đóng kết nối hoàn tất.")


if __name__ == "__main__":
    main()
