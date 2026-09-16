#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
chat_fault_tolerant_client.py — Mô phỏng máy trạng thái (State Machine) Client Chat có khả năng tự phục hồi lỗi.
"""

from enum import Enum, auto
import time
import random
import uuid
from typing import Dict, Optional, List


class ChatState(Enum):
    DISCONNECTED = auto()
    CONNECTING = auto()
    CRYPTO_ESTABLISHED = auto()
    SESSION_BINDING = auto()
    SYNCING_STATE = auto()
    ACTIVE_READY = auto()


class PendingMessage:
    """Đại diện cho tin nhắn đang chờ ACK (In-Flight Queue)."""
    def __init__(self, client_msg_id: str, recipient_id: str, content: str, seq: int):
        self.client_msg_id = client_msg_id
        self.recipient_id = recipient_id
        self.content = content
        self.seq = seq
        self.sent_at = time.time()
        self.retry_count = 0


class FaultTolerantChatClient:
    def __init__(self, user_id: str, device_id: str, session_token: str):
        self.user_id = user_id
        self.device_id = device_id
        self.session_token = session_token
        
        self.state: ChatState = ChatState.DISCONNECTED
        self.outbound_seq: int = 0
        self.last_synced_msg_id: int = 0
        
        # Hàng đợi tin nhắn đang chờ xác nhận (In-Flight Queue)
        self.in_flight_queue: Dict[str, PendingMessage] = {}
        
        # Cấu hình Timeout & Retry
        self.ack_timeout_sec: float = 1.0
        self.max_retries: int = 3
        self.reconnect_attempts: int = 0

    # -------------------------------------------------------------------------
    # CHU TRÌNH THIẾT LẬP KẾT NỐI ĐẦY ĐỦ (FULL CONNECT CYCLE)
    # -------------------------------------------------------------------------

    def establish_connection(self) -> bool:
        """Thiết lập kết nối từ đầu qua đầy đủ các state."""
        print(f"\n🔄 [BẮT ĐẦU CHU TRÌNH KẾT NỐI LẠI (Attempt #{self.reconnect_attempts + 1})]")
        
        # 1. Connect
        self.state = ChatState.CONNECTING
        time.sleep(0.05)
        
        # 2. Crypto Handshake
        self.state = ChatState.CRYPTO_ESTABLISHED
        time.sleep(0.05)
        
        # 3. Session Binding
        self.state = ChatState.SESSION_BINDING
        time.sleep(0.05)
        
        # 4. Sync State & Sequence Baseline
        self.state = ChatState.SYNCING_STATE
        self.outbound_seq = 100  # Server cấp sequence baseline mới
        self.state = ChatState.ACTIVE_READY
        
        self.reconnect_attempts = 0
        print(f"[✔] Kết nối và đồng bộ hoàn tất! State = ACTIVE_READY (Seq Baseline={self.outbound_seq})")
        
        # 5. Tự động gửi lại các tin nhắn chưa được ACK (Replay Pending Queue)
        self._replay_unacked_messages()
        return True

    # -------------------------------------------------------------------------
    # GỬI TIN NHẮN & QUẢN LÝ IN-FLIGHT QUEUE
    # -------------------------------------------------------------------------

    def send_message(self, recipient_id: str, content: str) -> Optional[str]:
        """Gửi tin nhắn và đưa vào In-Flight Queue để theo dõi ACK."""
        if self.state != ChatState.ACTIVE_READY:
            print(f"[⚠️ KHÔNG THỂ GỬI] Client chưa ở trạng thái ACTIVE_READY ({self.state.name})")
            return None

        self.outbound_seq += 1
        client_msg_id = f"msg_{uuid.uuid4().hex[:8]}"

        # Tạo bản ghi pending
        pending = PendingMessage(
            client_msg_id=client_msg_id,
            recipient_id=recipient_id,
            content=content,
            seq=self.outbound_seq
        )
        self.in_flight_queue[client_msg_id] = pending

        print(f"[📤 GỬI GÓI TIN] Seq={pending.seq} | ClientMsgId={client_msg_id} | Đến={recipient_id} | '{content}'")
        return client_msg_id

    def handle_server_ack(self, client_msg_id: str, server_msg_id: int):
        """Xử lý khi nhận được ACK thành công từ Server."""
        if client_msg_id in self.in_flight_queue:
            msg = self.in_flight_queue.pop(client_msg_id)
            print(f"[✔ NHẬN ACK] Tin nhắn '{msg.content}' đã được Server lưu thành công (ServerMsgId={server_msg_id})")

    # -------------------------------------------------------------------------
    # XỬ LÝ 3 KỊCH BẢN LỖI KỸ THUẬT
    # -------------------------------------------------------------------------

    # KỊCH BẢN 1: SILENT DROP (Không có phản hồi từ Server)
    def check_ack_timeouts_and_retry(self):
        """
        Quét hàng đợi In-Flight để phát hiện Silent Drop.
        Nếu quá thời gian ack_timeout_sec mà chưa có ACK -> Thử lại với CÙNG ClientMsgId (Idempotency).
        """
        now = time.time()
        for msg_id, pending in list(self.in_flight_queue.items()):
            if now - pending.sent_at > self.ack_timeout_sec:
                if pending.retry_count < self.max_retries:
                    pending.retry_count += 1
                    pending.sent_at = now
                    print(f"\n[⚠️ PHÁT HIỆN SILENT DROP] Quá {self.ack_timeout_sec}s không có ACK cho {msg_id}.")
                    print(f"   ↳ [RETRY #{pending.retry_count}] Gửi lại gói tin với cùng ClientMsgId để server chống trùng lặp.")
                else:
                    print(f"[❌ THẤT BẠI] Tin nhắn {msg_id} vượt quá số lần retry cho phép.")
                    del self.in_flight_queue[msg_id]

    # KỊCH BẢN 2: OUT-OF-SYNC (Lỗi lệch Sequence / Delta)
    def handle_out_of_sync_error(self, server_expected_seq: int):
        """
        Server trả về mã lỗi Sequence Mismatch / Out of Sync (ví dụ Error 409/428).
        Cách xử lý: Lùi state về SYNCING_STATE, nạp lại Sequence Baseline và Re-sync.
        """
        print(f"\n[⚠️ PHÁT HIỆN LỖI OUT-OF-SYNC] Server báo sai lệch Sequence! Server yêu cầu Seq={server_expected_seq}")
        print(f"   ├─ Chuyển trạng thái: {self.state.name} ➔ SYNCING_STATE")
        self.state = ChatState.SYNCING_STATE
        
        # Đồng bộ lại Sequence Baseline từ Server
        print("   ├─ Đang kéo Delta tin nhắn còn thiếu...")
        time.sleep(0.05)
        self.outbound_seq = server_expected_seq
        
        # Chuyển lại về ACTIVE_READY
        self.state = ChatState.ACTIVE_READY
        print(f"   └─ Đồng bộ hoàn tất! Sequence mới = {self.outbound_seq}. Trạng thái ➔ ACTIVE_READY")
        
        # Gửi lại các tin nhắn trong In-Flight Queue với Sequence mới
        self._replay_unacked_messages()

    # KỊCH BẢN 3: SOCKET RESET (Mất kết nối mạng / Server Reset)
    def handle_socket_reset(self):
        """
        Phát hiện Socket bị ngắt (Broken Pipe, Connection Reset by Peer, EOF).
        Cách xử lý: Chuyển về DISCONNECTED, tính thời gian chờ Exponential Backoff và Reconnect.
        """
        print(f"\n[🚨 PHÁT HIỆN SOCKET RESET] Mất kết nối Socket!")
        self.state = ChatState.DISCONNECTED
        
        self.reconnect_attempts += 1
        # Công thức Exponential Backoff có Jitter: Backoff = min(Max, Base * 2^attempt) + Jitter
        backoff_sec = min(4.0, 0.2 * (2 ** self.reconnect_attempts)) + random.uniform(0.05, 0.1)
        print(f"   ├─ Thời gian chờ Reconnect (Exponential Backoff): {backoff_sec:.2f}s")
        time.sleep(backoff_sec)
        
        # Thực hiện kết nối lại toàn bộ chu trình
        self.establish_connection()

    def _replay_unacked_messages(self):
        """Phát lại các tin nhắn còn tồn đọng trong In-Flight Queue sau khi kết nối lại."""
        if not self.in_flight_queue:
            return
        print(f"\n[📦 REPLAY QUEUE] Đang phát lại {len(self.in_flight_queue)} tin nhắn chưa được xác nhận...")
        for pending in self.in_flight_queue.values():
            self.outbound_seq += 1
            pending.seq = self.outbound_seq
            pending.sent_at = time.time()
            print(f"   ↳ Replay: Seq={pending.seq} | ClientMsgId={pending.client_msg_id} | '{pending.content}'")


if __name__ == "__main__":
    print("=" * 75)
    print("MÔ PHỎNG XỬ LÝ LỖI & PHỤC HỒI TỰ ĐỘNG TRONG CLIENT CHAT SOCKET")
    print("=" * 75)

    client = FaultTolerantChatClient("user_463450795", "device_xiaomi", "token_xyz")
    client.establish_connection()

    # --- KỊCH BẢN 1: Gửi tin nhắn thành công bình thường ---
    print("\n" + "-" * 50)
    print("1. KỊCH BẢN BÌNH THƯỜNG (HAPPY PATH): Gửi và nhận ACK")
    print("-" * 50)
    msg1_id = client.send_message("group_686355764", "Tin nhắn số 1")
    client.handle_server_ack(msg1_id, server_msg_id=8259001)

    # --- KỊCH BẢN 2: Xử lý SILENT DROP ---
    print("\n" + "-" * 50)
    print("2. KỊCH BẢN SILENT DROP: Server bị rớt gói tin / không gửi ACK")
    print("-" * 50)
    msg2_id = client.send_message("group_686355764", "Tin nhắn số 2 (Bị mất gói)")
    time.sleep(1.1)
    client.check_ack_timeouts_and_retry()
    client.handle_server_ack(msg2_id, server_msg_id=8259002)

    # --- KỊCH BẢN 3: Xử lý OUT-OF-SYNC ---
    print("\n" + "-" * 50)
    print("3. KỊCH BẢN OUT-OF-SYNC: Lệch Sequence ID")
    print("-" * 50)
    msg3_id = client.send_message("group_686355764", "Tin nhắn số 3")
    client.handle_out_of_sync_error(server_expected_seq=250)
    client.handle_server_ack(msg3_id, server_msg_id=8259003)

    # --- KỊCH BẢN 4: Xử lý SOCKET RESET ---
    print("\n" + "-" * 50)
    print("4. KỊCH BẢN SOCKET RESET: Đứt cáp mạng / Server Reset kết nối")
    print("-" * 50)
    msg4_id = client.send_message("group_686355764", "Tin nhắn số 4 (Đang gửi thì rớt mạng)")
    client.handle_socket_reset()
    client.handle_server_ack(msg4_id, server_msg_id=8259004)
