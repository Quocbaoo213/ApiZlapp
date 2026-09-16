# BÁO CÁO KỸ THUẬT: ĐỐI CHIẾU PCAP CŨ VS PCAP MỚI VÀ HOÀN THIỆN ZALO SOCKET SENDER

## 1. Thông tin Capture & Môi trường

| Thuộc tính | Capture Cũ | Capture Mới |
| :--- | :--- | :--- |
| **Tên File** | `PCAPdroid_13_thg 9_18_14_46.pcap` | `PCAPdroid_13_thg 9_19_56_02.pcap` |
| **Thời gian bắt gói** | Cũ (> 1 ngày trước) | Mới nhất (vừa thực hiện) |
| **Socket Endpoint** | `49.213.95.93:443` | `49.213.95.87:443` |
| **Sender UID** | `463450795` | `463450795` |
| **Target Group ID** | `686355764` | `686355764` |
| **Session State** | Cold session (khởi động mới hoàn toàn) | Hot session / Ticket resumption |

---

## 2. So sánh chi tiết kỹ thuật giữa PCAP Cũ và PCAP Mới

### 2.1. Số lượng Frame khởi tạo (Init Frames)
* **PCAP Cũ (Cold Init):** 64 frame C2S liên tiếp (từ `Seq = -2` đến `Seq = -65`), đòi hỏi khởi tạo toàn bộ các module: Contact sync, Sticker, Privacy settings, Status, Config flags...
* **PCAP Mới (Hot Resume):** Chỉ gồm **5 frame C2S** trước khi gửi tin nhắn:
  1. `Frame #01 (Seq=-36)`: `CMD=1971 SUB=0` (Heartbeat/Keepalive ping)
  2. `Frame #02 (Seq=-37)`: `CMD=2 SUB=2` (Session status ping)
  3. `Frame #03 (Seq=-38)`: `CMD=1971 SUB=0` (Heartbeat sync)
  4. `Frame #04 (Seq=-39)`: `CMD=206 SUB=1` (Typing notification tới Group `686355764`)
  5. `Frame #05 (Seq=-40)`: `CMD=203 SUB=4` (Send preparation state)
  6. `Frame #06 (Seq=-41)`: `CMD=207 SUB=1` (Tin nhắn Group D3)

---

### 2.2. Khám phá quan trọng về Cấu trúc D3 JSON Metadata (`"text": 1`)
* **Phát hiện:** Trong metadata JSON của `prop`:
  ```json
  {"sSrcType":-1,"sSrcStr":"","msg_warning_type":0,"emoji":{"content":0,"num":0,"uniq":0,"first":"","last":"","most":"","text":1}}
  ```
  * Giá trị `"text": 1` **KHÔNG PHẢI** là độ dài của xâu text (`len(text)`), mà là **hằng số phân loại kiểu tin nhắn text thuần (`text_type = 1`)**.
  * Ở cả hai tin nhắn trong capture mới (`"Hả"` và `"Tày vô đối"`), trường `"text"` trong JSON đều giữ cố định là `1`.
  * Khi client trước đây gửi `"text": len(text)` (ví dụ `30` hoặc `52`), Server không nhận diện được schema emoji nên âm thầm drop frame.

---

### 2.3. Quy luật `ck_val`, `cmsg_id` và Broadcast Decoding
* **Phân định Clock Domain theo Type:**
  * Các gói `ty = 1` (CMD 1971, CMD 2, CMD 203, CMD 210) nằm trong clock domain `0x7778xxxx` (khoảng 2.004 tỷ).
  * Các gói `ty = 2` (CMD 206, CMD 207) nằm trong clock domain `0xb3b8xxxx` (khoảng 3.015 tỷ) và `cmsg_id` nằm trong miền `0x9ad6xxxx` / `0x9ad7xxxx` (khoảng 2.597 tỷ).
* **Tính chất Monotonic:** Server yêu cầu `cmsg_id` và `ck_val` của bản tin `CMD 207` mới phải tăng đơn điệu (`> last_cmsg_id_in_pcap`) để tránh bị deduplicate hoặc drop silently.
* **Giải mã CMD 1867 SUB 0:** Payload từ byte 13 trở đi được nén chuẩn GZIP (`1f 8b 08`). Khi decompress, ta thu được JSON delivery sync:
  ```json
  {"e": 0, "last": "1789305007022", "msg": [{"text": {"type": "webchat", "data": {"to": 686355764, "id": 8259342810073, "cliMsgId": 1789304172687, "time": 0, "fromU": 0, "ts": 0, "fromD": null, "mcrypt": 0, "iv": null, "msg": "", "notify": 1, "attach": "", "ttl": 0, "refMessageId": 0, "at": 0}}, "ts": 0}}]}
  ```
* **Lưu ý về Frame 0 Ticket (Code -22):** Frame 0 (266 bytes) là 0-RTT session resumption ticket. Khi reconnect quá nhanh hoặc khi app trên điện thoại đăng nhập đè, server sẽ trả về `CMD 3 SUB 0 Code=-22` (Invalid ticket).

---

## 3. Kết quả thực nghiệm gửi tin nhắn thành công

Khi chạy script `zalo_send.py` với bản tin `"hello from agent"`:
1. Gửi Frame 0 Handshake $\rightarrow$ Nhận `S2C CMD=1 SUB=5 Code=0`.
2. Replay nguyên gốc raw byte-for-byte 5 Init Frames (`Seq -36` đến `-40`) $\rightarrow$ Server xử lý và trả về toàn bộ ACK thành công.
3. Gửi `CMD 207 SUB 1` (`Seq = -41`) $\rightarrow$ **Server phản hồi thành công rực rỡ**:
   * `[S2C Frame] CMD= 207 | SUB= 1 | SEQ= -41 | UID=463450795 | Code=0` (Xác nhận lưu tin nhắn)
   * `[S2C Frame] CMD=1867 | SUB= 0 | SEQ= 0 | UID=686355764 | Code=463450795` (Broadcast đồng bộ nhóm, đã giải mã GZIP payload thành công)
   * `[S2C Frame] CMD= 202 | SUB= 3 | SEQ= 0 | Ty=3 | Code=0` (6 Delivery receipts từ các thiết bị/thành viên trong nhóm: `gmi=8259342810073`, `cmi=1789304172687`, `sid=444650597`, `err=0`).

---

## 4. Danh mục File Artifacts

1. [`/root/zalo/frame0.bin`](file:///root/zalo/frame0.bin): Frame 0 Handshake trích xuất từ PCAP mới (266 bytes).
2. [`/root/zalo/init_sequence.json`](file:///root/zalo/init_sequence.json): Dữ liệu đầy đủ 30 frame C2S từ PCAP mới.
3. [`/root/zalo/zalo_send.py`](file:///root/zalo/zalo_send.py) & [`/root/b.py`](file:///root/b.py): Script gửi tin nhắn Socket hoàn chỉnh (kèm tính năng decode GZIP CMD 1867 và debug-wait).
4. [`/sdcard/Download/c.txt`](file:///sdcard/Download/c.txt) & [`/root/c.txt`](file:///root/c.txt): Báo cáo tổng hợp toàn diện.
