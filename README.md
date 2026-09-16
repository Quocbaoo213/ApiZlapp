# Zalo Python Core SDK (zalo-sdk)

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Architecture: Modular](https://img.shields.io/badge/Architecture-Modular%20Sub--Services-green.svg)]()

Bộ thư viện Python chuẩn hóa, hiệu năng cao mô phỏng 100% giao thức mạng tầng thấp **Zalo Mobile Native App** (TCP Socket PROV Gateway + D3 Frame Encoding) kết hợp tầng **HTTP/2 REST APIs**.

Được thiết kế theo kiến trúc Modular Sub-services độc lập, hỗ trợ chạy mượt mà trên **Windows, macOS, Linux** và môi trường **Cloud / Container (Docker / Serverless / Redis)**.

---

## 🚀 Tính năng nổi bật

### 1. Nhắn tin & Tương tác thời gian thực (Real-time Messaging)
- **Tin nhắn 1-1 & Nhóm**: Gửi và nhận tin nhắn văn bản với độ trễ cực thấp qua TCP Socket Gateway.
- **Định dạng chữ nâng cao (Rich Text / Typography)**: In đậm, In nghiêng, Gạch chân, Gạch ngang, Đổi màu chữ hex (`#FF0000`), Cỡ chữ (`14px`, `18px`, `24px`).
- **Trích dẫn tin nhắn (Quote Reply)**: Cấu trúc nhị phân D3 Quote chuẩn Zalo.
- **Thả cảm xúc (Reactions)**: Like, Love, Haha, Wow, Sad, Angry.
- **Trạng thái đang soạn (Typing Indicator)** & **Tin nhắn tự xóa (Auto-TTL)**: 5s, 10s, 30s, 1d, 7d.

### 2. Quản lý nhóm chat toàn diện (Group Management)
- **Tham gia nhóm**: Tự động nhận diện và giải mã link mời (`https://zalo.me/g/...`) hoặc qua ID nhóm (CMD 244 SUB 4 / CMD 2000 SUB 3).
- **Rời khỏi nhóm (Leave)**: Thoát nhóm sạch sẽ với ACK xác thực chuẩn (CMD 225 SUB 3).
- **Quản trị thành viên**: Xóa thành viên (Kick), Chặn thành viên (Ban), Thêm thành viên mới (Add).
- **Tiện ích nhóm**: Ghim thông báo / Topic (Pin), Bỏ ghim (Unpin), Tạo bình chọn (Poll), Giải tán nhóm (Disband).

### 3. Tra cứu hồ sơ & Danh bạ (User Profile & Directory)
- Tra cứu thông tin người dùng theo UID, @tag hoặc Quote: Họ tên, Tên Zalo, Giới tính, Ngày sinh, Ảnh đại diện HD.
- Tự động ghi nhớ và cập nhật thông tin thành viên xuất hiện qua các sự kiện Realtime.

### 4. Xác thực & Quản lý phiên (Authentication & Session)
- Đăng nhập 2 bước an toàn (Số điện thoại + Mật khẩu) với công cụ CLI `zalo-login`.
- Hỗ trợ nạp Session từ file JSON hoặc **Dictionary trực tiếp trong bộ nhớ (In-Memory)** mà không phụ thuộc vào file hệ thống.
- Tự động sinh Handshake PROV Frame 0 với mật mã đường cong elliptic **X25519 ECDH + AES-256-GCM**.

---

## 📦 Cài đặt

### Cách 1: Cài đặt từ thư mục nguồn (Khuyên dùng khi copy sang máy cá nhân)

```bash
# 1. Di chuyển vào thư mục dự án
cd zalo

# 2. Cài đặt các gói phụ thuộc
pip install -r requirements.txt

# 3. Cài đặt SDK ở chế độ phát triển (Editable mode)
pip install -e .
```

### Cách 2: Yêu cầu môi trường tối thiểu
- **Python**: `>= 3.9`
- **Thư viện phụ thuộc**:
  - `cryptography >= 41.0.0`
  - `pycryptodome >= 3.19.0`
  - `requests >= 2.31.0`
  - `urllib3 >= 2.0.0`

---

## 🔑 Đăng nhập tài khoản

Bạn có thể tạo session mới bất kỳ lúc nào bằng công cụ dòng lệnh đi kèm:

```bash
# Đăng nhập tương tác
python -m core.login

# Hoặc truyền tham số trực tiếp
python -m core.login -u 0993903236 -p "MatKhauCuaBan" -o fresh_session.json
```

Sau khi đăng nhập thành công, file `fresh_session.json` sẽ được tạo và sẵn sàng sử dụng.

---

## ⚡ Bắt đầu nhanh (Quickstart)

### 1. Gửi tin nhắn cơ bản

```python
from core import ZaloClient, ThreadType

# Khởi tạo client (tự động nạp fresh_session.json)
client = ZaloClient()
client.start()

# Gửi tin nhắn vào nhóm
client.send.send_text(
    target_id=700852067,
    text="Xin chào cả nhóm!",
    thread_type=ThreadType.GROUP
)

# Đóng kết nối
client.stop()
```

### 2. Định dạng chữ phong cách (Rich Text / Typography)

```python
client.send.send_text(
    target_id=700852067,
    text="THÔNG BÁO KHẨN CẤP!",
    thread_type=ThreadType.GROUP,
    color="#FF3B30",     # Màu đỏ
    bold=True,           # In đậm
    font_size="20px"     # Cỡ chữ to
)
```

### 3. Tham gia nhóm qua Link & Rời nhóm

```python
# Tham gia nhóm qua link
res = client.group.join_group("https://zalo.me/g/wrrzniqqwideocuiclly")
print("Kết quả vào nhóm:", res)

# Rời nhóm
client.group_action.leave_group(group_id=700852067)
```

### 4. Tạo Bot tự động trả lời (Interactive Bot Engine)

```python
from core import ZaloClient, Message

client = ZaloClient()

def on_message(msg: Message):
    # Bỏ qua tin nhắn của chính bot
    if msg.from_uid == client.uid:
        return

    print(f"[{msg.thread_id}] {msg.from_uid}: {msg.content}")

    # Lệnh .ping
    if msg.content == ".ping":
        client.send.send_text(
            target_id=msg.thread_id,
            text="Pong! Bot đang hoạt động.",
            thread_type=msg.thread_type
        )

client.on_message(on_message)
client.start()

# Giữ chương trình chạy
import time
while True:
    time.sleep(1)
```

---

## 📂 Cấu trúc dự án

```text
zalo/
├── core/                       # Package SDK chính
│   ├── __init__.py             # Exports top-level API
│   ├── client.py               # ZaloClient & ZaloAPI Facade
│   ├── api/                    # Các Sub-Services chức năng
│   │   ├── send.py             # Dịch vụ gửi tin nhắn, quote, style
│   │   ├── group.py            # Dịch vụ quản trị nhóm
│   │   ├── user.py             # Dịch vụ hồ sơ & danh bạ
│   │   └── properties.py       # Typing indicator, Receipts, TTL
│   ├── socket/                 # Giao thức tầng Socket Gateway
│   │   ├── client.py           # TCP Socket Client & Push Receiver
│   │   ├── protocol.py         # Binary Packet Encoder / Decoder
│   │   ├── crypto.py           # X25519 ECDH, AES-256-GCM, XOR D3
│   │   └── handshake.py        # Active Session Burst Frames
│   ├── login/                  # Module xác thực & nạp session
│   └── models/                 # Data classes & Enums
├── examples/                   # Các kịch bản mẫu hoàn chỉnh
│   ├── 01_send_messages.py     # Gửi tin nhắn, typography, reaction
│   ├── 02_group_management.py  # Tham gia link, kick, ban, pin, poll
│   ├── 03_bot_engine.py        # Bot xử lý lệnh tương tác realtime
│   └── 04_login_and_auth.py    # Đăng nhập & nạp session bộ nhớ RAM
├── setup.py                    # Cấu hình cài đặt package
├── pyproject.toml              # Chuẩn PEP 517 build
├── requirements.txt            # Danh sách dependencies
└── SDK_GUIDE.md                # Tài liệu hướng dẫn chi tiết & API Reference
```

---

## 📖 Tài liệu chuyên sâu

Xem tài liệu đầy đủ tại **[SDK_GUIDE.md](SDK_GUIDE.md)** bao gồm:
- Đặc tả chi tiết giao thức nhị phân và sơ đồ Handshake PROV.
- Bảng tra cứu toàn bộ các Class, Method, Parameters và Return Types.
- Hướng dẫn triển khai trên Cloud (Docker, Serverless, Redis session caching).

---

## 🤖 Ghi chú cho agent (reverse từ smali + pcap thực tế, 09/2026)

Workflow chuẩn: `LDPlayer (root, adb) -> pull zaloprefs + pcap PCAPdroid -> parse zaloprefs lấy UID/DK/CryptKey -> decode pcap bằng DK (GCM outer + XOR inner) -> login pass/CLI khi cần session mới -> test socket live (đọc ACK) -> đối chiếu smali`.

### Bản đồ CMD socket (đã verify pcap + smali `pn/g0`, `du/b`)
| Việc | CMD | Params plaintext (sau GCM, trước/sau XOR) | Ghi chú |
|---|---|---|---|
| Xoá khỏi nhóm (toggle TẮT) | 228/0 (`du/b.r`) | `gid:u32 + uid:u32*` (không count/flag) | Nút "Xoá khỏi nhóm" thật. SDK: `remove_member()` |
| Block/chặn (toggle BẬT) | 234/0 (`pn/g0.k`) | `gid:u32 + flag:u8(1) + count:u32 + uids` | `flag 0` gần như không dùng. SDK: `kick_member(is_block=True)` / `block_group_member()` |
| Rời nhóm | 225/3 (`du/b.g`, `pn/g0.N0`) | `01 + vercode:u32 + 0:u32 + lang:u16(0) + gid:u32 + 0x00A0:u16 + 0:u16` | SDK đúng |
| Giải tán nhóm | 242/0 (`pn/g0.h2`) | `01 + vercode:u32 + gid:u32` | Trước đây alias nhầm sang 1705, đã sửa |
| Join qua link | 244/4 (`pn/g0.n2`) | `01 + ver + 0:u32 + lang:u16 + gid:u32 + msg:l3 + source:u32(1) + sub:u8(0) + link:l3 FULL URL` | BẮT BUỘC có gid + full `https://zalo.me/g/...`; `gid=0` trả ACK rỗng |
| 2000/0 | fetch, không phải join | `01 + ver + 0:u32 + lang + gid + flag:u8` | Đừng dùng để join |
| 246/250 | board/poll/invite, không phải join nhóm | — | Đừng nhầm với join |

### Rời nhóm (leave) chi tiết — đọc kỹ trước khi test
- Lệnh: `225/3` (`du/b.g`, `pn/g0.N0`), C2S luôn 19B: `01 + vercode:u32(260802903) + 0:u32 + lang:u16(0) + gid:u32 + 0x00A0:u16(160) + 0:u16`. Chỉ gid thay đổi theo nhóm (pcap verify: `701210986`, `692675055`, `701500272`).
- S2C ACK: `status:i32` 4B đầu (=0 là server đã nhận) + ~1–1.3KB payload (snapshot state, chưa parse — độ dài tăng dần 1034→1357B trong pcap, đừng dùng để kết luận).
- **`status 0` / `send True` KHÔNG có nghĩa đã out**: live test rời `701210986` và `701514047` đều ACK `status 0`, `send_message` sau đó vẫn `True` (True chỉ = socket đã gửi). Verify thật bằng: member list trong app, hoặc bot còn nhận push `201`/tin mới của nhóm đó không.
- **Owner không rời được**: smali không check client-side, server trả `0x426f NOT_AUTHORIZED`. Nhóm nào bot là chủ (vd `692675055` "Bot là chủ nhóm") thì leave sẽ ACK 0 nhưng vẫn ở lại — phải chuyển quyền hoặc giải tán (`242`) thay vì leave.
- Rời rồi muốn vào lại: join lại bằng `244` kèm gid + full link đã biết (đã verify rejoin `701210986` OK). Không dùng `gid=0`.
- Pcap có tới 18 cặp leave C2S/S2C vì user spam leave lúc capture — khi thấy leave lặp đi lặp lại cùng gid mà member vẫn còn thì hiểu là 1 trong các trường hợp trên.

### Bẫy đã gặp (đừng lặp lại)
1. **C2S params bị XOR 2 lớp** (`xor_enc`: keystream `XK ^ le32(len+23) ^ le32(uid)`); **S2C ACK thì KHÔNG XOR** (đọc `status:i32` trực tiếp 4B đầu). Muốn so builder với pcap phải XOR-decode C2S trước.
2. **Gid phải biết trước khi join**: `244 gid=0` luôn ACK `len 123` rỗng, không resolve. Lấy gid từ lịch sử chat (`201/38` recommend-link), invite push `201`, hoặc HTTP `GROUP_API_INFO` (`group.api.zaloapp.com`), rồi gửi `244` kèm gid + full URL + `source=1` (đã verify: `ld5v...->701500272`, `krgx...->701210986`).
3. **ACK `status 0` ≠ thành công thật**: `send_*` trả `True` chỉ nghĩa là socket đã gửi. Verify bằng cách: nghe push `201`, gửi tin thử, hoặc check member list trong app.
4. **Thiếu `Union` import** (`protocol.py`, `socket/client.py`) làm crash Python 3.11 — đã thêm.
5. **ACK listener thiếu CMD** thì `_wait_cmd_ack` treo tới timeout: `228`/`242` đã được thêm vào list ở `socket/client.py`.
6. **Facade vs socket**: `ZaloClient.connect()/close()` (không phải `start/stop`); gửi tin nhóm là `send_message(thread_id, text, thread_type=GROUP)` (không có `send_text`); `leave_group` facade đã hỗ trợ `wait_response`.
7. **Login xoay DK**: mỗi lần `login.py` thành công là 1 `ksid`/DK mới, session file cũ hết hiệu lực. Dùng `live_session.json` (từ zaloprefs, offline) khi không muốn đá session thiết bị; dùng `login_session*.json` mới nhất khi cần chạy socket PC.
8. **Pcap chỉ giải được socket custom** (CONNECT + frame GCM). 54/56 flows là TLS pinning, PCAPdroid/Reqable MITM không bóc được — đừng cố.

### Lệnh main đúng
```bash
# nghe để lấy UID/group mới
python main.py --session login_session3.json --listen --duration 180
# xoá (228) / block (234) / rời (225) / giải tán (242) / join link (244)
python main.py --session <json> --group <GID> --kick <UID>     # 228, không block
python main.py --session <json> --group <GID> --ban <UID>      # 234 flag 1
python main.py --session <json> --leave <GID>                  # 225, đọc ACK success
python main.py --session <json> --disband --group <GID>        # 242
python main.py --session <json> --join https://zalo.me/g/<code> --group <GID>  # 244 cần gid
python main.py --session <json> --group <GID> --msg "text"     # nhắn nhóm
```

---

## 📄 Bản quyền & Tuyên bố miễn trừ trách nhiệm
Dự án được phát triển nhằm mục đích học tập và nghiên cứu giao thức mạng. Vui lòng tuân thủ điều khoản sử dụng của nhà cung cấp dịch vụ khi triển khai.
