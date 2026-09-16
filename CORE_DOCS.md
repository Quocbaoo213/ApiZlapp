# 📚 Zalo App Core SDK — Comprehensive Architecture & Technical Reference (`CORE_DOCS.md`)
> Tài liệu tổng hợp toàn bộ kiến trúc, giải thích chi tiết, docstrings và comments được trích xuất từ 100% codebase `core/`.
> File này dành cho AI Agent và lập trình viên tra cứu đầy đủ cấu trúc packet, opcode TCP, logic mã hóa D3/GCM, quy trình Handshake PROV và các API sub-services.

## 🌟 1. Tổng quan Kiến trúc Toàn diện (System Architecture)

Cấu trúc module của thư viện `core/` được thiết kế theo chuẩn Single Responsibility và tham chiếu từ kiến trúc micro-engine:
1. **`core/client.py`**: Entrypoint facade chính (`ZaloClient` / `ZaloAPI`), tích hợp các sub-services và điều phối kết nối.
2. **`core/socket/`**: Tầng mạng TCP Binary Socket Gateway:
   - `client.py`: Socket Hub (`ZaloSocketClient`) quản lý TLS socket, PROV Handshake, heartbeat ping, frame parser loop, reconnect supervisor.
   - `protocol.py`: Định nghĩa binary packet frame (OuterFrame, InnerPacketHeader), checksum, D3 compression, command opcodes (CMD 101, 201, 204, 228, 234, 242, 901, 1640, 1785...).
   - `crypto.py`: Mã hóa/Giải mã AES-GCM (Payload), AES-CBC (E2EE), XOR D3, X25519 Elliptic Curve Key Exchange.
   - `handshake.py`: Tạo PROV Authen Frame và gửi chuỗi handshake kích hoạt phiên Socket.
   - `actions/`: Các Mixin độc lập (`send_message.py`, `send_image.py`, `send_video.py`, `send_doodle.py`, `send_reaction.py`, `send_typing.py`, `pin_topic.py`, `poll.py`, `undo_message.py`, `group_actions.py`, `block_user.py`).
3. **`core/api/`**: Tầng dịch vụ API Logic cấp cao:
   - `handle/`: Dịch vụ gửi tin nhắn, đa phương tiện (Image, Video, Doodle), cảm xúc reaction, typing, thu hồi/xóa tin.
   - `group/`: Quản trị nhóm (Kick, Ban, Add, Leave, Join, Disband), Bảng tin nhóm (Pin, Unpin, Poll), Thông tin nhóm (Link preview, ID resolver).
   - `properties/`: Quản lý thuộc tính tin nhắn (Typing status, Delivery/Read receipts).
   - `user.py` & `message.py`: Quản lý hồ sơ người dùng và cấu trúc tin nhắn.
4. **`core/login/`**: Module Xác thực và Đăng nhập Zalo Mobile v10:
   - `client.py` & `password.py`: Đăng nhập bằng SĐT + Password mô phỏng app Zalo chính thức.
   - `captcha.py`: Tự động giải Slide Captcha bằng thuật toán đối sánh mẫu (Template Matching).
   - `two_factor.py`: Xác thực 2 bước (SMS/Call OTP, Xác minh bạn bè gần đây).
   - `session.py`: Quản lý lưu trữ phiên session JSON và trích xuất offline từ `zaloprefs.sqlite`.
5. **`core/models/`**: Định nghĩa cấu trúc dữ liệu Model và Enums (`ThreadType`, `ReactionIcon`, `MessageType`, `UserProfile`, `Message`, `Quote`).
6. **`core/utils/`**: Các hàm tiện ích ký tham số (`sign_params`), tính độ dài UTF-16 (`utf16_len`), phân tích thời gian tự xóa TTL (`parse_ttl_duration`).

## 📑 2. Danh mục Chi tiết Từng File trong `core/`

### 📁 Thư mục: `core/`

#### 📄 `core/client.py` (629 dòng)
**Mô tả Module:**
```text
core/client.py — ZaloClient / ZaloAPI: Entrypoint chính của Zalo App Core SDK.
Tổ chức kiến trúc sub-services modular tương tự Go platform reference (zalo.go / apis.go):
- send: SendAPI (Gửi tin nhắn, mention, quote, style, reaction, xóa/thu hồi, chặn user)
- group: GroupAPI (Facade nhóm toàn diện)
- group_action: GroupActionAPI (Kick, Ban, Add, Leave, Join, Disband)
- group_message: GroupMessageAPI (Pin, Unpin, Poll)
- group_info: GroupInfoAPI (Link info, ID resolver)
- properties: PropertiesAPI (Typing, Delivery/Read receipts, Undo)
- users: UserAPI (Profile & Contact registry)
- socket: ZaloSocketClient (Low-level TCP Socket Gateway)
```
**Danh sách Class:**
- `class ZaloClient` (Dòng 38): Client tích hợp đầy đủ các tính năng cho Zalo Mobile App.
  - `def __init__(self, session, session_path, frame0_path, debug)` (Dòng 41)
  - `def socket(self)` (Dòng 78)
  - `def socket(self, sock)` (Dòng 82)
  - `def _load_session_data(self)` (Dòng 90)
  - `def _init_socket_client(self)` (Dòng 133)
  - `def _update_services_socket(self)` (Dòng 146) — Cập nhật socket instance cho tất cả các sub-services sau khi khởi tạo/kết nối lại.
  - `def _on_raw_socket_frame(self, parsed_frame)` (Dòng 156)
  - `def connect(self)` (Dòng 193) — Kết nối tới Zalo Gateway và hoàn tất PROV Handshake.
  - `def add_message_listener(self, handler)` (Dòng 200) — Đăng ký listener nhận tin nhắn realtime.
  - `def send_message(self, target_id, text, thread_type, ttl_seconds, quote)` (Dòng 206) — Gửi tin nhắn (Group hoặc 1-1).
  - `def send_group_message(self, group_id, text, ttl_seconds, quote)` (Dòng 223) — Gửi tin nhắn nhóm.
  - `def send_1to1_message(self, user_id, text, ttl_seconds, quote)` (Dòng 233) — Gửi tin nhắn 1-1.
  - `def send_typing(self, target_id, is_group)` (Dòng 243) — Gửi trạng thái đang soạn tin nhắn.
  - `def send_reaction(self, target_id, cli_msg_id, global_msg_id, icon, is_group)` (Dòng 251) — Thả cảm xúc vào tin nhắn.
  - `def pin_message(self, group_id, title, cli_msg_id, global_msg_id, sender_name)` (Dòng 268) — Ghim tin nhắn trong nhóm.
  - `def unpin_message(self, group_id, global_msg_id, cli_msg_id)` (Dòng 285) — Bỏ ghim tin nhắn trong nhóm.
  - `def remove_member(self, group_id, member_uids)` (Dòng 298) — Xoá khỏi nhóm KHÔNG block (CMD 228 SUB 0, du/b.r) — nút 'Xoá khỏi nhóm' toggle TẮT.
  - `def kick_member(self, group_id, member_uids, is_block)` (Dòng 306) — Xóa thành viên khỏi nhóm.
  - `def block_group_member(self, group_id, member_uids)` (Dòng 315) — Chặn thành viên khỏi nhóm.
  - `def block_user(self, target_uid, is_block)` (Dòng 323) — Chặn người dùng 1-1.
  - `def unblock_user(self, target_uid)` (Dòng 331) — Bỏ chặn người dùng 1-1.
  - `def leave_group(self, group_id, new_owner_id, silent, block_readd, wait_response, timeout)` (Dòng 338) — Rời khỏi nhóm (CMD 239 SUB 1 / CMD 225 SUB 3).
  - `def delete_message(self, group_id, cli_msg_id, global_msg_id, owner_id, is_group, only_me)` (Dòng 364) — Xóa hoặc thu hồi tin nhắn.
  - `def recall_message(self, group_id, cli_msg_id, global_msg_id, owner_id, is_group)` (Dòng 383) — Thu hồi tin nhắn.
  - `def disband_group(self, group_id)` (Dòng 400) — Giải tán nhóm chat (CMD 242 SUB 0, pn/g0.h2).
  - `def add_member(self, group_id, member_uids, is_invite)` (Dòng 407) — Thêm hoặc mời thành viên vào nhóm.
  - `def join_group(self, target, msg)` (Dòng 416) — Tham gia nhóm chat qua ID hoặc Link.
  - `def preview_group_link(self, link_or_code)` (Dòng 424) — Xem trước thông tin nhóm / cộng đồng qua Link (tương ứng GroupLobbyView trong app Zalo).
  - `def create_poll(self, group_id, question, options)` (Dòng 431) — Tạo cuộc bình chọn trong nhóm.
  - `def send_photo(self, target_id, photo_url_or_path, thread_type, caption, title, description, width, height, total_size, thumb_url, hd_url, ttl, quote_data, native, sub_type, is_original)` (Dòng 440) — Gửi hình ảnh tới nhóm hoặc cá nhân 1-1.
  - `def send_group_photo(self, group_id, photo_url_or_path, caption)` (Dòng 479) — Shortcut gửi hình ảnh tới nhóm chat.
  - `def send_1to1_photo(self, to_uid, photo_url_or_path, caption)` (Dòng 489) — Shortcut gửi hình ảnh tới cá nhân 1-1.
  - `def send_doodle(self, target_id, doodle_url_or_path, thread_type, caption, title, description, thumb_url, hd_url, width, height, total_size, ttl, quote_data, native, sub_type, is_original)` (Dòng 503) — Gửi hình vẽ (doodle / SUB 37) tới nhóm hoặc cá nhân 1-1.
  - `def send_group_doodle(self, group_id, doodle_url_or_path, caption)` (Dòng 542) — Shortcut gửi hình vẽ (doodle) tới nhóm chat.
  - `def send_1to1_doodle(self, to_uid, doodle_url_or_path, caption)` (Dòng 552) — Shortcut gửi hình vẽ (doodle) tới cá nhân 1-1.
  - `def send_video(self, target_id, video_url_or_path, thread_type, caption, title, description, thumb_url, width, height, duration_ms, total_size, ttl, quote_data, native, sub_type)` (Dòng 562) — Gửi video tới nhóm hoặc cá nhân 1-1.
  - `def send_group_video(self, group_id, video_url_or_path, caption)` (Dòng 599) — Shortcut gửi video tới nhóm chat.
  - `def send_1to1_video(self, to_uid, video_url_or_path, caption)` (Dòng 609) — Shortcut gửi video tới cá nhân 1-1.
  - `def close(self)` (Dòng 619) — Đóng kết nối.
  - `def disconnect(self)` (Dòng 624) — Đóng kết nối (alias cho close).

**Toàn bộ Comments & Chú thích Logic (8 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L48 | `# Ưu tiên session argument, sau đó session_path argument` | `# Ưu tiên session argument, sau đó session_path argument` |
| L59 | `# 1. Socket client` | `# 1. Socket client` |
| L63 | `# 2. Khởi tạo các Sub-Services theo kiến trúc Go Reference` | `# 2. Khởi tạo các Sub-Services theo kiến trúc Go Reference` |
| L73 | `# Facades tương thích ngược` | `# Facades tương thích ngược` |
| L91 | `# 1. Trường hợp truyền trực tiếp dict in-memory` | `# 1. Trường hợp truyền trực tiếp dict in-memory` |
| L95 | `# 2. Trường hợp truyền đường dẫn hoặc tìm kiếm mặc định` | `# 2. Trường hợp truyền đường dẫn hoặc tìm kiếm mặc định` |
| L170 | `# Tự động học metadata người dùng` | `# Tự động học metadata người dùng` |
| L204 | `# --- Shortcut Delegations (Tương thích 100% với code cũ) ---` | `# --- Shortcut Delegations (Tương thích 100% với code cũ) ---` |

---

### 📁 Thư mục: `core/api/`

#### 📄 `core/api/common.py` (93 dòng)
**Mô tả Module:**
```text
core/api/common.py — BaseAPI class cung cấp session loading, signing và socket access.
Tương tự Go reference: internal/api/common/base.go
```
**Danh sách Class:**
- `class BaseAPI` (Dòng 24): Base class cho tất cả các sub-service API trong hệ thống.
  - `def __init__(self, session_path, socket_client)` (Dòng 27)
  - `def set_socket_client(self, socket_client)` (Dòng 31) — Gắn instance SocketClient đang hoạt động.
  - `def is_connected(self)` (Dòng 36)
  - `def uid(self)` (Dòng 40)
  - `def _extract_session_fields(self, data)` (Dòng 46) — Trích xuất các trường xác thực từ dictionary dữ liệu session.
  - `def _load_session(self)` (Dòng 65) — Nạp thông tin phiên đăng nhập (Hỗ trợ dict in-memory hoặc tìm kiếm đa nền tảng).

---

#### 📄 `core/api/message.py` (109 dòng)
**Mô tả Module:**
```text
core/api/message.py — API gửi tin nhắn, trích dẫn, RTF formatting và typing.
```
**Danh sách Class:**
- `class MessageAPI` (Dòng 11): Wrapper các thao tác gửi tin nhắn trên Socket.
  - `def __init__(self, socket_client)` (Dòng 14)
  - `def send(self, target_id, text, thread_type, ttl_seconds, quote)` (Dòng 17)
  - `def send_group(self, group_id, text, ttl_seconds, quote)` (Dòng 36)
  - `def send_1to1(self, target_uid, text, ttl_seconds, quote)` (Dòng 54)
  - `def send_styled(self, target_uid, text, color, bold, italic, underline, strike, fontsize, style_id, ttl_seconds, quote)` (Dòng 72)
  - `def send_typing(self, target_id, is_group)` (Dòng 106)

---

#### 📄 `core/api/user.py` (361 dòng)
**Mô tả Module:**
```text
core/api/user.py — API quản lý danh bạ, bạn bè và tra cứu hồ sơ người dùng (User Profile).
```
**Hằng số / Opcodes chính:** `TZ_VN, CACHE_TTL_SECONDS`

**Danh sách Class:**
- `class UserAPI` (Dòng 31): Quản lý tra cứu hồ sơ người dùng Zalo (Bạn bè, Người lạ, Thành viên nhóm).
  - `def __init__(self, session_path)` (Dòng 34)
  - `def _extract_session_fields(self, data)` (Dòng 41)
  - `def _load_session(self)` (Dòng 55)
  - `def _call_api(self, url, extra_params)` (Dòng 84)
  - `def register_seen_user(self, uid, display_name, avatar)` (Dòng 117) — Học thông tin người dùng được phát hiện từ sự kiện realtime.
  - `def refresh_friends_cache(self)` (Dòng 138) — Làm mới danh sách bạn bè và alias vào cache.
  - `def get_user_profile(self, target_uid, force_refresh, fallback_name, fallback_avatar)` (Dòng 173) — Truy xuất UserProfile cho bất kỳ UID nào (Bạn bè hoặc Người lạ).
  - `def get_all_friends(self, force_refresh)` (Dòng 224) — Lấy toàn bộ danh sách bạn bè đã cache.
  - `def get_aliases(self)` (Dòng 234) — Lấy bảng tra cứu biệt danh (Alias map).
  - `def discover_contacts(self, phones)` (Dòng 238) — Khám phá liên hệ Zalo theo danh sách số điện thoại.
  - `def format_user_info(user_obj)` (Dòng 274) — Định dạng dữ liệu người dùng thành thẻ thông tin chi tiết đẹp mắt.

**Toàn bộ Comments & Chú thích Logic (2 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L28 | `# 5 phút cache` | `CACHE_TTL_SECONDS = 300  # 5 phút cache` |
| L201 | `# Người lạ / Thành viên nhóm` | `# Người lạ / Thành viên nhóm` |

---

### 📁 Thư mục: `core/api/group/`

#### 📄 `core/api/group/api.py` (44 dòng)
**Mô tả Module:**
```text
core/api/group/api.py — GroupAPI: Tổng hợp tất cả các dịch vụ Nhóm (Action, Message Board, Info).
Tương ứng Go reference: internal/api/group/
```
**Danh sách Class:**
- `class GroupAPI` (Dòng 14): Facade API quản lý toàn diện các tính năng Nhóm:
- Quản trị: Kick, Ban, Add, Leave, Join, Disband
- Bảng tin: Pin, Unpin, Poll
- Thông tin: Tra cứu Link, Resolve Group ID
- Tương tác: Thả reaction, Xóa/Thu hồi tin nhắn
  - `def ban(self, group_id, member_uids)` (Dòng 23) — Alias cho ban_member (CMD 234 SUB 0 với is_block=True).
  - `def block_user(self, target_uid, is_block)` (Dòng 27) — Chặn / bỏ chặn người dùng 1-1 qua Socket (CMD 382/383 SUB 0).
  - `def _call_group_api(self, endpoint, params)` (Dòng 33) — Helper gọi Group HTTP API (tương thích backward compatibility).

---

#### 📄 `core/api/group/info.py` (292 dòng)
**Mô tả Module:**
```text
core/api/group/info.py — Tra cứu thông tin nhóm và phân giải mã liên kết (Link / ID).
Tương ứng Go reference: internal/api/get/fetch-group-info.go
```
**Danh sách Class:**
- `class GroupInfoAPI` (Dòng 26): Quản lý tra cứu thông tin nhóm và phân giải link tham gia nhóm.
  - `def parse_group_target(target)` (Dòng 30) — Phân tích chuỗi target thành ('link', gid, link_code) hoặc ('id', group_id, None).
  - `def get_group_info_by_link(self, link_or_code)` (Dòng 56) — Tra cứu thông tin nhóm từ Link tham gia hoặc mã code.
  - `def resolve_group_id_from_link(self, link_or_code)` (Dòng 87) — Phân giải liên kết nhóm (https://zalo.me/g/... hoặc link code) để lấy Group ID.
  - `def format_relative_created_time(created_time_ms)` (Dòng 129) — Định dạng chuỗi thời gian tạo tương đối theo thuật toán của App Zalo
(com.zing.zalo.ui.zviews.GroupLobbyBottomSheetView.w6(J)Ljava/lang/String;).
- < 24h: 'Vừa tạo hôm nay'
- < 30.5 ngày: 'Đã tạo X ngày trước'
- < 365 ngày: 'Đã tạo X tháng trước'
- >= 365 ngày: 'Đã tạo hơn X năm trước'
  - `def preview_group_link(self, link_or_code)` (Dòng 165) — Xem trước thông tin nhóm / cộng đồng từ Link (tương ứng GroupLobbyView trong app Zalo).
Hiển thị đầy đủ: Tên nhóm/cộng đồng, người tạo ("nhóm của..."/"cộng đồng của..."), 
ngày tạo ("đã tạo ngày/tháng/năm"), số thành viên, mô tả, quyền duyệt và nút Tham Gia.

**Toàn bộ Comments & Chú thích Logic (13 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L39 | `# Check for explicit numeric GID in target string (6-15 digits)` | `# Check for explicit numeric GID in target string (6-15 digits)` |
| L95 | `# 1. Kiểm tra cache trong socket client nếu có` | `# 1. Kiểm tra cache trong socket client nếu có` |
| L101 | `# 2. Gửi yêu cầu phân giải qua Socket CMD 244 SUB 4` | `# 2. Gửi yêu cầu phân giải qua Socket CMD 244 SUB 4` |
| L113 | `# 3. Tra cứu qua Group HTTP API` | `# 3. Tra cứu qua Group HTTP API` |
| L142 | `# nếu là seconds thì đổi sang milliseconds` | `if ts < 1e11:  # nếu là seconds thì đổi sang milliseconds` |
| L147 | `# 0x5265c00` | `ONE_DAY_MS = 86400000.0  # 0x5265c00` |
| L148 | `# 0x9d11f600 (~30.5 ngày)` | `ONE_MONTH_MS = 2635200000.0  # 0x9d11f600 (~30.5 ngày)` |
| L149 | `# 365 ngày` | `ONE_YEAR_MS = 31536000000.0  # 365 ngày` |
| L176 | `# 1. Phân giải qua Socket CMD 901 SUB 3 (Preview Link)` | `# 1. Phân giải qua Socket CMD 901 SUB 3 (Preview Link)` |
| L187 | `# 2. Tra cứu qua Group HTTP API` | `# 2. Tra cứu qua Group HTTP API` |
| L191 | `# Trích xuất metadata` | `# Trích xuất metadata` |
| L227 | `# milliseconds timestamp` | `if ts > 1e11:  # milliseconds timestamp` |
| L237 | `# Định dạng text hiển thị chuẩn UI GroupLobbyView của App Zalo` | `# Định dạng text hiển thị chuẩn UI GroupLobbyView của App Zalo` |

---

### 📁 Thư mục: `core/api/group/action/`

#### 📄 `core/api/group/action/add.py` (45 dòng)
**Mô tả Module:**
```text
core/api/group/action/add.py — Thêm / mời thành viên vào nhóm chat.
Tương ứng Go reference: internal/api/group/action/action-methods.go (AddMembers)
```
**Danh sách Class:**
- `class AddAPI` (Dòng 15): Quản lý thêm / mời thành viên vào nhóm qua Socket (CMD 235 SUB 0).
  - `def add_member(self, group_id, member_uids, is_invite)` (Dòng 18) — Thêm hoặc mời thành viên vào nhóm chat (CMD 235 SUB 0, bb=1, ty=1).
  - `def invite_member(self, group_id, member_uids)` (Dòng 39) — Gửi lời mời tham gia nhóm tới thành viên.

---

#### 📄 `core/api/group/action/api.py` (28 dòng)
**Mô tả Module:**
```text
core/api/group/action/api.py — GroupActionAPI: Tổng hợp các thao tác quản trị nhóm.
Tương ứng Go reference: internal/api/group/action/
```
**Danh sách Class:**
- `class GroupActionAPI` (Dòng 15): Facade service cho các hành động quản trị nhóm (Kick, Ban, Add, Leave, Join, Disband).

---

#### 📄 `core/api/group/action/ban.py` (61 dòng)
**Mô tả Module:**
```text
core/api/group/action/ban.py — Chặn / Ban thành viên khỏi nhóm chat.
Tương ứng Go reference: internal/api/group/action/action-methods.go (BlockUsers, UnblockUsers)
```
**Danh sách Class:**
- `class BanAPI` (Dòng 15): Quản lý chặn / cấm thành viên vào nhóm qua Socket (CMD 234 SUB 0 với is_block=True).
  - `def block_group_member(self, group_id, member_uids)` (Dòng 18) — Chặn / ban thành viên khỏi nhóm chat (CMD 234 SUB 0 với is_block=True).
  - `def ban_member(self, group_id, member_uids)` (Dòng 43) — Thực hiện thao tác Ban thành viên: Kick kèm Chặn không cho vào lại nhóm (CMD 234 SUB 0 với is_block=True).

---

#### 📄 `core/api/group/action/disband.py` (50 dòng)
**Mô tả Module:**
```text
core/api/group/action/disband.py — Giải tán nhóm chat hoặc rời nhóm chuyển quyền.
Tương ứng Go reference: internal/api/group/action/
```
**Danh sách Class:**
- `class DisbandAPI` (Dòng 15): Giải tán nhóm thật (CMD 242 SUB 0, pn/g0.h2). 1705 chỉ là group-event, KHÔNG disband.
  - `def disband_group_242(self, group_id)` (Dòng 18) — Giải tán nhóm (CMD 242: 01 vercode gid).
  - `def send_group_event_1705(self, group_id, owner_uid)` (Dòng 33) — Group event 1705 (giữ tương thích, KHÔNG phải disband).

---

#### 📄 `core/api/group/action/join.py` (154 dòng)
**Mô tả Module:**
```text
core/api/group/action/join.py — Tham gia nhóm chat qua Link hoặc ID.
Tương ứng Go reference: internal/api/group/action/action-methods.go (JoinGroup)
```
**Danh sách Class:**
- `class JoinAPI` (Dòng 16): Quản lý tham gia nhóm qua Socket (CMD 901 SUB 3, CMD 2000 SUB 3, CMD 246 SUB 3, CMD 244 SUB 4, CMD 250 SUB 1).
  - `def join_group_by_id(self, group_id, msg, source)` (Dòng 21) — Tham gia nhóm Zalo qua Group ID / UID (CMD 2000 SUB 3, CMD 246 SUB 3, CMD 244 SUB 4).
  - `def join_group_by_link(self, link_or_code, msg, source, group_id)` (Dòng 43) — Tham gia qua link. Giữ FULL URL https://zalo.me/g/... + gid đã biết (nếu có).
  - `def join_group(self, target, msg, source)` (Dòng 143) — Phương thức vạn năng: tự nhận diện Link URL hoặc Group ID.

**Toàn bộ Comments & Chú thích Logic (3 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L80 | `# 1. Gửi CMD 901 SUB 3 (Link Preview & Interaction)` | `# 1. Gửi CMD 901 SUB 3 (Link Preview & Interaction)` |
| L93 | `# 2. Gửi CMD 244 SUB 4 (Request Join Group qua Link/Code)` | `# 2. Gửi CMD 244 SUB 4 (Request Join Group qua Link/Code)` |
| L111 | `# 3. Nếu đã xác định được GID, gửi thêm CMD 2000 SUB 3` | `# 3. Nếu đã xác định được GID, gửi thêm CMD 2000 SUB 3` |

---

#### 📄 `core/api/group/action/kick.py` (51 dòng)
**Mô tả Module:**
```text
core/api/group/action/kick.py — Kick / xóa thành viên khỏi nhóm chat.
Tương ứng Go reference: internal/api/group/action/action-methods.go (KickUsers)
```
**Danh sách Class:**
- `class KickAPI` (Dòng 15): Xoá member: toggle TẮT = 228 (du/b.r), toggle BẬT = 234 flag 1 (pn/g0.k).
  - `def remove_member(self, group_id, member_uids)` (Dòng 18) — Xoá khỏi nhóm KHÔNG block (CMD 228 SUB 0).
  - `def kick_member(self, group_id, member_uids, is_block)` (Dòng 33) — Xóa/kick (CMD 228 khi is_block=False) hoặc block (CMD 234 flag 1 khi is_block=True).

---

#### 📄 `core/api/group/action/leave.py` (51 dòng)
**Mô tả Module:**
```text
core/api/group/action/leave.py — Rời / thoát khỏi nhóm chat.
Tương ứng Go reference: internal/api/group/action/action-methods.go (LeaveGroup)
```
**Danh sách Class:**
- `class LeaveAPI` (Dòng 15): Quản lý rời nhóm chat qua Socket (CMD 239 SUB 1).
  - `def leave_group(self, group_id, new_owner_id, silent, block_readd, wait_response, timeout)` (Dòng 18) — Rời khỏi nhóm chat (CMD 239 SUB 1, bb=0, ty=1).

Tham số:
  - group_id: ID nhóm chat
  - new_owner_id: UID chủ nhóm mới (nếu chuyển nhượng quyền creator)
  - silent: Rời nhóm trong im lặng (chỉ báo admin)
  - block_readd: Chặn không cho mời lại vào nhóm này
  - wait_response: Chờ server trả về ACK xác nhận thành công

---

### 📁 Thư mục: `core/api/group/message/`

#### 📄 `core/api/group/message/api.py` (22 dòng)
**Mô tả Module:**
```text
core/api/group/message/api.py — GroupMessageAPI: Tổng hợp các tính năng bảng tin & tin nhắn nhóm.
Tương ứng Go reference: internal/api/group/message/
```
**Danh sách Class:**
- `class GroupMessageAPI` (Dòng 12): Facade service cho các tính năng bảng tin nhóm (Ghim, Bỏ ghim, Bình chọn).

---

#### 📄 `core/api/group/message/pin.py` (55 dòng)
**Mô tả Module:**
```text
core/api/group/message/pin.py — Ghim tin nhắn & Xem danh sách tin nhắn đã ghim trong nhóm.
Tương ứng Go reference: internal/api/group/message/message-methods.go (PinMessage)
```
**Danh sách Class:**
- `class PinAPI` (Dòng 15): Quản lý ghim tin nhắn & xem danh sách ghim qua Socket (CMD 1752 SUB 2 & CMD 1703 SUB 0).
  - `def pin_message(self, group_id, title, cli_msg_id, global_msg_id, sender_uid, sender_name)` (Dòng 18) — Ghim tin nhắn / Tạo Topic quan trọng trong nhóm chat (CMD 1752 SUB 2).
  - `def get_pinned_topics(self, group_id)` (Dòng 44) — Lấy danh sách các tin nhắn / topic đã ghim trong nhóm (CMD 1703 SUB 0).

---

#### 📄 `core/api/group/message/poll.py` (37 dòng)
**Mô tả Module:**
```text
core/api/group/message/poll.py — Tạo cuộc bình chọn (Poll) trong nhóm chat.
Tương ứng Go reference: internal/api/group/action/action-methods.go (CreatePoll, VotePoll, LockPoll)
```
**Danh sách Class:**
- `class PollAPI` (Dòng 15): Quản lý tạo và điều khiển cuộc bình chọn (Poll) qua Socket (CMD 1640 SUB 3).
  - `def create_poll(self, group_id, question, options)` (Dòng 18) — Tạo cuộc bình chọn trong nhóm chat (CMD 1640 SUB 3).

---

#### 📄 `core/api/group/message/unpin.py` (37 dòng)
**Mô tả Module:**
```text
core/api/group/message/unpin.py — Bỏ ghim tin nhắn trong nhóm chat.
Tương ứng Go reference: internal/api/group/message/message-methods.go (UnpinMessage)
```
**Danh sách Class:**
- `class UnpinAPI` (Dòng 15): Quản lý bỏ ghim tin nhắn trong nhóm qua Socket (CMD 1703 SUB 0).
  - `def unpin_message(self, group_id, global_msg_id, cli_msg_id)` (Dòng 18) — Bỏ ghim tin nhắn trong nhóm qua Socket (CMD 1703 SUB 0).

---

### 📁 Thư mục: `core/api/handle/`

#### 📄 `core/api/handle/api.py` (32 dòng)
**Mô tả Module:**
```text
core/api/handle/api.py — SendAPI: Tổng hợp các tính năng gửi tin nhắn và tương tác.
Tương ứng Go reference: internal/api/handle/
```
**Danh sách Class:**
- `class SendAPI` (Dòng 17): Facade service tập hợp tất cả các API gửi tin nhắn, ảnh, video, doodle, reaction, typing, xóa tin, chặn user.

---

#### 📄 `core/api/handle/blockUser.py` (9 dòng)
**Mô tả Module:**
```text
core/api/handle/blockUser.py — Alias module cho BlockUserAPI.
```
---

#### 📄 `core/api/handle/block_user.py` (38 dòng)
**Mô tả Module:**
```text
core/api/handle/block_user.py — API Chặn và bỏ chặn người dùng 1-1.
Tương ứng Go reference: internal/api/handle/block-user.go, unblock-user.go
```
**Danh sách Class:**
- `class BlockUserAPI` (Dòng 15): Quản lý chặn / bỏ chặn người dùng 1-1 (CMD 382, CMD 383, CMD 821).
  - `def block_user(self, target_uid, is_block)` (Dòng 18) — Chặn người dùng 1-1 (CMD 382 SUB 0 / CMD 821 SUB 3).
  - `def unblock_user(self, target_uid)` (Dòng 29) — Bỏ chặn người dùng 1-1 (CMD 383 SUB 0).

---

#### 📄 `core/api/handle/sendDoodle.py` (9 dòng)
**Mô tả Module:**
```text
core/api/handle/sendDoodle.py — Alias module cho SendDoodleAPI.
```
---

#### 📄 `core/api/handle/sendImage.py` (9 dòng)
**Mô tả Module:**
```text
core/api/handle/sendImage.py — Alias module cho SendImageAPI.
```
---

#### 📄 `core/api/handle/sendMessage.py` (9 dòng)
**Mô tả Module:**
```text
core/api/handle/sendMessage.py — Alias module cho SendMessagesAPI.
```
---

#### 📄 `core/api/handle/sendReaction.py` (9 dòng)
**Mô tả Module:**
```text
core/api/handle/sendReaction.py — Alias module cho SendReactionAPI.
```
---

#### 📄 `core/api/handle/sendTyping.py` (9 dòng)
**Mô tả Module:**
```text
core/api/handle/sendTyping.py — Alias module cho SendTypingAPI.
```
---

#### 📄 `core/api/handle/sendVideo.py` (9 dòng)
**Mô tả Module:**
```text
core/api/handle/sendVideo.py — Alias module cho SendVideoAPI.
```
---

#### 📄 `core/api/handle/send_doodle.py` (99 dòng)
**Mô tả Module:**
```text
core/api/handle/send_doodle.py — API gửi Doodle / Hình vẽ (SUB 37).
```
**Danh sách Class:**
- `class SendDoodleAPI` (Dòng 16): API chuyên biệt cho gửi Doodle / Hình vẽ.
  - `def send_doodle(self, target_id, doodle_url_or_path, thread_type, caption, title, description, thumb_url, hd_url, width, height, total_size, ttl, quote_data, native, sub_type, is_original)` (Dòng 19) — Gửi hình vẽ (doodle / SUB 37) tới Nhóm hoặc Cá nhân 1-1.
  - `def send_group_doodle(self, group_id, doodle_url_or_path, caption)` (Dòng 69) — Shortcut gửi hình vẽ (doodle) tới nhóm chat.
  - `def send_1to1_doodle(self, to_uid, doodle_url_or_path, caption)` (Dòng 85) — Shortcut gửi hình vẽ (doodle) tới cá nhân 1-1.

---

#### 📄 `core/api/handle/send_image.py` (114 dòng)
**Mô tả Module:**
```text
core/api/handle/send_image.py — API gửi hình ảnh (Image / Photo / SUB 32).
```
**Danh sách Class:**
- `class SendImageAPI` (Dòng 16): API chuyên biệt cho gửi hình ảnh (Image / Photo).
  - `def send_photo(self, target_id, photo_url_or_path, thread_type, caption, title, description, width, height, total_size, thumb_url, hd_url, ttl, quote_data, native, sub_type, is_original)` (Dòng 19) — Gửi hình ảnh (photo / media attachment) tới Nhóm hoặc Cá nhân 1-1.
Tự động phân giải kích thước ảnh (width, height, size) nếu chưa được chỉ định.
  - `def send_group_photo(self, group_id, photo_url_or_path, caption)` (Dòng 80) — Shortcut gửi hình ảnh tới nhóm chat.
  - `def send_1to1_photo(self, to_uid, photo_url_or_path, caption)` (Dòng 96) — Shortcut gửi hình ảnh tới cá nhân 1-1.

---

#### 📄 `core/api/handle/send_messages.py` (93 dòng)
**Mô tả Module:**
```text
core/api/handle/send_messages.py — API gửi tin nhắn (Text, Mention, Quote, Native RTF Styles).
Tương ứng Go reference: internal/api/handle/send-messages.go, normal-mentions.go, all-mentions.go
```
**Danh sách Class:**
- `class SendMessagesAPI` (Dòng 17): Quản lý gửi tin nhắn văn bản, trích dẫn (quote), mention và kiểu chữ qua Socket Gateway.
  - `def send_message(self, thread_id, text, thread_type, quote_data, mentions, style_id, size, color, bold, italic, underline, strike, fontsize, list_type, ttl)` (Dòng 20) — Gửi tin nhắn đa năng tới Nhóm (CMD 207 SUB 1) hoặc Cá nhân 1-1 (CMD 113 SUB 41).
  - `def send_group_message(self, group_id, text)` (Dòng 87) — Shortcut gửi tin nhắn tới nhóm chat.
  - `def send_1to1_message(self, to_uid, text)` (Dòng 91) — Shortcut gửi tin nhắn tới cá nhân 1-1.

---

#### 📄 `core/api/handle/send_reaction.py` (47 dòng)
**Mô tả Module:**
```text
core/api/handle/send_reaction.py — API thả cảm xúc vào tin nhắn (Reaction).
Tương ứng Go reference: internal/api/handle/send-reaction.go, send-multi-reaction.go
```
**Danh sách Class:**
- `class SendReactionAPI` (Dòng 16): Quản lý thả cảm xúc vào tin nhắn qua Socket (CMD 1785 / 1780 SUB 0).
  - `def send_reaction(self, target_id, cli_msg_id, global_msg_id, icon, is_group)` (Dòng 19) — Thả cảm xúc (❤️, 👍, 😂, 😮, 😭, 😡, 💔) vào tin nhắn.

---

#### 📄 `core/api/handle/send_typing.py` (26 dòng)
**Mô tả Module:**
```text
core/api/handle/send_typing.py — API gửi trạng thái đang soạn tin (Typing).
```
**Danh sách Class:**
- `class SendTypingAPI` (Dòng 15): API chuyên biệt cho Typing indicator.
  - `def send_typing(self, target_id, is_group)` (Dòng 18) — Gửi trạng thái đang soạn tin nhắn.

---

#### 📄 `core/api/handle/send_video.py` (109 dòng)
**Mô tả Module:**
```text
core/api/handle/send_video.py — API gửi Video (Video / SUB 44).
```
**Danh sách Class:**
- `class SendVideoAPI` (Dòng 16): API chuyên biệt cho gửi Video.
  - `def send_video(self, target_id, video_url_or_path, thread_type, caption, title, description, thumb_url, width, height, duration_ms, total_size, ttl, quote_data, native, sub_type)` (Dòng 19) — Gửi video (video / media attachment) tới Nhóm hoặc Cá nhân 1-1.
Tự động phân giải metadata video nếu chưa được chỉ định.
  - `def send_group_video(self, group_id, video_url_or_path, caption)` (Dòng 79) — Shortcut gửi video tới nhóm chat.
  - `def send_1to1_video(self, to_uid, video_url_or_path, caption)` (Dòng 95) — Shortcut gửi video tới cá nhân 1-1.

---

#### 📄 `core/api/handle/undoMessage.py` (9 dòng)
**Mô tả Module:**
```text
core/api/handle/undoMessage.py — Alias module cho UndoMessageAPI.
```
---

#### 📄 `core/api/handle/undo_message.py` (78 dòng)
**Mô tả Module:**
```text
core/api/handle/undo_message.py — Xóa và thu hồi tin nhắn (Recall / Delete).
Tách riêng hoàn toàn logic giữa Xóa tin nhắn (Delete CMD 205) và Thu hồi tin nhắn (Recall CMD 204).
Tương ứng Go reference: internal/api/properties/undo-message.go & internal/api/group/message/message-methods.go
```
**Danh sách Class:**
- `class UndoMessageAPI` (Dòng 16): Quản lý xóa tin nhắn (CMD 205 SUB 3) & thu hồi tin nhắn (CMD 204 SUB 2).
  - `def delete_message(self, group_id, cli_msg_id, global_msg_id, owner_id, is_group, only_me)` (Dòng 19) — Xóa tin nhắn qua Socket (CMD 205 SUB 3):
- only_me=True: Xóa chỉ ở phía mình (t_type=3 cho group / 1 cho 1-1, il=2)
- only_me=False: Xóa tin nhắn khỏi cuộc trò chuyện
  - `def recall_message(self, group_id, cli_msg_id, global_msg_id, owner_id, is_group)` (Dòng 51) — Thu hồi tin nhắn (Undo/Recall) cho tất cả mọi người (CMD 204 SUB 2).
Độc lập hoàn toàn, không phụ thuộc hay ảnh hưởng đến delete_message.

---

### 📁 Thư mục: `core/api/properties/`

#### 📄 `core/api/properties/api.py` (22 dòng)
**Mô tả Module:**
```text
core/api/properties/api.py — PropertiesAPI: Quản lý trạng thái và thuộc tính tin nhắn / phiên.
Tương ứng Go reference: internal/api/properties/
```
**Danh sách Class:**
- `class PropertiesAPI` (Dòng 12): Facade service cho các thuộc tính tin nhắn và trạng thái người dùng.

---

#### 📄 `core/api/properties/receipts.py` (38 dòng)
**Mô tả Module:**
```text
core/api/properties/receipts.py — Báo cáo đã nhận và đã đọc tin nhắn (Delivery / Read receipts).
Tương ứng Go reference: internal/api/properties/mark-as-delivered.go, mark-as-read.go
```
**Danh sách Class:**
- `class ReceiptsAPI` (Dòng 15): Quản lý thông báo đã nhận / đã xem tin nhắn qua Socket (CMD 202 SUB 3).
  - `def mark_as_delivered(self, group_id, sender_uid, cli_msg_id, global_msg_id)` (Dòng 18) — Gửi ACK đã nhận tin nhắn trong nhóm.

---

#### 📄 `core/api/properties/typing.py` (30 dòng)
**Mô tả Module:**
```text
core/api/properties/typing.py — Báo trạng thái đang soạn tin nhắn (Typing indicator).
Tương ứng Go reference: internal/api/properties/set-typing.go
```
**Danh sách Class:**
- `class TypingAPI` (Dòng 15): Quản lý trạng thái đang soạn tin (CMD 206 SUB 1 cho Group, CMD 106 SUB 1 cho 1-1).
  - `def set_typing(self, thread_id, is_group)` (Dòng 18) — Gửi thông báo đang gõ phím.

---

### 📁 Thư mục: `core/login/`

#### 📄 `core/login/__main__.py` (93 dòng)
**Mô tả Module:**
```text
core/login/__main__.py — CLI Entrypoint cho Đăng nhập Zalo (Số điện thoại + Mật khẩu).
Hỗ trợ:
- Tự động giải Captcha trượt (Slide Captcha correlation matching)
- Xác thực 2 lớp qua SMS / Email / Cuộc gọi / Tổng đài OTP
- Xác thực qua danh sách bạn bè gần đây
- Đọc DK trực tiếp từ tệp zaloprefs SQLite (--zaloprefs <path> --uid <UID>)
- Thử nghiệm kết nối Socket PROV Handshake tức thì (<60s)
Tương thích 100% với zalo_login_v10.py.
```
**Danh sách Hàm (Functions):**
- `def main()` (Dòng 24)

---

#### 📄 `core/login/captcha.py` (124 dòng)
**Mô tả Module:**
```text
core/login/captcha.py — Tự động giải Slide Captcha cho quy trình đăng nhập Zalo.
Thuật toán Correlation Matching giữa ảnh nền và ảnh mảnh ghép (slice) tại tọa độ y=top.
Tương thích 100% với zalo_login_v10.py.
```
**Danh sách Hàm (Functions):**
- `def solve_captcha_img(bg_png, slice_png, top)` (Dòng 24) — Giải slide captcha: correlation matching giữa slice và bg tại y=top.
Trả về: (best_x_offset, confidence_score)
- `def captcha_flow(captcha_session, zcid)` (Dòng 65) — Tự động thực hiện chu trình: gen challenge -> solve -> verify -> captchaToken.
Trả về: captchaToken (str) hoặc None nếu thất bại.

**Toàn bộ Comments & Chú thích Logic (4 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L34 | `# Lấy các điểm pixel có độ mờ > 200 trong slice để làm mẫu so khớp` | `# Lấy các điểm pixel có độ mờ > 200 trong slice để làm mẫu so khớp` |
| L74 | `# 1. Tải Captcha Challenge (Background PNG + Slice PNG)` | `# 1. Tải Captcha Challenge (Background PNG + Slice PNG)` |
| L99 | `# 2. Giải tọa độ khớp` | `# 2. Giải tọa độ khớp` |
| L104 | `# 3. Gửi tọa độ xác thực` | `# 3. Gửi tọa độ xác thực` |

---

#### 📄 `core/login/client.py` (110 dòng)
**Mô tả Module:**
```text
core/login/client.py — Module Quản lý Xác thực, Đăng nhập & Khởi tạo Session Zalo qua HTTP/2 API.
Mô phỏng 100% quy trình đăng nhập zalo_login_v10.py.
```
**Danh sách Class:**
- `class ZaloLoginClient` (Dòng 34): Client tích hợp đầy đủ cho quy trình đăng nhập Zalo qua HTTP/2 API.
  - `def __init__(self, zcid, zcid_path, api_key, secret, client_version, renew_zcid)` (Dòng 37)
  - `def save_zcid(self, zcid)` (Dòng 57)
  - `def login(self, phone, password, out_session_path, real_friends, zaloprefs_path, target_uid, probe_socket)` (Dòng 61) — Thực hiện quy trình đăng nhập hoàn chỉnh và lưu session.

---

#### 📄 `core/login/device.py` (325 dòng)
**Mô tả Module:**
```text
core/login/device.py — Quản lý cấu hình thiết bị, mã hóa HTTP và ZCID cho Login.
Tương thích 100% với zalo_login_v10.py.
```
**Hằng số / Opcodes chính:** `INIT_KEY, DEFAULT_API_KEY, DEFAULT_SECRET, DEFAULT_BASE_KEY, DEFAULT_CS, DEFAULT_CERT, DEFAULT_CLIENT_VERSION, DEFAULT_USER_AGENT, REG_URL, ACC_URL, ZMVC_URL, ZMCAP_URL`

**Danh sách Class:**
- `class DeviceProfile` (Dòng 250): Quản lý thông tin cấu hình thiết bị di động.
  - `def __init__(self, params)` (Dòng 252)
  - `def default(cls)` (Dòng 258)
  - `def to_dict(self)` (Dòng 261)
  - `def __getattr__(self, item)` (Dòng 264)
  - `def __getitem__(self, item)` (Dòng 269)

**Danh sách Hàm (Functions):**
- `def pad16(d)` (Dòng 147) — PKCS7 padding cho khối 16 bytes.
- `def key32_96(zcid)` (Dòng 153) — Trích xuất khóa 32 bytes từ chuỗi ZCID 96-hex.
Lấy các ký tự chẵn từ 0..31 + 16 ký tự từ cuối lùi dần.
- `def norm_phone(p)` (Dòng 165) — Chuẩn hóa số điện thoại về định dạng +84...
- `def pwd_hash(phone, password, base_key)` (Dòng 175) — Tính mã băm mật khẩu AES-ECB với key MD5(BASE_KEY + phone)[5:21].
- `def gen_zcid96(init_key)` (Dòng 186) — Sinh ZCID 96 hex UPPERCASE hợp lệ.
AES-CBC(INIT_KEY, '0,unknown,SM-J610F,{ts_ms},0').
- `def is_valid_zcid(zcid_hex, init_key)` (Dòng 197) — Kiểm tra xem chuỗi ZCID 96-hex có giải mã được bằng INIT_KEY và hợp lệ không.
- `def enc_body(params, zcid, api_key, secret)` (Dòng 218) — Mã hóa AES-CBC toàn bộ body params và tính chữ ký MD5 signature.
- `def base_params(zcid, phone, password)` (Dòng 227) — Tạo bộ tham số mặc định kết hợp HAR device và thông tin người dùng.
- `def http_post_curl(url, body, zcid, timeout)` (Dòng 273) — Gửi HTTP/2 POST qua cURL với headers chuẩn Zalo Native.
- `def http_post_json_curl(url, body, zcid, cookie, timeout)` (Dòng 300) — Gửi HTTP/2 POST dạng Webview JSON/Form qua cURL.

**Toàn bộ Comments & Chú thích Logic (4 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L18 | `# ═══ HẰNG SỐ MÃ HÓA HTTP & XÁC THỰC ═══` | `# ═══ HẰNG SỐ MÃ HÓA HTTP & XÁC THỰC ═══` |
| L28 | `# Endpoints` | `# Endpoints` |
| L35 | `# ═══ CẤU HÌNH THIẾT BỊ SAMSUNG SM-J610F (HAR-EXACT) ═══` | `# ═══ CẤU HÌNH THIẾT BỊ SAMSUNG SM-J610F (HAR-EXACT) ═══` |
| L145 | `# ═══ MÃ HÓA & HÀM TIỆN ÍCH ═══` | `# ═══ MÃ HÓA & HÀM TIỆN ÍCH ═══` |

---

#### 📄 `core/login/password.py` (355 dòng)
**Mô tả Module:**
```text
core/login/password.py — Đăng nhập 2 bước chuẩn qua Số điện thoại & Mật khẩu.
Tự động xử lý Captcha trượt, xác thực 2FA OTP, xác thực bạn bè và kiểm tra Socket PROV Handshake tức thì.
Tương thích 100% với zalo_login_v10.py.
```
**Danh sách Class:**
- `class PasswordAuth` (Dòng 40): Xử lý toàn bộ quy trình đăng nhập Zalo qua HTTP/2 APIs và xác thực Socket PROV.
  - `def __init__(self, zcid, zcid_path, api_key, secret, client_version, renew_zcid)` (Dòng 43)
  - `def _init_zcid(self, zcid, renew_zcid)` (Dòng 58) — Khởi tạo ZCID: Ưu tiên zcid truyền vào -> file lưu trữ -> sinh mới.
  - `def _save_zcid_to_file(self, val)` (Dòng 84)
  - `def authenticate(self, phone, password, real_friends, out_session_path, zaloprefs_path, target_uid, probe_socket)` (Dòng 91) — Thực hiện toàn bộ quy trình đăng nhập:
1. phone/verify (tự động giải captcha slide nếu mã 2060)
2. activeAccountByPassword
   - Thành công trực tiếp (Trusted Device)
   - 2048: Yêu cầu 2FA OTP hoặc Xác thực Bạn bè
3. verifyAccount với verificationToken + ckeyset
4. Lưu fresh_session.json
5. Kiểm tra socket PROV authen tức thì
  - `def _process_login_success(self, data, t_start, out_session_path, zaloprefs_path, target_uid, probe_socket)` (Dòng 260) — Xử lý khi đăng nhập thành công: bóc tách khóa, lưu file và probe socket.

**Danh sách Hàm (Functions):**
- `def login(phone, password, real_friends, out_session_path, zcid, renew_zcid, zaloprefs_path, target_uid, probe_socket)` (Dòng 334) — Hàm tiện ích đăng nhập nhanh từ Python script hoặc module khác.

**Toàn bộ Comments & Chú thích Logic (12 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L77 | `# Sinh mới ZCID 96-hex` | `# Sinh mới ZCID 96-hex` |
| L118 | `# ── BƯỚC 1: XÁC THỰC SỐ ĐIỆN THOẠI ──` | `# ── BƯỚC 1: XÁC THỰC SỐ ĐIỆN THOẠI ──` |
| L136 | `# Xử lý Captcha trượt tự động nếu gặp lỗi 2060` | `# Xử lý Captcha trượt tự động nếu gặp lỗi 2060` |
| L154 | `# ── BƯỚC 2: ĐĂNG NHẬP MẬT KHẨU ──` | `# ── BƯỚC 2: ĐĂNG NHẬP MẬT KHẨU ──` |
| L168 | `# Trường hợp A: Đăng nhập thành công trực tiếp (Thiết bị tin cậy / Trusted Device)` | `# Trường hợp A: Đăng nhập thành công trực tiếp (Thiết bị tin cậy / Trusted De...` |
| L174 | `# Trường hợp B: Bắt buộc xác thực 2 bước (2FA hoặc Bạn bè)` | `# Trường hợp B: Bắt buộc xác thực 2 bước (2FA hoặc Bạn bè)` |
| L180 | `# Bóc tách session 2FA từ secureUrl` | `# Bóc tách session 2FA từ secureUrl` |
| L189 | `# ── BƯỚC 3a: 2FA VERIFICATION CENTER (SMS / Email / Cuộc gọi / Tổng đài) ──` | `# ── BƯỚC 3a: 2FA VERIFICATION CENTER (SMS / Email / Cuộc gọi / Tổng đài) ──` |
| L222 | `# ── BƯỚC 3: XÁC THỰC BẠN BÈ (Friend Verification) ──` | `# ── BƯỚC 3: XÁC THỰC BẠN BÈ (Friend Verification) ──` |
| L233 | `# ── BƯỚC 4: verifyAccount (Friend Verify token + ckeyset) ──` | `# ── BƯỚC 4: verifyAccount (Friend Verify token + ckeyset) ──` |
| L277 | `# Đọc DK từ zaloprefs nếu được chỉ định` | `# Đọc DK từ zaloprefs nếu được chỉ định` |
| L315 | `# Thử nghiệm Socket PROV Handshake tức thì (<60s từ lúc login)` | `# Thử nghiệm Socket PROV Handshake tức thì (<60s từ lúc login)` |

---

#### 📄 `core/login/probe.py` (166 dòng)
**Mô tả Module:**
```text
core/login/probe.py — Thử nghiệm và xác thực tức thì gói PROV Handshake (Frame 0) trên Gateway.
Kiểm tra tính hợp lệ của bộ khóa (DK, session_key, KSID, UID) ngay sau khi đăng nhập (<60s).
Tương thích 100% với zalo_login_v10.py.
```
**Danh sách Hàm (Functions):**
- `def build_p110(sk_str, uid_int, vercode)` (Dòng 24) — Tạo khối dữ liệu 110 bytes (p110) chứa session_key được mã hóa XOR keystream.
Inner structure: 01 + ff*4 + 0000 + vercode + 02 + len(model) + model + len(imei) + imei + 00*6 + len(sk) + sk.
- `def calc_cs(uid_int, ctr, cmd, dirn, sub, seq_b)` (Dòng 44) — Tính toán Checksum xác thực cho PROV Frame 0.
- `def probe_socket_authen(sk, dk, ksid, servers, uid_int, ctr, timeout)` (Dòng 50) — Gửi thử Frame 0 PROV tới danh sách máy chủ Socket Zalo để kiểm tra xác thực.
Trả về: (results_list, is_success)

**Toàn bộ Comments & Chú thích Logic (2 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L79 | `# Bỏ qua IPv6 khi probe nhanh` | `if not host or not pub_key_b64 or ':' in host:  # Bỏ qua IPv6 khi probe nhanh` |
| L89 | `# X25519 ECDH Handshake` | `# X25519 ECDH Handshake` |

---

#### 📄 `core/login/qr.py` (36 dòng)
**Mô tả Module:**
```text
core/login/qr.py — Quản lý xác thực đăng nhập qua QR Code.
```
**Danh sách Class:**
- `class QRAuth` (Dòng 13): Quản lý tạo mã QR, thăm dò trạng thái quét (polling) và kích hoạt session qua QR.
  - `def __init__(self, zcid)` (Dòng 16)
  - `def generate_qr(self)` (Dòng 21) — Khởi tạo phiên QR Code mới.
  - `def check_status(self)` (Dòng 31) — Kiểm tra trạng thái quét mã QR từ thiết bị chính.

**Toàn bộ Comments & Chú thích Logic (1 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L24 | `# Template / placeholder cho luồng QR login` | `# Template / placeholder cho luồng QR login` |

---

#### 📄 `core/login/session.py` (177 dòng)
**Mô tả Module:**
```text
core/login/session.py — Quản lý trích xuất, đọc zaloprefs SQLite và lưu Session Zalo.
Tương thích 100% với zalo_login_v10.py.
```
**Danh sách Class:**
- `class SessionManager` (Dòng 85): Quản lý đọc và ghi session file và zaloprefs SQLite.
  - `def save(data, filepath)` (Dòng 88)
  - `def load(filepath)` (Dòng 92)
  - `def load_zaloprefs(prefs_path, uid)` (Dòng 97)
  - `def extract_dk(data)` (Dòng 101) — Trích xuất DK (32 bytes) từ session dictionary.
  - `def extract_cryptkey(data)` (Dòng 140) — Trích xuất cryptkey từ session dictionary.
  - `def validate(data)` (Dòng 164) — Kiểm tra tính hợp lệ tối thiểu của một session dictionary.

**Danh sách Hàm (Functions):**
- `def extract_all(response)` (Dòng 18) — Bóc tách tất cả các khóa và thông tin xác thực từ response đăng nhập.
- `def read_from_zaloprefs(prefs_path, uid)` (Dòng 45) — Đọc trực tiếp DK (Session KeySet Value) và KeySet ID từ tệp zaloprefs (SQLite database).
Bảng: prefs_v2
Khóa: KEY_STRING_SOCKET_PRO_V1_KEY_SET_VALUE_{UID}, KEY_STRING_SOCKET_PRO_V1_KEY_SET_ID_{UID}
- `def save_session_file(session_data, filepath)` (Dòng 73) — Lưu session dictionary ra tệp JSON hoàn chỉnh.

**Toàn bộ Comments & Chú thích Logic (4 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L105 | `# 1. dk trực tiếp (bytes / hex)` | `# 1. dk trực tiếp (bytes / hex)` |
| L114 | `# 2. dk_hex` | `# 2. dk_hex` |
| L121 | `# 3. dk_b64` | `# 3. dk_b64` |
| L128 | `# 4. keySet.keySetValue (base64)` | `# 4. keySet.keySetValue (base64)` |

---

#### 📄 `core/login/two_factor.py` (258 dòng)
**Mô tả Module:**
```text
core/login/two_factor.py — Quản lý các phương thức xác thực nâng cao (2FA OTP & Bạn bè).
Bao gồm:
1. Nhánh 2FA Verification Center (SMS, Email, Cuộc gọi OTP, Tổng đài)
2. Nhánh Friend Verification (Auto-match theo danh sách tên hoặc lựa chọn thủ công)
Tương thích 100% với zalo_login_v10.py.
```
**Hằng số / Opcodes chính:** `METHOD_NAMES`

**Danh sách Class:**
- `class TwoFactorAuth` (Dòng 31): Quản lý xác thực 2 lớp qua Webview Verification Center.
  - `def get_webview_html(session)` (Dòng 35) — Tải mã HTML của giao diện 2FA từ Verification Center.
  - `def post_vc_json(url, session, data)` (Dòng 47) — Gửi request JSON tới Verification Center API.
  - `def extract_available_methods(cls, session)` (Dòng 65) — Bóc tách danh sách các phương thức 2FA khả dụng và bị khóa (rate-limited).
  - `def execute_2fa_flow(cls, session, interactive)` (Dòng 93) — Thực hiện toàn bộ quy trình 2FA chuẩn zalo_login_v10:
1. Liệt kê phương thức khả dụng (SMS, email, SĐT, tổng đài OTP)
2. Người dùng tự chọn phương thức mong muốn (input)
3. Gửi mã OTP tới phương thức đã chọn
4. Người dùng tự nhập mã OTP (input, tối đa 3 lần)
5. Trả về verificationToken
- `class FriendAuth` (Dòng 166): Quản lý xác thực tài khoản qua danh sách bạn bè gần đây.
  - `def execute_friend_flow(session, zcid, cookie, real_friends, interactive)` (Dòng 170) — Thực hiện chu trình xác thực bạn bè chuẩn zalo_login_v10:
1. Tải danh sách câu hỏi / bạn bè
2. Tự động so khớp với real_friends nếu có
3. Nếu không đủ tên → người dùng tự nhập số thứ tự các bạn bè qua input()
4. Trả về access_token (verificationToken)

**Toàn bộ Comments & Chú thích Logic (2 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L159 | `# Sai mã: KHÔNG resend (mã cũ vẫn dùng được, resend → -1001 rate-limit)` | `# Sai mã: KHÔNG resend (mã cũ vẫn dùng được, resend → -1001 rate-limit)` |
| L229 | `# Loại trùng nhưng giữ nguyên thứ tự` | `# Loại trùng nhưng giữ nguyên thứ tự` |

---

### 📁 Thư mục: `core/models/`

#### 📄 `core/models/enums.py` (131 dòng)
**Mô tả Module:**
```text
core/models/enums.py — Các Enums định nghĩa trạng thái, loại luồng chat và icon cảm xúc trong Zalo.
```
**Danh sách Class:**
- `class ThreadType` (Dòng 10): Không có docstring
- `class Gender` (Dòng 15): Không có docstring
  - `def to_display_string(cls, code)` (Dòng 21)
- `class MessageType` (Dòng 29): Không có docstring
- `class ReactionIcon` (Dòng 37): Không có docstring
  - `def resolve(cls, val)` (Dòng 56) — Phân giải bất kỳ input reaction nào thành tuple (rType, rIcon, display_name).
- Standard: ❤️ (5, '/-heart'), 👍 (0, ':>'), 😂 (3, ':-D'), 😮 (32, ':-O'), 😭 (2, ':-(( '), 😡 (4, ':-t')
- Extended: 👎 (1, '/-weak'), 💔 (6, '/-break'), emoticons chuẩn Zalo
- Custom: Bất kỳ Emoji (👉, 🔥, 🎉, 🚀) hoặc Text ('h', 'ok', ...) -> (75, val, val)
- Remove: (-1, '', 'Hủy cảm xúc')
  - `def from_str(cls, val)` (Dòng 98)
- `class ZaloGroupErrorCode` (Dòng 103): Mã lỗi quản trị và tham gia nhóm trích xuất chính xác từ smali ToastUtils (0x426a - 0x4282).
  - `def get_message(cls, code)` (Dòng 117)

**Toàn bộ Comments & Chú thích Logic (10 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L94 | `# Custom emoji hoặc text tùy chỉnh (vd: "👉", "h", "🔥", "🚀")` | `# Custom emoji hoặc text tùy chỉnh (vd: "👉", "h", "🔥", "🚀")` |
| L106 | `# 0x426a: str_error_group_not_existed (Nhóm không còn tồn tại)` | `GROUP_NOT_EXISTED = 17002      # 0x426a: str_error_group_not_existed (Nhóm kh...` |
| L107 | `# 0x426b: str_error_group_full (Nhóm đã đầy thành viên)` | `GROUP_FULL = 17003             # 0x426b: str_error_group_full (Nhóm đã đầy th...` |
| L108 | `# 0x426d: str_error_group_block (Bạn đã bị chặn khỏi nhóm)` | `GROUP_BLOCKED = 17005          # 0x426d: str_error_group_block (Bạn đã bị chặ...` |
| L109 | `# 0x426e: str_error_group_link_expired (Link tham gia nhóm đã hết hạn hoặc bị hủy)` | `LINK_EXPIRED = 17006           # 0x426e: str_error_group_link_expired (Link t...` |
| L110 | `# 0x4270: str_error_group_need_approval (Yêu cầu tham gia đang chờ duyệt)` | `NEED_APPROVAL = 17008          # 0x4270: str_error_group_need_approval (Yêu c...` |
| L111 | `# 0x4271: str_error_group_already_member (Bạn đã là thành viên của nhóm này)` | `ALREADY_MEMBER = 17009         # 0x4271: str_error_group_already_member (Bạn ...` |
| L112 | `# 0x4279: ERROR_OVER_NUMBER_JOINED_GROUP_PER_USER (Đạt giới hạn tham gia nhóm)` | `OVER_JOIN_LIMIT = 17017        # 0x4279: ERROR_OVER_NUMBER_JOINED_GROUP_PER_U...` |
| L113 | `# 0x427a: ERROR_OVER_NUMBER_OWNED_GROUP_PER_USER (Đạt giới hạn sở hữu nhóm)` | `OVER_OWN_LIMIT = 17018         # 0x427a: ERROR_OVER_NUMBER_OWNED_GROUP_PER_US...` |
| L114 | `# 0x4282: str_error_community_full (Cộng đồng đã đạt giới hạn thành viên)` | `COMMUNITY_FULL = 17026         # 0x4282: str_error_community_full (Cộng đồng ...` |

---

#### 📄 `core/models/message.py` (56 dòng)
**Mô tả Module:**
```text
core/models/message.py — Data models cho Tin nhắn và Trích dẫn (Quote).
```
**Danh sách Class:**
- `class Quote` (Dòng 12): Không có docstring
  - `def to_dict(self)` (Dòng 23)
- `class Message` (Dòng 45): Không có docstring

---

#### 📄 `core/models/user.py` (131 dòng)
**Mô tả Module:**
```text
core/models/user.py — Data model cho User Profile Zalo.
```
**Hằng số / Opcodes chính:** `TZ_VN`

**Danh sách Class:**
- `class UserProfile` (Dòng 15): Không có docstring
  - `def from_dict(cls, d)` (Dòng 33)
  - `def gender_display(self)` (Dòng 102) — Chuỗi hiển thị giới tính có icon.
  - `def to_card(self)` (Dòng 106) — Định dạng hồ sơ thành thẻ thông tin chi tiết đẹp mắt.

**Toàn bộ Comments & Chú thích Logic (2 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L55 | `# Last online formatting` | `# Last online formatting` |
| L77 | `# Account creation estimation` | `# Account creation estimation` |

---

### 📁 Thư mục: `core/socket/`

#### 📄 `core/socket/blockUser.py` (15 dòng)
**Mô tả Module:**
```text
core/socket/blockUser.py — TCP Binary Protocol Builder cho Block / Unblock User.
```
---

#### 📄 `core/socket/client.py` (562 dòng)
**Mô tả Module:**
```text
core/socket/client.py — Module Tầng Mạng Socket TCP Binary Client cho Zalo Protocol (ZaloSocketClient Hub).
Kiến trúc Modular kế thừa các Action Mixins độc lập (Single Responsibility / zalos.go reference):
- SendMessageActionMixin: Gửi tin nhắn text, mentions, quote, RTF styling, set conversation TTL
- SendImageActionMixin: Gửi hình ảnh / Photo / Image (SUB 32)
- SendVideoActionMixin: Gửi Video (SUB 44)
- SendDoodleActionMixin: Gửi Hình vẽ / Doodle (SUB 37)
- SendReactionActionMixin: Thả cảm xúc reaction (CMD 1785/1780)
- SendTypingActionMixin: Gửi typing indicator (CMD 206/106)
- PinTopicActionMixin: Ghim, bỏ ghim và lấy danh sách pinned topics (CMD 1752/1708/1703)
- PollActionMixin: Tạo bình chọn (CMD 1640)
- UndoMessageActionMixin: Thu hồi và xóa tin nhắn (CMD 204/114/205)
- GroupActionsMixin: Kick, Ban, Remove, Add, Leave, Join, Disband group (CMD 228/234/235/225/239/242/901/902/2000)
- BlockUserActionMixin: Chặn & bỏ chặn người dùng 1-1 (CMD 382/383)
```
**Hằng số / Opcodes chính:** `DEFAULT_SERVERS`

**Danh sách Class:**
- `class ZaloSocketClient` (Dòng 72): Zalo TCP Socket Network Engine & API Hub.
  - `def __init__(self, uid, dk, cryptkey, session_key, ksid, server_pubkey_b64, frame0_path, init_sequence_path, server_pool, state_file, on_message_callback, ping_interval, debug)` (Dòng 87)
  - `def _prepare_cmd_ack(self, cmd)` (Dòng 146)
  - `def _wait_cmd_ack(self, cmd, timeout)` (Dòng 155)
  - `def _try_load_frame0(self)` (Dòng 165)
  - `def _resolve_state_file(self)` (Dòng 186)
  - `def _load_or_init_state(self)` (Dòng 199)
  - `def _save_state(self, force)` (Dòng 212)
  - `def _save_state_if_needed(self)` (Dòng 227)
  - `def _next_seq(self)` (Dòng 230)
  - `def _next_cmsg_id(self)` (Dòng 235)
  - `def _next_ck_val(self)` (Dòng 240)
  - `def _get_next_counters(self)` (Dòng 245)
  - `def _select_socket_server(self)` (Dòng 256)
  - `def connect(self)` (Dòng 264)
  - `def close(self)` (Dòng 339)
  - `def disconnect(self)` (Dòng 351) — Alias cho close().
  - `def _recv_loop(self)` (Dòng 355)
  - `def _ping_loop(self)` (Dòng 516)
  - `def _disconnect_socket(self)` (Dòng 537)
  - `def _supervisor_loop(self)` (Dòng 549)

**Toàn bộ Comments & Chú thích Logic (6 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L277 | `# 1. Gửi HTTP Handshake` | `# 1. Gửi HTTP Handshake` |
| L281 | `# 2. Gửi Frame 0 Handshake (Type 8)` | `# 2. Gửi Frame 0 Handshake (Type 8)` |
| L299 | `# 3. Drain buffer` | `# 3. Drain buffer` |
| L311 | `# 4. Gửi chuỗi Init Frames` | `# 4. Gửi chuỗi Init Frames` |
| L321 | `# 5. Khởi chạy luồng Receive & Ping Keepalive` | `# 5. Khởi chạy luồng Receive & Ping Keepalive` |
| L388 | `# Bắt phản hồi ACK cho CMD điều khiển` | `# Bắt phản hồi ACK cho CMD điều khiển` |

---

#### 📄 `core/socket/crypto.py` (283 dòng)
**Mô tả Module:**
```text
core/socket/crypto.py — Module Mật mã học (Cryptography) chuẩn cho Zalo Core SDK.
Hỗ trợ đầy đủ:
- AES-128-ECB (Mã hóa mật khẩu đăng nhập)
- AES-128-CBC (Mã hóa HTTP Form Data & E2EE tin nhắn)
- AES-256-GCM (Mã hóa & Giải mã Outer Socket Frame)
- X25519 ECDH (Trao đổi khóa bất đối xứng chuẩn RFC 7748)
- MD5 Signature (Ký số request API)
- XOR Masking (Lớp bảo vệ D3 Message)
- GZIP Compression & Decompression
```
**Hằng số / Opcodes chính:** `DEFAULT_XK, DEFAULT_BASE_KEY, DEFAULT_SECRET, _P, _A24, _BASE_POINT_U`

**Danh sách Hàm (Functions):**
- `def key32(zcid)` (Dòng 39) — Trích xuất khóa 32 bytes AES từ chuỗi ZCID hex (tối thiểu 96 ký tự).
Thuật toán: 16 ký tự chẵn đầu + 16 ký tự chẵn cuối (đếm lùi).
- `def password_hash(phone, password, base_key)` (Dòng 52) — Băm mật khẩu Zalo theo AES-128-ECB không IV:
- Key: 16 bytes từ MD5(BASE_KEY + phone)[5:21]
- Plaintext: password được đệm null-byte (0x00) về độ dài 16 bytes.
- `def compute_sig(data_hex, api_key, secret)` (Dòng 63) — Tính chữ ký số MD5 cho HTTP POST request:
MD5(f"api_key={api_key}data={data_hex}{secret}")
- `def encrypt_http_data(params, zcid)` (Dòng 76) — Mã hóa tham số JSON thành chuỗi Hex bằng AES-128/256-CBC với key32(zcid) và IV=0x00*16.
Sử dụng PKCS#7 padding.
- `def decrypt_http_data(data_hex, zcid)` (Dòng 89) — Giải mã chuỗi Hex trả về từ HTTP API thành JSON dictionary.
- `def encrypt_aes_gcm(plaintext, dk, iv)` (Dòng 106) — Mã hóa Outer Socket Frame bằng AES-256-GCM với Derived Key (DK 32 bytes):
Định dạng đầu ra: [Ciphertext][16 bytes Auth Tag][12 bytes Nonce/IV]
- `def decrypt_aes_gcm(frame_body, dk)` (Dòng 123) — Giải mã Outer Socket Frame bằng AES-256-GCM với Derived Key (DK 32 bytes):
Định dạng đầu vào: [Ciphertext][16 bytes Auth Tag][12 bytes Nonce/IV]
- `def encrypt_e2ee_cbc(plaintext, cryptkey, iv)` (Dòng 145) — Mã hóa E2EE tin nhắn 1-1 bằng AES-128-CBC với CryptKey (16 bytes):
Sử dụng PKCS#7 padding.
Trả về: (ciphertext, iv)
- `def decrypt_e2ee_cbc(ciphertext, cryptkey, iv)` (Dòng 164) — Giải mã E2EE tin nhắn 1-1 bằng AES-128-CBC với CryptKey (16 bytes).
- `def xor_d3(data, key)` (Dòng 185) — Thực hiện phép toán XOR chu kỳ trên mảng byte bằng khóa D3 (mặc định: XK 32 bytes).
Phép toán đối xứng: xor_d3(xor_d3(data)) == data.
- `def _clamp(k_bytes)` (Dòng 201)
- `def _cswap(swap, x_2, x_3)` (Dòng 209)
- `def x25519(scalar_bytes, u_bytes)` (Dòng 214) — Nhân điểm trên đường cong Montgomery Curve25519 theo chuẩn RFC 7748.
- `def x25519_keypair()` (Dòng 252) — Sinh cặp khóa X25519 ngẫu nhiên: (private_key 32B, public_key 32B).
- `def x25519_shared_secret(private_key, peer_public_key)` (Dòng 261) — Tính toán bí mật chung (Shared Secret 32 bytes) từ Private Key của mình và Public Key đối phương.
- `def gzip_decompress(data)` (Dòng 272) — Giải nén luồng byte nén chuẩn GZIP (bắt đầu bằng 0x1f 0x8b).
- `def gzip_compress(data)` (Dòng 279) — Nén luồng byte sang chuẩn GZIP.

**Toàn bộ Comments & Chú thích Logic (23 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L24 | `# Khóa mặc định (có thể truyền động qua tham số hàm)` | `# Khóa mặc định (có thể truyền động qua tham số hàm)` |
| L29 | `# Hằng số Curve25519 / RFC 7748` | `# Hằng số Curve25519 / RFC 7748` |
| L35 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L36 | `# 1. ZCID Key Derivation & HTTP Signatures` | `# 1. ZCID Key Derivation & HTTP Signatures` |
| L37 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L72 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L73 | `# 2. HTTP Data Encryption (AES-CBC + IV=0)` | `# 2. HTTP Data Encryption (AES-CBC + IV=0)` |
| L74 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L102 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L103 | `# 3. Outer Socket Frame Encryption (AES-256-GCM)` | `# 3. Outer Socket Frame Encryption (AES-256-GCM)` |
| L104 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L141 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L142 | `# 4. E2EE Message Encryption (AES-128-CBC)` | `# 4. E2EE Message Encryption (AES-128-CBC)` |
| L143 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L181 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L182 | `# 5. D3 Message XOR Masking` | `# 5. D3 Message XOR Masking` |
| L183 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L197 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L198 | `# 6. X25519 ECDH (RFC 7748)` | `# 6. X25519 ECDH (RFC 7748)` |
| L199 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L268 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L269 | `# 7. GZIP Compression Utilities` | `# 7. GZIP Compression Utilities` |
| L270 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |

---

#### 📄 `core/socket/groupActions.py` (37 dòng)
**Mô tả Module:**
```text
core/socket/groupActions.py — TCP Binary Protocol Builder cho các thao tác nhóm (Kick, Ban, Add, Leave, Join, Disband).
```
---

#### 📄 `core/socket/handshake.py` (190 dòng)
**Mô tả Module:**
```text
core/socket/handshake.py — Khởi tạo kết nối bảo mật PROV Frame (Type 8 Handshake) & Chuỗi khung Active Session.
```
**Danh sách Hàm (Functions):**
- `def build_p110(sk_str, uid, vercode)` (Dòng 24) — Tạo payload 110 bytes chứa thông tin thiết bị và session key.
- `def build_authen_body(sk_str, uid, ctr)` (Dòng 37) — Tạo authen body cho Frame 0 Handshake.
- `def build_prov_frame(session_key, dk, ksid, server_pubkey_b64, uid)` (Dòng 47) — Sinh PROV Frame 0 (Type 8) - Trao đổi khóa bảo mật X25519 ECDH + AES-256-GCM 2 lớp.
- `def build_init_frames(uid, dest, vercode)` (Dòng 82) — Sinh danh sách init frames gửi ngay sau Handshake để kích hoạt phiên Active.
- `def send_init_frames(sock, dk, uid, dest, vercode, send_lock)` (Dòng 175) — Gửi tuần tự chuỗi khung khởi tạo để Active phiên trên Gateway server.

**Toàn bộ Comments & Chú thích Logic (5 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L93 | `# ── core register burst ──` | `# ── core register burst ──` |
| L102 | `# ── 10100 submit bundle (Signal identity) ──` | `# ── 10100 submit bundle (Signal identity) ──` |
| L118 | `# ── sync / config ──` | `# ── sync / config ──` |
| L139 | `# ── 1530 ticket ──` | `# ── 1530 ticket ──` |
| L159 | `# ── 3400 E2EE devices JSON ──` | `# ── 3400 E2EE devices JSON ──` |

---

#### 📄 `core/socket/keepalive.py` (17 dòng)
**Mô tả Module:**
```text
core/socket/keepalive.py — TCP Binary Protocol Builder cho Ping / Keepalive.
```
---

#### 📄 `core/socket/pinTopic.py` (17 dòng)
**Mô tả Module:**
```text
core/socket/pinTopic.py — TCP Binary Protocol Builder & Handler cho Pinned Topics.
```
---

#### 📄 `core/socket/poll.py` (11 dòng)
**Mô tả Module:**
```text
core/socket/poll.py — TCP Binary Protocol Builder & Handler cho Group Polls.
```
---

#### 📄 `core/socket/protocol.py` (2347 dòng)
**Mô tả Module:**
```text
core/socket/protocol.py — Module Giao thức Nhị phân (Binary Protocol Engine) cho Zalo TCP Socket.
Hỗ trợ đầy đủ:
- Outer Frame Format: [uint32 total_len][uint8 ftype][body]
- Inner Packet Header Format (18 bytes): struct '<IBBiIBHB'
- D3 Message Encoder & Decoder (Group, 1-1, RTF styling, Quote, Mentions, TTL)
- Checksum Calculation (CKSUM_MAGIC = 0x6CE7DAA0)
- Packet Builders: Ping, Typing, Group Msg, 1-1 Msg, Reaction, Pin Topic, Unpin Topic, Disband (CMD 1705)
- Incoming Packet Parsers (Frame Type 3 & 4, CMD 101, 201, 1865, 1867, 202)
```
**Hằng số / Opcodes chính:** `CKSUM_MAGIC, MAGIC_CHECKSUM_XOR, XK, FRAME_TYPE_CONTROL, FRAME_TYPE_DATA, FRAME_TYPE_KEY_EXCHANGE, FRAME_TYPE_HANDSHAKE, CMD_PING, SUB_PING, CMD_GROUP_MSG, SUB_GROUP_MSG, CMD_1TO1_MSG, SUB_1TO1_MSG, SUB_PHOTO_MSG, SUB_DOODLE_MSG, SUB_PHOTO_ATTACH_MSG, SUB_ATTACH_MSG, SUB_VIDEO_MSG, CMD_GROUP_TYPING, SUB_GROUP_TYPING, CMD_1TO1_TYPING, SUB_1TO1_TYPING, CMD_GROUP_PREPARE, SUB_GROUP_PREPARE, CMD_GROUP_SYNC_BROADCAST, SUB_GROUP_SYNC, CMD_DELIVERY_RECEIPT, SUB_DELIVERY_RECEIPT, CMD_1TO1_INCOMING, CMD_REMOVE_MEMBER, SUB_REMOVE_MEMBER, CMD_KICK_MEMBER, SUB_KICK_MEMBER, CMD_DISBAND_GROUP, SUB_DISBAND_GROUP, CMD_BLOCK_GROUP_MEMBER, SUB_BLOCK_GROUP_MEMBER, CMD_BLOCK_USER, SUB_BLOCK_USER, CMD_ADD_MEMBER, SUB_ADD_MEMBER, CMD_LEAVE_GROUP, SUB_LEAVE_GROUP, CMD_LEAVE_GROUP_225, SUB_LEAVE_GROUP_225, CMD_LEAVE_GROUP_239, SUB_LEAVE_GROUP_239, CMD_JOIN_GROUP, SUB_JOIN_GROUP, CMD_JOIN_GROUP_INVITE, SUB_JOIN_GROUP_INVITE, CMD_REQUEST_JOIN_GROUP, SUB_REQUEST_JOIN_GROUP, CMD_GROUP_LINK_INFO, SUB_GROUP_LINK_INFO, CMD_JOIN_GROUP_BY_LINK, SUB_JOIN_GROUP_BY_LINK, CMD_PIN_TOPIC, SUB_PIN_TOPIC, CMD_UNPIN_TOPIC, SUB_UNPIN_TOPIC, CMD_CREATE_POLL, SUB_CREATE_POLL, CMD_RECALL_MSG_GROUP, SUB_RECALL_MSG_GROUP, CMD_RECALL_MSG_1TO1, SUB_RECALL_MSG_1TO1, CMD_DELETE_MSG, SUB_DELETE_MSG, CMD_BLOCK_USER_1TO1, SUB_BLOCK_USER_1TO1, CMD_UNBLOCK_USER_1TO1, SUB_UNBLOCK_USER_1TO1, INNER_HEADER_FORMAT, INNER_HEADER_SIZE`

**Danh sách Class:**
- `class InnerPacketHeader` (Dòng 163): Không có docstring
  - `def pack(self)` (Dòng 173)
  - `def unpack(cls, data)` (Dòng 187)
- `class OuterFrame` (Dòng 195): Không có docstring
  - `def pack(self)` (Dòng 200)
  - `def unpack_from_buffer(cls, buf)` (Dòng 204) — Bóc tách một Outer Frame hoàn chỉnh từ stream buffer.
Trả về (OuterFrame, bytes_consumed) hoặc None nếu buffer chưa nhận đủ dữ liệu.

**Danh sách Hàm (Functions):**
- `def compute_checksum(cmd, sub, seq, uid, target, target_type, cmsg, bb, ty, ver)` (Dòng 226) — Tính Checksum ck_val:
ck_val = (bb + ty + seq + uid + ver + cmd + sub + target + target_type + cmsg) mod 2^32 XOR 0x6ce7daa0
- `def xor_encode_d3(plain, uid, xk)` (Dòng 239) — Mã hóa XOR 2 lớp cho payload D3 dựa trên chiều dài payload và UID.
- `def xor_decode_d3(cipher, uid, xk)` (Dòng 250) — Giải mã XOR D3 (phép toán đối xứng).
- `def dekey(a4, uid)` (Dòng 257) — doEncryptData keystream: XK ^ le32(a4) ^ le32(uid), cyclic-32
- `def xor_enc(pt, uid)` (Dòng 264) — encode plaintext params (a4 = len + 23)
- `def build_photo_attach(url, width, height, total_size, title, description, thumb_url, hd_url, is_original)` (Dòng 274) — Tạo Photo Attachment payload theo chuẩn Zalo Native D3 Attachment.
- `def build_video_attach(url, width, height, duration, total_size, title, description, thumb_url)` (Dòng 321) — Tạo Video Attachment payload theo chuẩn Zalo D3 Attachment.
- `def build_d3_payload_group(text, ttl_ms, quote_data, mentions, style_id, size, color, bold, italic, underline, strike, fontsize, list_type, rtf_mode, attach)` (Dòng 361) — Xây dựng cấu trúc nhị phân D3 cho tin nhắn nhóm (hỗ trợ Text thường, Quote trích dẫn, Mention, Style, Ảnh/Attach và TTL tự xóa).
- `def build_d3_json(style_id)` (Dòng 498) — JSON metadata cho D3 — style_id → thêm decorInfo (font/kiểu chữ)
- `def build_d3_payload_1to1(text, cryptkey, ttl_ms, quote_data, attach)` (Dòng 512) — Xây dựng cấu trúc nhị phân D3 cho tin nhắn 1-1 (mã hóa E2EE bằng AES-128-CBC với CryptKey).
- `def build_d3_payload_1to1_styled(text, cryptkey, style_id, size, color, bold, italic, ttl_ms)` (Dòng 596) — Xây dựng D3 payload cho tin nhắn 1-1 có style (kiểu chữ typoId, kích thước, màu sắc, bold/italic).
- `def build_d3_payload_1to1_rtf(text, cryptkey, styles, rtf_mode, list_type)` (Dòng 639) — Xây dựng D3 payload cho tin nhắn 1-1 Rich Text Formatting (RTF Spans).
- `def build_ping_packet(uid, seq, ck_val, dest)` (Dòng 703) — Tạo Inner Packet Heartbeat Keepalive (CMD 1971 SUB 0).
- `def build_typing_packet(uid, target_id, is_group, seq, ck_val, cmsg_id)` (Dòng 713) — Tạo Inner Packet Typing notification (CMD 206 / CMD 106).
- `def build_group_message_packet(uid, group_id, text, seq, ck_val, cmsg_id, ttl_ms, quote_data, mentions, style_id, size, color, bold, italic, underline, strike, fontsize, list_type, rtf_mode, attach)` (Dòng 724) — Tạo Inner Packet gửi tin nhắn nhóm (CMD 207 SUB 1) hỗ trợ Plaintext, Style, Attach/Ảnh và TTL.
- `def build_1to1_message_packet(uid, target_uid, text, cryptkey, seq, ck_val, cmsg_id, ttl_ms, quote_data, style_id, size, color, bold, italic, underline, strike, fontsize, list_type, rtf_mode, attach)` (Dòng 754) — Tạo Inner Packet gửi tin nhắn 1-1 (CMD 113 SUB 41) hỗ trợ Plaintext, Style, RTF, Attach/Ảnh và TTL.
- `def build_photo_binary_payload(url, title, description, thumb_url, hd_url, caption, width, height, total_size, sub_type, is_original)` (Dòng 789) — Tạo Payload Nhị Phân Native Photo Message theo chuẩn C3 trong pn/g0.smali.

Hỗ trợ cả SUB 32 (Native Photo) và SUB 37 (API / Attachment / Doodle) cùng cờ is_original.

Cấu trúc trường nhị phân:
- [2B LE sub_type][1B feature_blocks_count = 0]
- a (Title / Caption): chuỗi text tiêu đề / chú thích
- e (Description / Normal URL): chuỗi mô tả / link ảnh normal
- d (HD URL): link ảnh HD
- c (Thumb URL): link ảnh Thumbnail
- b (Action ID / 0): 2B LE 0
- f (Extra): chuỗi phụ trợ (mặc định rỗng)
- g (Meta JSON): {"width": w, "height": h, "totalSize": sz, "hd": hd_url, "is_original": 0/1}
- `def build_photo_message_packet(uid, target_id, photo_url, seq, ck_val, cmsg_id, is_group, caption, title, description, width, height, total_size, thumb_url, hd_url, ttl_ms, quote_data, cryptkey, native, sub_type, is_original)` (Dòng 869) — Tạo Inner Packet gửi tin nhắn hình ảnh Native (CMD 207/113 SUB 32/37) hoặc D3 attachment fallback (SUB 1/41).
- `def build_video_binary_payload(url, title, description, thumb_url, width, height, duration_ms, total_size, sub_type)` (Dòng 967) — Tạo Payload Nhị Phân Native Video Message theo chuẩn C3 trong pn/g0.smali và Lp00/x0.smali.
- `def build_video_message_packet(uid, target_id, video_url, seq, ck_val, cmsg_id, is_group, caption, title, description, thumb_url, width, height, duration_ms, total_size, ttl_ms, quote_data, cryptkey, native, sub_type)` (Dòng 1025) — Tạo Inner Packet gửi tin nhắn Video Native (CMD 207/113 SUB 32/37) hoặc D3 attachment fallback (SUB 1/41).
- `def build_reaction_packet(uid, target_id, cli_msg_id, global_msg_id, icon, is_group, seq, ck_val, cmsg_id)` (Dòng 1120) — Tạo Inner Packet gửi reaction vào tin nhắn (CMD 1785 / CMD 1780).
- `def build_pin_topic_packet(uid, group_id, title, cli_msg_id, global_msg_id, sender_name, seq, ck_val, vercode)` (Dòng 1170) — Tạo Inner Packet Ghim tin nhắn / Tạo Topic Ghim vào nhóm (CMD 1752 SUB 2).
Chuẩn Zalo Android (Reverse từ PCAP thực tế).
- `def build_unpin_topic_packet(uid, group_id, topic_id, global_msg_id, cli_msg_id, seq, ck_val, vercode)` (Dòng 1228) — Tạo Inner Packet Bỏ ghim tin nhắn / Topic khỏi nhóm (CMD 1708 SUB 0).
Reverse từ Smali pn/g0.smali (method q1).
- `def build_fetch_pinned_topics_packet(uid, group_id, from_time, seq, ck_val, vercode)` (Dòng 1262) — Tạo Inner Packet lấy danh sách bài ghim / Topic trong nhóm (CMD 1703 SUB 0).
- `def build_cmd_1705_packet(uid, group_id, field_8byte, prefix_data, seq, ck_val)` (Dòng 1282) — Tạo Inner Packet Giải tán nhóm / Rời nhóm & Chuyển quyền (CMD 1705 SUB 0).
- `def build_disband_242_packet(uid, group_id, seq, ck_val, vercode)` (Dòng 1314) — Giải tán nhóm thật (CMD 242 SUB 0, pn/g0.h2).
Smali ManageGroupView + pcap C2S 242 (9B: 01 ver gid).
  - 0x01 (1B)
  - vercode: 4B LE
  - groupId: 4B LE
Payload gửi trực tiếp dưới dạng Plaintext trong Outer Frame AES-GCM.
- `def build_remove_member_packet(uid, group_id, member_uids, seq, ck_val)` (Dòng 1343) — Xoá khỏi nhóm KHÔNG block (CMD 228 SUB 0, du/b.r).
Smali du/b.r + pcap C2S 228 (8B: gid + uid).
  - groupId: 4B LE
  - memberUids: 4B LE mỗi người (không count, không flag)
- `def build_kick_member_packet(uid, group_id, member_uids, is_block, seq, ck_val)` (Dòng 1369) — Tạo Inner Packet xóa/kick/ban thành viên khỏi nhóm (CMD 234 SUB 0, bb=0, ty=1).
Chuẩn Zalo Android (Reverse từ PCAP thực tế & Smali pn/g0.smali method k):
  - groupId: 4B LE
  - isBlock/flag: 1B (0x01 nếu block/ban, 0x00 nếu kick)
  - memberCount: 4B LE
  - memberUids: 4B LE cho từng thành viên
- `def build_block_group_member_packet(uid, group_id, member_uids, seq, ck_val, vercode)` (Dòng 1403) — Tạo Inner Packet Chặn / Ban thành viên khỏi nhóm (CMD 234 SUB 0 với is_block=True).
Chuẩn Zalo Android (Smali pn/g0.smali method k).
- `def build_block_user_packet(uid, target_uid, is_block, seq, ck_val, vercode)` (Dòng 1425) — Tạo Inner Packet Chặn / Bỏ chặn người dùng 1-1 (CMD 382 SUB 0 / CMD 383 SUB 0).
Reverse từ Smali pn/g0.smali (method f và method e2):
  - Block (CMD 382 SUB 0): [0x01][vercode: 4B LE][count: 2B LE (1)][target_uid: 4B LE][source: 2B LE (0)]
  - Unblock (CMD 383 SUB 0): [0x01][vercode: 4B LE][target_uid: 4B LE][source: 2B LE (0)]
- `def build_unblock_user_packet(uid, target_uid, seq, ck_val, vercode)` (Dòng 1460) — Tạo Inner Packet Bỏ chặn người dùng 1-1 (CMD 383 SUB 0).
- `def build_leave_group_packet(uid, group_id, new_owner_id, is_silent, is_block_readd, seq, ck_val, vercode, lang)` (Dòng 1471) — Tạo Inner Packet Rời / Thoát khỏi nhóm chat (CMD 239 SUB 1).
Chuẩn Zalo Android (Reverse từ au/o.smali lines 538-840 & PCAP Frame 412/440):
  - 0x01 (1 byte ver)
  - vercode: uint32 LE (260802903)
  - json_str: 4B LE len + UTF-8 bytes (ví dụ: '{"srcType":3}' nếu không chuyển owner, '{"srcType":2}' nếu có new_owner)
  - lang: uint16 LE (0x0000)
  - groupId: uint32 LE
  - newOwnerId: uint32 LE (0 nếu không chọn chủ nhóm mới)
  - is_silent: uint8 (1 nếu rời trong im lặng, 0 nếu thông báo)
  - is_block_readd: uint8 (1 nếu chặn mời lại vào nhóm, 0 nếu không)
- `def build_leave_group_225_packet(uid, group_id, seq, ck_val, vercode, lang)` (Dòng 1521) — Tạo Inner Packet Rời khỏi nhóm chat trực tiếp qua Socket (CMD 225 SUB 3).
Chuẩn PCAP Frame 438 & du/b.smali method N0:
  - 0x01 (1 byte)
  - vercode: uint32 LE (260802903)
  - empty_str: 4B LE (0x00000000)
  - lang: uint16 LE (0x0000)
  - groupId: uint32 LE
  - flag: uint32 LE (0x000000A0 = 160)
- `def build_create_poll_packet(uid, group_id, question, options, seq, ck_val, vercode)` (Dòng 1561) — Tạo Inner Packet Tạo cuộc bình chọn / Poll trong nhóm (CMD 1640 SUB 3).
Chuẩn Zalo Android (Reverse từ PCAP thực tế).
- `def build_join_group_by_link_901_packet(uid, link_url, seq, ck_val)` (Dòng 1602) — Tạo Inner Packet tham gia nhóm qua link (CMD 901 SUB 3).
Verified 100% từ PCAP thực tế (16/09/2026).

D3 plaintext structure (total = 8 + 1 + url_len bytes):
  [0:8]        = 0x00 * 8  (8 zero bytes header)
  [8]          = url_len   (u8, độ dài URL)
  [9:9+url_len] = url_encoded (URL bytes với mỗi byte thứ 4 (i%4==3) XOR 0x33)

Encoding: xor_encode_d3(plain, uid)
- `def build_preview_link_901_packet(uid, link_url, seq, ck_val, vercode, source, sub_type)` (Dòng 1643) — Alias → build_join_group_by_link_901_packet (chuẩn PCAP 16/09/2026).
- `def build_query_group_906_packet(uid, group_id, seq, ck_val)` (Dòng 1658) — Tạo Inner Packet truy vấn thông tin nhóm theo GID (CMD 906 SUB 0, chuẩn PCAP Frame 421).
- `def parse_d3_compressed_json(body, uid)` (Dòng 1681) — Giải mã payload JSON nén Deflate/Gzip D3 từ phản hồi Socket (CMD 244, 901, 902, etc.).
Hỗ trợ cả trường hợp body có tiền tố 4-byte status code lẫn không có.
- `def build_recall_message_packet(uid, target_id, cli_msg_id, global_msg_id, msg_type, owner_id, is_group, cmsg_counter, seq, ck_val)` (Dòng 1756) — Tạo Inner Packet Thu hồi tin nhắn toàn nhóm / 1-1 cho tất cả mọi người (CMD 204 SUB 2 / CMD 114 SUB 2).
Chuẩn Zalo Android (Reverse từ PCAP Frame 2433 & Smali pn/g0.smali method b3):
  - D3 plain (28 bytes):
    [target_id: 4B LE][cliMsgId: 8B LE][globalMsgId: 8B LE][msgType: 4B LE][ownerId: 4B LE]
  - D3 enc: xor_encode_d3(d3_plain, uid)
  - Framing prefix (13 bytes):
    [target_id: 4B LE][0x04 if is_group else 0x03][cmsg_id: 4B LE][416: 4B LE]
  - Params payload (41 bytes total):
    prefix + d3_enc -> xor_enc(payload, uid)
  - Header: ck, bb=0, ty=2, seq, uid, ver=3, cmd=(204 if is_group else 114), sub=2.
- `def build_delete_message_packet(uid, group_id, cli_msg_id, global_msg_id, is_group, only_me, seq, ck_val)` (Dòng 1808) — Tạo Inner Packet Xóa tin nhắn (CMD 205 SUB 3, bb=0, ty=1).
Chuẩn Zalo Android (Reverse từ PCAP thực tế):
  - only_me=True  -> il = 1 (chỉ xóa ở phía cá nhân)
  - only_me=False -> il = 2 (xóa ở phía tất cả mọi người trong cuộc trò chuyện)
- `def build_add_member_packet(uid, group_id, member_uids, is_invite, seq, ck_val)` (Dòng 1851) — Tạo Inner Packet thêm thành viên vào nhóm (CMD 235 SUB 0, bb=0, ty=1).
Payload nhị phân:
  - groupId: int32 LE
  - isInvite: uint8 (1: Mời tham gia, 0: Thêm trực tiếp)
  - memberCount: int32 LE
  - memberUids: int32 LE cho từng thành viên
- `def build_join_group_packet(uid, group_id, source, seq, ck_val, vercode, ts_ms)` (Dòng 1886) — Tạo Inner Packet yêu cầu tham gia nhóm qua Socket (CMD 246 SUB 3).
Nguồn: Reverse engineering từ smali pn/g0.smali (method z).
Binary payload:
  - [0x01] (1 byte ver)
  - [vercode: 4B LE]
  - [0x00000000: 4B LE (empty string len)]
  - [0x0000: 2B LE lang]
  - [groupId: 4B LE]
  - [source: 4B LE]
  - [ts: 8B LE]
Mã hóa XOR với xor_enc(payload, uid).
Header: ck, bb=0, ty=1, seq, uid, ver=3, cmd=246, sub=3.
- `def build_join_group_invite_packet(uid, group_id, inviter_uid, seq, ck_val, vercode)` (Dòng 1925) — Tạo Inner Packet chấp nhận lời mời tham gia nhóm qua Socket (CMD 250 SUB 1).
Nguồn: Reverse engineering từ smali pn/g0.smali (method H2).
Binary payload:
  - [0x01] (1 byte ver)
  - [vercode: 4B LE]
  - [0x00000000: 4B LE]
  - [0x0000: 2B LE lang]
  - [groupId: 4B LE]
  - [inviterUid: 8B LE]
Mã hóa XOR với xor_enc(payload, uid).
Header: ck, bb=0, ty=1, seq, uid, ver=3, cmd=250, sub=1.
- `def build_request_join_group_packet(uid, group_id, msg, link_url, source, sub_source, seq, ck_val, vercode)` (Dòng 1959) — Tạo Inner Packet gửi yêu cầu tham gia nhóm qua liên kết / Code (CMD 244 SUB 4).
Chuẩn PCAP Frame 422 & Smali pn/g0.smali method n2:
  - 0x01 (1 byte ver)
  - vercode: 4B LE
  - str1 (msg/inviter): 4B LE len + UTF-8 bytes
  - lang: 2B LE (0)
  - groupId: 4B LE
  - str2 (note/extra): 4B LE len + UTF-8 bytes
  - source: 4B LE (1)
  - sub_source: 1B (0)
  - str3 (full link_url): 4B LE len + UTF-8 bytes
- `def build_group_link_info_packet(uid, link_url, source, sub_source, seq, ck_val, vercode)` (Dòng 2020) — Tạo Inner Packet phân giải thông tin nhóm từ Liên kết nhóm (CMD 244 SUB 4).
- `def build_join_group_by_link_packet(uid, link_code, group_id, flag_byte, seq, ck_val, vercode)` (Dòng 2043) — Tạo Inner Packet tham gia nhóm qua Link (CMD 2000 SUB 3).
Nguồn: Reverse engineering từ smali du/b.smali method h(String, byte, cu/h).
- `def build_join_group_2000_packet(uid, group_id, flag_byte, seq, ck_val, vercode)` (Dòng 2077) — Tạo Inner Packet tham gia nhóm trực tiếp qua Group ID (CMD 2000 SUB 3).
- `def build_outer_frame(inner_packet, dk)` (Dòng 2107) — Đóng gói Inner Packet thành Outer Frame AES-256-GCM (Type 4).
- `def parse_incoming_frame(frame, dk, cryptkey, my_uid)` (Dòng 2120) — Bóc tách và giải mã một Outer Frame nhận được từ máy chủ.
- `def parse_incoming_messages_payload(cmd, sub, uid, params_bytes, cryptkey, my_uid)` (Dòng 2189) — Phân tích và giải mã các bản tin tin nhắn đến (CMD 101, 201, 1865, 1867).
- `def parse_group_sync_1867(params_bytes)` (Dòng 2323)
- `def parse_delivery_receipt_202(params_bytes)` (Dòng 2328)

**Toàn bộ Comments & Chú thích Logic (84 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L39 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L40 | `# 1. Hằng số Giao thức (Protocol Constants)` | `# 1. Hằng số Giao thức (Protocol Constants)` |
| L41 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L47 | `# Outer Frame Types` | `# Outer Frame Types` |
| L53 | `# Inner Command Codes & Sub Codes` | `# Inner Command Codes & Sub Codes` |
| L125 | `# CMD 2000 SUB 3: Join group via link (du/b.smali method h, g:S=0x7d0)` | `# CMD 2000 SUB 3: Join group via link (du/b.smali method h, g:S=0x7d0)` |
| L153 | `# Struct format Header 18 bytes:` | `# Struct format Header 18 bytes:` |
| L154 | `# uint32 ck, uint8 bb, uint8 ty, int32 seq, uint32 uid, uint8 ver, uint16 cmd, uint8 sub` | `INNER_HEADER_FORMAT = '<IBBiIBHB'  # uint32 ck, uint8 bb, uint8 ty, int32 seq...` |
| L158 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L159 | `# 2. Data Structures` | `# 2. Data Structures` |
| L160 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L164 | `# uint32: Clock counter / Checksum` | `ck: int      # uint32: Clock counter / Checksum` |
| L165 | `# uint8 : Broadcast flag (0 hoặc 1)` | `bb: int      # uint8 : Broadcast flag (0 hoặc 1)` |
| L166 | `# uint8 : Clock domain type (1: system/ping, 2: message)` | `ty: int      # uint8 : Clock domain type (1: system/ping, 2: message)` |
| L167 | `# int32 : Sequence number (âm đối với C2S, 0 đối với S2C)` | `seq: int     # int32 : Sequence number (âm đối với C2S, 0 đối với S2C)` |
| L168 | `# uint32: User ID` | `uid: int     # uint32: User ID` |
| L169 | `# uint8 : Protocol version (mặc định: 3)` | `ver: int     # uint8 : Protocol version (mặc định: 3)` |
| L170 | `# uint16: Command code` | `cmd: int     # uint16: Command code` |
| L171 | `# uint8 : Sub command code` | `sub: int     # uint8 : Sub command code` |
| L196 | `# uint32 LE (bao gồm 4 bytes len + 1 byte type + body)` | `total_len: int  # uint32 LE (bao gồm 4 bytes len + 1 byte type + body)` |
| L197 | `# uint8` | `ftype: int      # uint8` |
| L198 | `# Raw payload hoặc Ciphertext (AES-256-GCM)` | `body: bytes     # Raw payload hoặc Ciphertext (AES-256-GCM)` |
| L222 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L223 | `# 3. Checksum & D3 XOR Encoders` | `# 3. Checksum & D3 XOR Encoders` |
| L224 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L270 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L271 | `# 4. Message Builders (Xây dựng Gói tin D3)` | `# 4. Message Builders (Xây dựng Gói tin D3)` |
| L272 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L400 | `# Zalo Native RichTextFormat (TextStyle Spans)` | `# Zalo Native RichTextFormat (TextStyle Spans)` |
| L469 | `# 4 bytes 0x00000000` | `buf += struct.pack('<I', 0)                  # 4 bytes 0x00000000` |
| L470 | `# 2 bytes độ dài mention tag` | `buf += struct.pack('<H', mention_len)        # 2 bytes độ dài mention tag` |
| L471 | `# 4 bytes Quoted Owner UID` | `buf += struct.pack('<I', q_uid)              # 4 bytes Quoted Owner UID` |
| L472 | `# 1 byte 0x02` | `buf += bytes([0x02])                         # 1 byte 0x02` |
| L473 | `# 4 bytes Quoted Owner UID` | `buf += struct.pack('<I', q_uid)              # 4 bytes Quoted Owner UID` |
| L474 | `# 8 bytes Quoted Timestamp ms` | `buf += struct.pack('<Q', q_ts)               # 8 bytes Quoted Timestamp ms` |
| L475 | `# 8 bytes Quoted GlobalMsgId` | `buf += struct.pack('<Q', q_gmi)              # 8 bytes Quoted GlobalMsgId` |
| L476 | `# 8 bytes Quoted CliMsgId` | `buf += struct.pack('<Q', q_cmi)              # 8 bytes Quoted CliMsgId` |
| L477 | `# 2 bytes Quoted CliMsgType` | `buf += struct.pack('<H', q_typ)              # 2 bytes Quoted CliMsgType` |
| L478 | `# Length-prefixed quoted text` | `buf += struct.pack('<H', len(q_text_bytes)) + q_text_bytes     # Length-prefi...` |
| L479 | `# Length-prefixed quoted attach` | `buf += struct.pack('<H', len(q_attach_bytes)) + q_attach_bytes # Length-prefi...` |
| L480 | `# 8 bytes Quoted TTL ms (TTL của tin bị quote)` | `buf += struct.pack('<Q', q_ttl_ms)           # 8 bytes Quoted TTL ms (TTL của...` |
| L481 | `# 2 bytes 0x0007` | `buf += struct.pack('<H', 7)                  # 2 bytes 0x0007` |
| L482 | `# 12 bytes style header (size, color, type_val)` | `buf += style_hdr                             # 12 bytes style header (size, c...` |
| L483 | `# Length-prefixed property JSON` | `buf += struct.pack('<I', len(prop_bytes)) + prop_bytes         # Length-prefi...` |
| L485 | `# Block TTL của tin nhắn phản hồi (Bot)` | `buf += bytes([0x08]) + struct.pack('<I', ttl_ms) + bytes(4) # Block TTL của t...` |
| L486 | `# Message text UTF-8` | `buf += text_bytes                            # Message text UTF-8` |
| L586 | `# 8 bytes Quoted TTL ms (0 nếu không có)` | `buf += struct.pack('<Q', q_ttl_ms)           # 8 bytes Quoted TTL ms (0 nếu k...` |
| L591 | `# Block TTL của tin nhắn phản hồi` | `buf += bytes([0x08]) + struct.pack('<I', ttl_ms) + bytes(4) # Block TTL của t...` |
| L699 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L700 | `# 5. Packet Builders (Tạo gói tin Inner Packet)` | `# 5. Packet Builders (Tạo gói tin Inner Packet)` |
| L701 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L840 | `# 1. Header block` | `# 1. Header block` |
| L843 | `# 2. Body fields block` | `# 2. Body fields block` |
| L844 | `# a: Title / Caption` | `# a: Title / Caption` |
| L846 | `# e: Description / Normal URL` | `# e: Description / Normal URL` |
| L848 | `# d: HD URL` | `# d: HD URL` |
| L850 | `# c: Thumb URL` | `# c: Thumb URL` |
| L852 | `# f: Extra` | `# f: Extra` |
| L854 | `# g: Metadata JSON` | `# g: Metadata JSON` |
| L1001 | `# 1. Header block` | `# 1. Header block` |
| L1004 | `# 2. Body fields block:` | `# 2. Body fields block:` |
| L1445 | `# ArrayList count = 1` | `buf.extend(struct.pack('<H', 1))  # ArrayList count = 1` |
| L1447 | `# source = 0` | `buf.extend(struct.pack('<H', 0))  # source = 0` |
| L1450 | `# source = 0` | `buf.extend(struct.pack('<H', 0))  # source = 0` |
| L1494 | `# 239` | `cmd = CMD_LEAVE_GROUP  # 239` |
| L1495 | `# 1` | `sub = SUB_LEAVE_GROUP  # 1` |
| L1501 | `# JSON options` | `# JSON options` |
| L1507 | `# 2B LE lang code (0)` | `buf.extend(struct.pack('<H', lang))  # 2B LE lang code (0)` |
| L1539 | `# 225` | `cmd = CMD_LEAVE_GROUP_225  # 225` |
| L1540 | `# 3` | `sub = SUB_LEAVE_GROUP_225  # 3` |
| L1624 | `# Apply 4th-byte XOR 0x33 encoding to URL bytes (Zalo-specific obfuscation)` | `# Apply 4th-byte XOR 0x33 encoding to URL bytes (Zalo-specific obfuscation)` |
| L1630 | `# Build D3 plaintext` | `# Build D3 plaintext` |
| L1633 | `# D3-encode params` | `# D3-encode params` |
| L1642 | `# Alias cũ để backward compat` | `# Alias cũ để backward compat` |
| L1702 | `# Gzip header 0x1f 0x8b` | `# Gzip header 0x1f 0x8b` |
| L1728 | `# Zlib raw or stream` | `# Zlib raw or stream` |
| L1983 | `# 244` | `cmd = CMD_REQUEST_JOIN_GROUP  # 244` |
| L1984 | `# 4` | `sub = SUB_REQUEST_JOIN_GROUP  # 4` |
| L1989 | `# str1 len 0` | `buf.extend(struct.pack('<I', 0))  # str1 len 0` |
| L1990 | `# lang 0` | `buf.extend(struct.pack('<H', 0))  # lang 0` |
| L2116 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L2117 | `# 6. Incoming Packet Parsers (Giải mã Phản hồi từ Máy chủ)` | `# 6. Incoming Packet Parsers (Giải mã Phản hồi từ Máy chủ)` |
| L2118 | `# ---------------------------------------------------------------------------` | `# ---------------------------------------------------------------------------` |
| L2339 | `# Re-exports for Handshake & Init Session` | `# Re-exports for Handshake & Init Session` |

---

#### 📄 `core/socket/sendDoodle.py` (19 dòng)
**Mô tả Module:**
```text
core/socket/sendDoodle.py — TCP Binary Protocol Builder & Handler cho Doodle.
```
---

#### 📄 `core/socket/sendImage.py` (23 dòng)
**Mô tả Module:**
```text
core/socket/sendImage.py — TCP Binary Protocol Builder & Handler cho Image.
```
---

#### 📄 `core/socket/sendMessage.py` (27 dòng)
**Mô tả Module:**
```text
core/socket/sendMessage.py — TCP Binary Protocol Builder & Handler cho Text / D3 Messages.
```
---

#### 📄 `core/socket/sendReaction.py` (12 dòng)
**Mô tả Module:**
```text
core/socket/sendReaction.py — TCP Binary Protocol Builder & Handler cho Message Reactions.
```
---

#### 📄 `core/socket/sendTyping.py` (12 dòng)
**Mô tả Module:**
```text
core/socket/sendTyping.py — TCP Binary Protocol Builder & Handler cho Typing Status.
```
---

#### 📄 `core/socket/sendVideo.py` (23 dòng)
**Mô tả Module:**
```text
core/socket/sendVideo.py — TCP Binary Protocol Builder & Handler cho Video.
```
---

#### 📄 `core/socket/undoMessage.py` (15 dòng)
**Mô tả Module:**
```text
core/socket/undoMessage.py — TCP Binary Protocol Builder cho Recall & Delete Messages.
```
---

### 📁 Thư mục: `core/socket/actions/`

#### 📄 `core/socket/actions/block_user.py` (57 dòng)
**Mô tả Module:**
```text
core/socket/actions/block_user.py — Socket action mixin cho Chặn & Bỏ chặn người dùng.
```
**Danh sách Class:**
- `class BlockUserActionMixin` (Dòng 21): Mixin xử lý chặn và bỏ chặn người dùng 1-1 qua Socket.
  - `def block_user(self, target_uid, is_block)` (Dòng 24) — Chặn / Bỏ chặn người dùng 1-1 qua Socket (CMD 382 SUB 0 cho Block, CMD 383 SUB 0 cho Unblock).
  - `def unblock_user(self, target_uid)` (Dòng 55) — Bỏ chặn người dùng 1-1 qua Socket (CMD 383 SUB 0).

---

#### 📄 `core/socket/actions/group_actions.py` (673 dòng)
**Mô tả Module:**
```text
core/socket/actions/group_actions.py — Socket action mixin cho các thao tác nhóm.
(Kick, Ban, Remove, Add, Leave, Join, Disband, Preview Link, Link Info)
```
**Danh sách Class:**
- `class GroupActionsMixin` (Dòng 46): Mixin xử lý các thao tác quản trị và tương tác nhóm qua Socket.
  - `def send_group_event_1705(self, group_id, owner_uid, wait_ack, timeout)` (Dòng 49) — Gửi lệnh CMD 1705 (Giải tán / Rời nhóm & Chuyển quyền) qua socket.
  - `def disband_group_242(self, group_id, wait_response, timeout)` (Dòng 92) — Giải tán nhóm thật (CMD 242 SUB 0, pn/g0.h2).
  - `def remove_member(self, group_id, member_uids)` (Dòng 136) — Xoá khỏi nhóm KHÔNG block (CMD 228 SUB 0, du/b.r).
  - `def kick_member(self, group_id, member_uids, is_block)` (Dòng 163) — Kick / xóa / ban thành viên khỏi nhóm chat qua Socket (CMD 228 hoặc CMD 234).
  - `def block_group_member(self, group_id, member_uids)` (Dòng 201) — Chặn / Ban thành viên khỏi nhóm chat qua Socket (CMD 234 SUB 0 với is_block=True).
  - `def leave_group(self, group_id, new_owner_id, silent, block_readd, wait_response, timeout)` (Dòng 209) — Rời / Thoát khỏi nhóm chat qua Socket (CMD 225 SUB 3 & CMD 239 SUB 1).
  - `def add_member(self, group_id, member_uids, is_invite)` (Dòng 279) — Thêm / mời thành viên vào nhóm chat qua Socket (CMD 235 SUB 0).
  - `def join_group(self, group_id, source)` (Dòng 315) — Tham gia nhóm chat qua Socket (CMD 2000 SUB 3 & CMD 246 SUB 3).
  - `def preview_link_901(self, link_url, wait_response, timeout)` (Dòng 366) — Gửi yêu cầu phân giải / Preview link nhóm (CMD 901 SUB 3).
  - `def query_group_906(self, group_id, wait_response, timeout)` (Dòng 411) — Gửi yêu cầu truy vấn cấu hình nhóm theo GID (CMD 906 SUB 0).
  - `def join_group_by_link(self, link_url, group_id, msg, source, wait_response, timeout)` (Dòng 444) — Tham gia nhóm qua link (CMD 901 SUB 3).
  - `def join_group_invite(self, group_id, inviter_uid)` (Dòng 554) — Chấp nhận lời mời tham gia nhóm chat qua Socket (CMD 250 SUB 1).
  - `def request_join_group(self, group_id, link_url, msg, source, sub_source, wait_response, timeout)` (Dòng 584) — Gửi yêu cầu tham gia nhóm qua Link/Code/ID bằng Socket (CMD 244 SUB 4).
  - `def request_group_link_info(self, link_url, source, sub_source, timeout)` (Dòng 659) — Gửi yêu cầu phân giải thông tin link nhóm qua Socket và trả về Group ID nếu tìm thấy.

**Toàn bộ Comments & Chú thích Logic (4 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L226 | `# 1. Gói tin rời nhóm trực tiếp CMD 225 SUB 3` | `# 1. Gói tin rời nhóm trực tiếp CMD 225 SUB 3` |
| L236 | `# 2. Gói tin rời nhóm phụ trợ CMD 239 SUB 1` | `# 2. Gói tin rời nhóm phụ trợ CMD 239 SUB 1` |
| L327 | `# Gửi CMD 2000 SUB 3` | `# Gửi CMD 2000 SUB 3` |
| L344 | `# Gửi CMD 246 SUB 3` | `# Gửi CMD 246 SUB 3` |

---

#### 📄 `core/socket/actions/pin_topic.py` (126 dòng)
**Mô tả Module:**
```text
core/socket/actions/pin_topic.py — Socket action mixin cho Ghim / Bỏ ghim / Lấy Pinned Topics.
```
**Danh sách Class:**
- `class PinTopicActionMixin` (Dòng 21): Mixin xử lý ghim, bỏ ghim và lấy danh sách topic nhóm.
  - `def pin_message(self, group_id, title, cli_msg_id, global_msg_id, sender_name)` (Dòng 24) — Ghim tin nhắn / Tạo Topic ghim trong nhóm qua Socket (CMD 1752 SUB 2).
  - `def unpin_message(self, group_id, topic_id, global_msg_id, cli_msg_id)` (Dòng 58) — Bỏ ghim tin nhắn / Topic khỏi nhóm qua Socket (CMD 1708 SUB 0).
  - `def fetch_pinned_topics(self, group_id, wait_response, timeout)` (Dòng 92) — Lấy danh sách các tin nhắn / topic đã ghim trong nhóm (CMD 1703 SUB 0).

---

#### 📄 `core/socket/actions/poll.py` (63 dòng)
**Mô tả Module:**
```text
core/socket/actions/poll.py — Socket action mixin cho tạo bình chọn (Poll).
```
**Danh sách Class:**
- `class PollActionMixin` (Dòng 19): Mixin xử lý tạo bình chọn qua Socket.
  - `def create_poll(self, group_id, question, options, expired_time, multi_choice, allow_add_option, is_anonymous, hide_vote_result, allow_share)` (Dòng 22) — Tạo cuộc bình chọn (Poll) trong nhóm chat Zalo (CMD 1640 SUB 3).

---

#### 📄 `core/socket/actions/send_doodle.py` (57 dòng)
**Mô tả Module:**
```text
core/socket/actions/send_doodle.py — Socket action mixin cho gửi Doodle (SUB 37).
```
**Danh sách Class:**
- `class SendDoodleActionMixin` (Dòng 11): Mixin xử lý gửi hình vẽ qua Socket.
  - `def send_doodle(self, target_id, doodle_url_or_path, is_group, caption, title, description, width, height, total_size, thumb_url, hd_url, ttl_ms, ttl, quote_data, native, sub_type, is_original, thread_type)` (Dòng 14) — Gửi hình vẽ (doodle / SUB 37) tới Group hoặc 1-1.

---

#### 📄 `core/socket/actions/send_image.py` (88 dòng)
**Mô tả Module:**
```text
core/socket/actions/send_image.py — Socket action mixin cho gửi Hình ảnh (Photo / Image).
```
**Danh sách Class:**
- `class SendImageActionMixin` (Dòng 20): Mixin xử lý gửi hình ảnh qua Socket.
  - `def send_photo(self, target_id, photo_url_or_path, is_group, caption, title, description, width, height, total_size, thumb_url, hd_url, ttl_ms, ttl, quote_data, native, sub_type, is_original, thread_type)` (Dòng 23) — Gửi hình ảnh (photo / media card) tới Group hoặc 1-1 qua TCP Socket Gateway.

---

#### 📄 `core/socket/actions/send_message.py` (175 dòng)
**Mô tả Module:**
```text
core/socket/actions/send_message.py — Socket action mixin cho gửi Text / D3 Messages & TTL.
```
**Danh sách Class:**
- `class SendMessageActionMixin` (Dòng 24): Mixin xử lý gửi tin nhắn text, mentions, quote, RTF styles và cài đặt TTL.
  - `def send_group_message(self, group_id, text, ttl_ms, ttl, quote_data, mentions, style_id, size, color, bold, italic, underline, strike, fontsize, list_type, rtf_mode, attach)` (Dòng 27)
  - `def send_1to1_message(self, target_uid, text, ttl_ms, ttl, quote_data, style_id, size, color, bold, italic, underline, strike, fontsize, list_type, rtf_mode, attach)` (Dòng 86)
  - `def set_conversation_ttl(self, target_id, ttl_seconds, is_group)` (Dòng 144) — Kích hoạt hoặc thay đổi chế độ Tin nhắn tự xóa (TTL) cho hội thoại (CMD 2060 SUB 0).

---

#### 📄 `core/socket/actions/send_reaction.py` (57 dòng)
**Mô tả Module:**
```text
core/socket/actions/send_reaction.py — Socket action mixin cho thả cảm xúc (Reaction).
```
**Danh sách Class:**
- `class SendReactionActionMixin` (Dòng 20): Mixin xử lý thả cảm xúc vào tin nhắn qua Socket.
  - `def send_reaction(self, target_id, cli_msg_id, global_msg_id, icon, is_group)` (Dòng 23)

---

#### 📄 `core/socket/actions/send_typing.py` (42 dòng)
**Mô tả Module:**
```text
core/socket/actions/send_typing.py — Socket action mixin cho gửi Typing.
```
**Danh sách Class:**
- `class SendTypingActionMixin` (Dòng 22): Mixin xử lý gửi trạng thái Typing qua Socket.
  - `def send_typing(self, target_id, is_group)` (Dòng 25)

**Toàn bộ Comments & Chú thích Logic (1 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L31 | `# Target type cho typing CMD 206 / CMD 106 luôn luôn là 3` | `tt = 3  # Target type cho typing CMD 206 / CMD 106 luôn luôn là 3` |

---

#### 📄 `core/socket/actions/send_video.py` (84 dòng)
**Mô tả Module:**
```text
core/socket/actions/send_video.py — Socket action mixin cho gửi Video (SUB 44).
```
**Danh sách Class:**
- `class SendVideoActionMixin` (Dòng 20): Mixin xử lý gửi video qua Socket.
  - `def send_video(self, target_id, video_url_or_path, is_group, caption, title, description, thumb_url, width, height, duration_ms, total_size, ttl_ms, ttl, quote_data, native, sub_type, thread_type)` (Dòng 23) — Gửi video (video / media card) tới Group hoặc 1-1 qua TCP Socket Gateway.

---

#### 📄 `core/socket/actions/undo_message.py` (88 dòng)
**Mô tả Module:**
```text
core/socket/actions/undo_message.py — Socket action mixin cho Thu hồi & Xóa tin nhắn.
```
**Danh sách Class:**
- `class UndoMessageActionMixin` (Dòng 19): Mixin xử lý thu hồi và xóa tin nhắn qua Socket.
  - `def recall_message(self, target_id, global_msg_id, cli_msg_id, is_group)` (Dòng 22) — Thu hồi tin nhắn cho tất cả mọi người (CMD 204 SUB 2 cho nhóm, CMD 114 SUB 2 cho 1-1).
  - `def delete_message(self, target_id, global_msg_id, cli_msg_id, owner_id, is_group)` (Dòng 55) — Xóa tin nhắn ở phía người dùng (CMD 205 SUB 3).

---

### 📁 Thư mục: `core/socket/tcp/`

#### 📄 `core/socket/tcp/send_doodle.py` (82 dòng)
**Mô tả Module:**
```text
core/socket/tcp/send_doodle.py — TCP Binary Protocol Builder & Handler cho Doodle / Hình vẽ (SUB 37).
```
**Danh sách Hàm (Functions):**
- `def build_doodle_attach(url, width, height, total_size, title, description, thumb_url)` (Dòng 17) — Tạo D3 Attachment JSON Dictionary cho Hình vẽ / Doodle (SUB 37).
- `def build_doodle_message_packet(uid, target_id, doodle_url, seq, ck_val, cmsg_id, is_group, caption, title, description, width, height, total_size, thumb_url, ttl_ms, quote_data, cryptkey, native, sub_type, is_original)` (Dòng 38) — Tạo Inner Packet gửi Doodle / Hình vẽ (CMD 207/113 SUB 37).

---

#### 📄 `core/socket/tcp/send_image.py` (204 dòng)
**Mô tả Module:**
```text
core/socket/tcp/send_image.py — TCP Binary Protocol Builder & Handler cho Image (Photo / SUB 32).
```
**Danh sách Hàm (Functions):**
- `def build_photo_attach(url, width, height, total_size, title, description, thumb_url, hd_url)` (Dòng 23) — Tạo D3 Attachment JSON Dictionary cho Hình ảnh (tType = 3).
- `def build_photo_binary_payload(url, title, description, thumb_url, hd_url, caption, width, height, total_size, sub_type, is_original)` (Dòng 49) — Tạo Payload Nhị Phân Native Photo Message theo chuẩn C3 trong pn/g0.smali.
- `def build_photo_message_packet(uid, target_id, photo_url, seq, ck_val, cmsg_id, is_group, caption, title, description, width, height, total_size, thumb_url, hd_url, ttl_ms, quote_data, cryptkey, native, sub_type, is_original)` (Dòng 111) — Tạo Inner Packet gửi tin nhắn hình ảnh Native (CMD 207/113 SUB 32/37).

**Toàn bộ Comments & Chú thích Logic (2 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L88 | `# 1. Header block [2B LE sub_type][1B feature_blocks_count = 0]` | `# 1. Header block [2B LE sub_type][1B feature_blocks_count = 0]` |
| L91 | `# 2. Body fields block` | `# 2. Body fields block` |

---

#### 📄 `core/socket/tcp/send_video.py` (202 dòng)
**Mô tả Module:**
```text
core/socket/tcp/send_video.py — TCP Binary Protocol Builder & Handler cho Video (SUB 44).
```
**Danh sách Hàm (Functions):**
- `def build_video_attach(url, width, height, duration, total_size, title, description, thumb_url)` (Dòng 22) — Tạo D3 Attachment JSON Dictionary cho Video (tType = 4).
- `def build_video_binary_payload(url, title, description, thumb_url, width, height, duration_ms, total_size, sub_type)` (Dòng 48) — Tạo Payload Nhị Phân Native Video Message theo chuẩn C3 trong pn/g0.smali và Lp00/x0.smali.
- `def build_video_message_packet(uid, target_id, video_url, seq, ck_val, cmsg_id, is_group, caption, title, description, thumb_url, width, height, duration_ms, total_size, ttl_ms, quote_data, cryptkey, native, sub_type)` (Dòng 109) — Tạo Inner Packet gửi tin nhắn Video Native (CMD 207/113 SUB 44) hoặc D3 attachment fallback (SUB 1/41).

**Toàn bộ Comments & Chú thích Logic (2 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L85 | `# 1. Header block` | `# 1. Header block` |
| L88 | `# 2. Body fields block:` | `# 2. Body fields block:` |

---

### 📁 Thư mục: `core/utils/`

#### 📄 `core/utils/helpers.py` (287 dòng)
**Mô tả Module:**
```text
core/utils/helpers.py — Các hàm tiện ích hỗ trợ xử lý chuỗi, TTL và chữ ký.
```
**Hằng số / Opcodes chính:** `API_KEY, API_SECRET, CLIENT_TYPE, CLIENT_VERSION, USER_AGENT`

**Danh sách Hàm (Functions):**
- `def sign_params(params, secret)` (Dòng 17) — Tính toán chữ ký sig MD5 sorted keys cho Zalo Mobile API.
- `def zalo_encode(payload, cryptkey_b64)` (Dòng 23) — Mã hóa payload (dict/list) theo chuẩn ZaloEncode (Go reference: util.ZaloEncode).
AES-128-CBC, IV=0x00*16, PKCS7 padding, key từ base64(cryptkey).
Trả về base64 string để gửi trong form field 'params'.
- `def parse_ttl_duration(val)` (Dòng 42) — Chuyển đổi chuỗi thời gian người dùng nhập thành số giây TTL chuẩn Zalo.
- `def utf16_len(text)` (Dòng 65) — Độ dài chuỗi theo đơn vị UTF-16 code units (2-byte) chuẩn Zalo.
- `def extract_target_uid(arg_text, mentioned_uids, quote_owner_id, bot_uid)` (Dòng 70) — Trích xuất UID mục tiêu từ @tag, arg số, hoặc quote reply.
- `def to_math_bold(text)` (Dòng 92) — Chuyển đổi ký tự ASCII sang Mathematical Bold (𝐓𝐞𝐬𝐭 𝐁𝐨𝐥𝐝).
- `def to_math_italic(text)` (Dòng 108) — Chuyển đổi ký tự ASCII sang Mathematical Italic (𝑇𝑒𝑠𝑡 𝐼𝑡𝑎𝑙𝑖𝑐).
- `def to_math_bold_italic(text)` (Dòng 125) — Chuyển đổi ký tự ASCII sang Mathematical Bold Italic (𝑻𝒆𝒔𝒕 𝑩𝒐𝒍𝒅 𝑰𝒕𝒂𝒍𝒊𝒄).
- `def to_combining_underline(text)` (Dòng 139) — Thêm dấu gạch chân Unicode (u̲n̲d̲e̲r̲l̲i̲n̲e̲).
- `def to_combining_strike(text)` (Dòng 144) — Thêm dấu gạch ngang Unicode (s̶t̶r̶i̶k̶e̶).
- `def apply_visual_styling(text, bold, italic, underline, strike, fontsize, color)` (Dòng 149) — Trả về nội dung văn bản gốc thuần túy, định dạng được mã hóa trực tiếp qua Zalo Native RTF Protocol.
- `def estimate_account_creation(uid)` (Dòng 164) — Ước tính khoảng thời gian khởi tạo tài khoản Zalo dựa trên dải số UID tuần tự.
- `def get_high_res_avatar(avatar_url)` (Dòng 185) — Nâng cấp URL avatar từ s160/s120 sang s600 hoặc ảnh gốc chất lượng cao.
- `def resolve_photo_metadata(source, default_width, default_height, timeout)` (Dòng 194) — Phân giải metadata ảnh (URL hoặc đường dẫn file cục bộ).
Trả về: (photo_url_or_path, width, height, total_size)
- `def resolve_video_metadata(source, default_width, default_height, default_duration_ms, timeout)` (Dòng 248) — Phân giải metadata video (URL hoặc đường dẫn file cục bộ).
Trả về: (video_url_or_path, width, height, duration_ms, total_size)

**Toàn bộ Comments & Chú thích Logic (5 comments):**
| Dòng | Nội dung Comment | Ngữ cảnh Code |
| :--- | :--- | :--- |
| L189 | `# s160-26-ava-talk.zadn.vn -> s600-26-ava-talk.zadn.vn` | `# s160-26-ava-talk.zadn.vn -> s600-26-ava-talk.zadn.vn` |
| L213 | `# 1. Đường dẫn file cục bộ` | `# 1. Đường dẫn file cục bộ` |
| L223 | `# 2. Remote URL (http:// hoặc https://)` | `# 2. Remote URL (http:// hoặc https://)` |
| L266 | `# 1. Đường dẫn file cục bộ` | `# 1. Đường dẫn file cục bộ` |
| L271 | `# 2. Remote URL` | `# 2. Remote URL` |

---

