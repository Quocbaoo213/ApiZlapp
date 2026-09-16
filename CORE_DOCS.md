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

#### 📄 `core/client.py` (233 dòng)
**Danh sách Class:**
- `class ZaloClient` (Dòng 21): Không có docstring
  - `def __init__(self, session, session_path, frame0_path, debug)` (Dòng 23)
  - `def socket(self)` (Dòng 46)
  - `def socket(self, sock)` (Dòng 50)
  - `def _load_session_data(self)` (Dòng 58)
  - `def _init_socket_client(self)` (Dòng 87)
  - `def _update_services_socket(self)` (Dòng 90)
  - `def _on_raw_socket_frame(self, parsed_frame)` (Dòng 106)
  - `def connect(self)` (Dòng 126)
  - `def add_message_listener(self, handler)` (Dòng 132)
  - `def send_message(self, target_id, text, thread_type, ttl_seconds, quote)` (Dòng 135)
  - `def send_group_message(self, group_id, text, ttl_seconds, quote)` (Dòng 138)
  - `def send_1to1_message(self, user_id, text, ttl_seconds, quote)` (Dòng 141)
  - `def send_typing(self, target_id, is_group)` (Dòng 144)
  - `def send_reaction(self, target_id, cli_msg_id, global_msg_id, icon, is_group)` (Dòng 147)
  - `def pin_message(self, group_id, title, cli_msg_id, global_msg_id, sender_name)` (Dòng 150)
  - `def unpin_message(self, group_id, global_msg_id, cli_msg_id)` (Dòng 153)
  - `def remove_member(self, group_id, member_uids)` (Dòng 156)
  - `def kick_member(self, group_id, member_uids, is_block)` (Dòng 159)
  - `def block_group_member(self, group_id, member_uids)` (Dòng 162)
  - `def block_user(self, target_uid, is_block)` (Dòng 165)
  - `def unblock_user(self, target_uid)` (Dòng 168)
  - `def leave_group(self, group_id, new_owner_id, silent, block_readd, wait_response, timeout)` (Dòng 171)
  - `def delete_message(self, group_id, cli_msg_id, global_msg_id, owner_id, is_group, only_me)` (Dòng 176)
  - `def recall_message(self, group_id, cli_msg_id, global_msg_id, owner_id, is_group)` (Dòng 179)
  - `def disband_group(self, group_id)` (Dòng 182)
  - `def add_member(self, group_id, member_uids, is_invite)` (Dòng 185)
  - `def join_group(self, target, msg)` (Dòng 188)
  - `def preview_group_link(self, link_or_code)` (Dòng 191)
  - `def get_group_list(self, page, last_group_id, avatar_size)` (Dòng 194): Lấy danh sách nhóm phân trang
  - `def get_all_groups(self, force_refresh)` (Dòng 197): Tự động lấy tất cả nhóm đang tham gia
  - `def get_group_detail(self, group_id, force_refresh)` (Dòng 200): Lấy chi tiết thông tin một nhóm theo ID
  - `def get_user_profile(self, user_id, force_refresh)` (Dòng 203): Lấy thông tin chi tiết người dùng
  - `def get_friends(self, force_refresh)` (Dòng 206): Lấy danh sách đối tượng bạn bè đầy đủ
  - `def get_friend_list(self, page, count)` (Dòng 209): Lấy danh sách bạn bè phân trang từ server
  - `def remove_friend(self, user_id)` (Dòng 212): Hủy kết bạn (unfriend)
  - `def find_user_by_phone(self, phone)` (Dòng 215): Tìm kiếm tài khoản người dùng qua số điện thoại
  - `def discover_contacts(self, phones)` (Dòng 218): Tra cứu danh bạ hàng loạt qua số điện thoại
  - `def send_friend_request(self, user_id, message)` (Dòng 221): Gửi yêu cầu kết bạn kèm lời chào
  - `def accept_friend_request(self, user_id)` (Dòng 224): Chấp nhận yêu cầu kết bạn
  - `def reject_friend_request(self, user_id)` (Dòng 227): Từ chối yêu cầu kết bạn
  - `def get_friend_requests(self, page)` (Dòng 230): Lấy danh sách lời mời kết bạn gửi đến
  - `def create_poll(self, group_id, question, options)` (Dòng 233)
  - `def send_photo(self, target_id, photo_url_or_path, thread_type, caption, title, description, width, height, total_size, thumb_url, hd_url, ttl, quote_data, native, sub_type, is_original)` (Dòng 197)
  - `def send_group_photo(self, group_id, photo_url_or_path, caption)` (Dòng 200)
  - `def send_1to1_photo(self, to_uid, photo_url_or_path, caption)` (Dòng 203)
  - `def send_doodle(self, target_id, doodle_url_or_path, thread_type, caption, title, description, thumb_url, hd_url, width, height, total_size, ttl, quote_data, native, sub_type, is_original)` (Dòng 209)
  - `def send_group_doodle(self, group_id, doodle_url_or_path, caption)` (Dòng 212)
  - `def send_1to1_doodle(self, to_uid, doodle_url_or_path, caption)` (Dòng 215)
  - `def send_video(self, target_id, video_url_or_path, thread_type, caption, title, description, thumb_url, width, height, duration_ms, total_size, ttl, quote_data, native, sub_type)` (Dòng 218)
  - `def send_group_video(self, group_id, video_url_or_path, caption)` (Dòng 221)
  - `def send_1to1_video(self, to_uid, video_url_or_path, caption)` (Dòng 224)
  - `def close(self)` (Dòng 227)
  - `def disconnect(self)` (Dòng 231)

---

### 📁 Thư mục: `core/api/`

#### 📄 `core/api/common.py` (57 dòng)
**Danh sách Class:**
- `class BaseAPI` (Dòng 8): Không có docstring
  - `def __init__(self, session_path, socket_client)` (Dòng 10)
  - `def set_socket_client(self, socket_client)` (Dòng 14)
  - `def is_connected(self)` (Dòng 18)
  - `def uid(self)` (Dòng 22)
  - `def _extract_session_fields(self, data)` (Dòng 28)
  - `def _load_session(self)` (Dòng 40)

---

#### 📄 `core/api/message.py` (44 dòng)
**Danh sách Class:**
- `class MessageAPI` (Dòng 5): Không có docstring
  - `def __init__(self, socket_client)` (Dòng 7)
  - `def send(self, target_id, text, thread_type, ttl_seconds, quote)` (Dòng 10)
  - `def send_group(self, group_id, text, ttl_seconds, quote)` (Dòng 20)
  - `def send_1to1(self, target_uid, text, ttl_seconds, quote)` (Dòng 27)
  - `def send_styled(self, target_uid, text, color, bold, italic, underline, strike, fontsize, style_id, ttl_seconds, quote)` (Dòng 34)
  - `def send_typing(self, target_id, is_group)` (Dòng 41)

---

#### 📄 `core/api/user.py` (316 dòng)
**Hằng số / Opcodes chính:** `TZ_VN, CACHE_TTL_SECONDS`

**Danh sách Class:**
- `class UserAPI` (Dòng 15): API tra cứu thông tin người dùng, quan hệ bạn bè và danh bạ qua REST API
  - `def __init__(self, session_path)` (Dòng 17)
  - `def _extract_session_fields(self, data)` (Dòng 24)
  - `def _load_session(self)` (Dòng 34)
  - `def _call_api(self, url, extra_params)` (Dòng 53)
  - `def register_seen_user(self, uid, display_name, avatar)` (Dòng 70)
  - `def refresh_friends_cache(self)` (Dòng 84)
  - `def get_user_profile(self, target_uid, force_refresh, fallback_name, fallback_avatar)` (Dòng 109)
  - `def get_all_friends(self, force_refresh)` (Dòng 132)
  - `def get_aliases(self)` (Dòng 141)
  - `def discover_contacts(self, phones)` (Dòng 144): Tra cứu hàng loạt thông tin tài khoản theo danh sách số điện thoại
  - `def remove_friend(self, user_id)` (Dòng 158): Hủy kết bạn (unfriend) qua POST https://friend.talk.zing.vn/api/friend/remove và cập nhật cache nội bộ
  - `def get_friend_list(self, page, count)` (Dòng 171): Lấy danh sách bạn bè phân trang từ https://friend.talk.zing.vn/api/friend/getlist
  - `def find_user_by_phone(self, phone)` (Dòng 174): Tìm kiếm người dùng qua số điện thoại bằng discoverContact và tự động lưu vào seen/profile cache
  - `def send_friend_request(self, user_id, message)` (Dòng 190): Gửi yêu cầu kết bạn kèm lời chào
  - `def accept_friend_request(self, user_id)` (Dòng 204): Chấp nhận yêu cầu kết bạn đang chờ duyệt
  - `def reject_friend_request(self, user_id)` (Dòng 219): Từ chối yêu cầu kết bạn
  - `def get_friend_requests(self, page)` (Dòng 227): Lấy danh sách lời mời kết bạn gửi đến
  - `def format_user_info(user_obj)` (Dòng 237): Định dạng thẻ thông tin người dùng chuẩn Zalo không emoji thừa

---

### 📁 Thư mục: `core/api/group/`

#### 📄 `core/api/group/api.py` (20 dòng)
**Danh sách Class:**
- `class GroupAPI` (Dòng 7): Không có docstring
  - `def ban(self, group_id, member_uids)` (Dòng 9)
  - `def block_user(self, target_uid, is_block)` (Dòng 12)
  - `def _call_group_api(self, endpoint, params)` (Dòng 17)

---

#### 📄 `core/api/group/info.py` (177 dòng)
**Danh sách Class:**
- `class GroupInfoAPI` (Dòng 11): API tra cứu và quản lý thông tin nhóm qua REST API và Socket
  - `def parse_group_target(target)` (Dòng 20): Phân giải target chuỗi/số thành kiểu target ('id' hoặc 'link'), group ID, và link code
  - `def get_group_info_by_link(self, link_or_code)` (Dòng 38): Tra cứu thông tin nhóm từ liên kết hoặc link code qua POST /group/info
  - `def resolve_group_id_from_link(self, link_or_code)` (Dòng 56): Phân giải Group ID số nguyên từ liên kết hoặc cache socket
  - `def format_relative_created_time(created_time_ms)` (Dòng 90): Định dạng thời gian tạo nhóm tương đối (hôm nay, x ngày trước, x tháng trước)
  - `def preview_group_link(self, link_or_code)` (Dòng 117): Xem trước thông tin chi tiết của nhóm từ liên kết
  - `def get_group_list(self, page, last_group_id, avatar_size)` (Dòng 187): Lấy danh sách nhóm phân trang từ endpoint POST https://group.api.zaloapp.com/group/list
  - `def get_all_groups(self, force_refresh)` (Dòng 215): Tự động phân trang lấy toàn bộ danh sách nhóm người dùng đang tham gia và lưu cache
  - `def get_group_detail(self, group_id, force_refresh)` (Dòng 238): Lấy chi tiết thông tin 1 nhóm theo group_id
  - `def format_group_item(group_data)` (Dòng 248): Định dạng thông tin nhóm thành chuỗi văn bản sạch, hiển thị tên, ID, thành viên, phó nhóm, link

---

### 📁 Thư mục: `core/api/group/action/`

#### 📄 `core/api/group/action/add.py` (19 dòng)
**Danh sách Class:**
- `class AddAPI` (Dòng 6): Không có docstring
  - `def add_member(self, group_id, member_uids, is_invite)` (Dòng 8)
  - `def invite_member(self, group_id, member_uids)` (Dòng 18)

---

#### 📄 `core/api/group/action/api.py` (10 dòng)
**Danh sách Class:**
- `class GroupActionAPI` (Dòng 8): Không có docstring

---

#### 📄 `core/api/group/action/ban.py` (28 dòng)
**Danh sách Class:**
- `class BanAPI` (Dòng 6): Không có docstring
  - `def block_group_member(self, group_id, member_uids)` (Dòng 8)
  - `def ban_member(self, group_id, member_uids)` (Dòng 20)

---

#### 📄 `core/api/group/action/disband.py` (36 dòng)
**Danh sách Class:**
- `class DisbandAPI` (Dòng 6): Không có docstring
  - `def disband_group_242(self, group_id)` (Dòng 8)
  - `def send_group_event_1705(self, group_id, owner_uid)` (Dòng 22)

---

#### 📄 `core/api/group/action/join.py` (97 dòng)
**Danh sách Class:**
- `class JoinAPI` (Dòng 7): Không có docstring
  - `def join_group_by_id(self, group_id, msg, source)` (Dòng 10)
  - `def join_group_by_link(self, link_or_code, msg, source, group_id)` (Dòng 23)
  - `def join_group(self, target, msg, source)` (Dòng 88)

---

#### 📄 `core/api/group/action/kick.py` (26 dòng)
**Danh sách Class:**
- `class KickAPI` (Dòng 6): Không có docstring
  - `def remove_member(self, group_id, member_uids)` (Dòng 8)
  - `def kick_member(self, group_id, member_uids, is_block)` (Dòng 18)

---

#### 📄 `core/api/group/action/leave.py` (16 dòng)
**Danh sách Class:**
- `class LeaveAPI` (Dòng 6): Không có docstring
  - `def leave_group(self, group_id, new_owner_id, silent, block_readd, wait_response, timeout)` (Dòng 8)

---

### 📁 Thư mục: `core/api/group/message/`

#### 📄 `core/api/group/message/api.py` (7 dòng)
**Danh sách Class:**
- `class GroupMessageAPI` (Dòng 5): Không có docstring

---

#### 📄 `core/api/group/message/pin.py` (27 dòng)
**Danh sách Class:**
- `class PinAPI` (Dòng 6): Không có docstring
  - `def pin_message(self, group_id, title, cli_msg_id, global_msg_id, sender_uid, sender_name)` (Dòng 8)
  - `def get_pinned_topics(self, group_id)` (Dòng 18)

---

#### 📄 `core/api/group/message/poll.py` (16 dòng)
**Danh sách Class:**
- `class PollAPI` (Dòng 6): Không có docstring
  - `def create_poll(self, group_id, question, options)` (Dòng 8)

---

#### 📄 `core/api/group/message/unpin.py` (16 dòng)
**Danh sách Class:**
- `class UnpinAPI` (Dòng 6): Không có docstring
  - `def unpin_message(self, group_id, global_msg_id, cli_msg_id)` (Dòng 8)

---

### 📁 Thư mục: `core/api/handle/`

#### 📄 `core/api/handle/api.py` (12 dòng)
**Danh sách Class:**
- `class SendAPI` (Dòng 10): Không có docstring

---

#### 📄 `core/api/handle/blockUser.py` (2 dòng)
---

#### 📄 `core/api/handle/block_user.py` (26 dòng)
**Danh sách Class:**
- `class BlockUserAPI` (Dòng 6): Không có docstring
  - `def block_user(self, target_uid, is_block)` (Dòng 8)
  - `def unblock_user(self, target_uid)` (Dòng 18)

---

#### 📄 `core/api/handle/sendDoodle.py` (2 dòng)
---

#### 📄 `core/api/handle/sendImage.py` (2 dòng)
---

#### 📄 `core/api/handle/sendMessage.py` (2 dòng)
---

#### 📄 `core/api/handle/sendReaction.py` (2 dòng)
---

#### 📄 `core/api/handle/sendTyping.py` (2 dòng)
---

#### 📄 `core/api/handle/sendVideo.py` (2 dòng)
---

#### 📄 `core/api/handle/send_doodle.py` (25 dòng)
**Danh sách Class:**
- `class SendDoodleAPI` (Dòng 7): Không có docstring
  - `def send_doodle(self, target_id, doodle_url_or_path, thread_type, caption, title, description, thumb_url, hd_url, width, height, total_size, ttl, quote_data, native, sub_type, is_original)` (Dòng 9)
  - `def send_group_doodle(self, group_id, doodle_url_or_path, caption)` (Dòng 21)
  - `def send_1to1_doodle(self, to_uid, doodle_url_or_path, caption)` (Dòng 24)

---

#### 📄 `core/api/handle/send_image.py` (35 dòng)
**Danh sách Class:**
- `class SendImageAPI` (Dòng 7): Không có docstring
  - `def send_photo(self, target_id, photo_url_or_path, thread_type, caption, title, description, width, height, total_size, thumb_url, hd_url, ttl, quote_data, native, sub_type, is_original)` (Dòng 9)
  - `def send_group_photo(self, group_id, photo_url_or_path, caption)` (Dòng 28)
  - `def send_1to1_photo(self, to_uid, photo_url_or_path, caption)` (Dòng 31)

---

#### 📄 `core/api/handle/send_messages.py` (28 dòng)
**Danh sách Class:**
- `class SendMessagesAPI` (Dòng 7): Không có docstring
  - `def send_message(self, thread_id, text, thread_type, quote_data, mentions, style_id, size, color, bold, italic, underline, strike, fontsize, list_type, ttl)` (Dòng 9)
  - `def send_group_message(self, group_id, text)` (Dòng 24)
  - `def send_1to1_message(self, to_uid, text)` (Dòng 27)

---

#### 📄 `core/api/handle/send_reaction.py` (21 dòng)
**Danh sách Class:**
- `class SendReactionAPI` (Dòng 7): Không có docstring
  - `def send_reaction(self, target_id, cli_msg_id, global_msg_id, icon, is_group)` (Dòng 9)

---

#### 📄 `core/api/handle/send_typing.py` (15 dòng)
**Danh sách Class:**
- `class SendTypingAPI` (Dòng 6): Không có docstring
  - `def send_typing(self, target_id, is_group)` (Dòng 8)

---

#### 📄 `core/api/handle/send_video.py` (33 dòng)
**Danh sách Class:**
- `class SendVideoAPI` (Dòng 7): Không có docstring
  - `def send_video(self, target_id, video_url_or_path, thread_type, caption, title, description, thumb_url, width, height, duration_ms, total_size, ttl, quote_data, native, sub_type)` (Dòng 9)
  - `def send_group_video(self, group_id, video_url_or_path, caption)` (Dòng 29)
  - `def send_1to1_video(self, to_uid, video_url_or_path, caption)` (Dòng 32)

---

#### 📄 `core/api/handle/undoMessage.py` (2 dòng)
---

#### 📄 `core/api/handle/undo_message.py` (28 dòng)
**Danh sách Class:**
- `class UndoMessageAPI` (Dòng 6): Không có docstring
  - `def delete_message(self, group_id, cli_msg_id, global_msg_id, owner_id, is_group, only_me)` (Dòng 8)
  - `def recall_message(self, group_id, cli_msg_id, global_msg_id, owner_id, is_group)` (Dòng 19)

---

### 📁 Thư mục: `core/api/properties/`

#### 📄 `core/api/properties/api.py` (7 dòng)
**Danh sách Class:**
- `class PropertiesAPI` (Dòng 5): Không có docstring

---

#### 📄 `core/api/properties/receipts.py` (15 dòng)
**Danh sách Class:**
- `class ReceiptsAPI` (Dòng 6): Không có docstring
  - `def mark_as_delivered(self, group_id, sender_uid, cli_msg_id, global_msg_id)` (Dòng 8)

---

#### 📄 `core/api/properties/typing.py` (15 dòng)
**Danh sách Class:**
- `class TypingAPI` (Dòng 6): Không có docstring
  - `def set_typing(self, thread_id, is_group)` (Dòng 8)

---

### 📁 Thư mục: `core/login/`

#### 📄 `core/login/__main__.py` (54 dòng)
**Danh sách Hàm (Functions):**
- `def main()` (Dòng 9)

---

#### 📄 `core/login/captcha.py` (73 dòng)
**Danh sách Hàm (Functions):**
- `def solve_captcha_img(bg_png, slice_png, top)` (Dòng 13)
- `def captcha_flow(captcha_session, zcid)` (Dòng 37)

---

#### 📄 `core/login/client.py` (22 dòng)
**Danh sách Class:**
- `class ZaloLoginClient` (Dòng 9): Không có docstring
  - `def __init__(self, zcid, zcid_path, api_key, secret, client_version, renew_zcid)` (Dòng 11)
  - `def save_zcid(self, zcid)` (Dòng 16)
  - `def login(self, phone, password, out_session_path, real_friends, zaloprefs_path, target_uid, probe_socket)` (Dòng 20)

---

#### 📄 `core/login/device.py` (137 dòng)
**Hằng số / Opcodes chính:** `INIT_KEY, DEFAULT_API_KEY, DEFAULT_SECRET, DEFAULT_BASE_KEY, DEFAULT_CS, DEFAULT_CERT, DEFAULT_CLIENT_VERSION, DEFAULT_USER_AGENT, REG_URL, ACC_URL, ZMVC_URL, ZMCAP_URL`

**Danh sách Class:**
- `class DeviceProfile` (Dòng 91): Không có docstring
  - `def __init__(self, params)` (Dòng 93)
  - `def default(cls)` (Dòng 99)
  - `def to_dict(self)` (Dòng 102)
  - `def __getattr__(self, item)` (Dòng 105)
  - `def __getitem__(self, item)` (Dòng 110)

**Danh sách Hàm (Functions):**
- `def pad16(d)` (Dòng 25)
- `def key32_96(zcid)` (Dòng 29)
- `def norm_phone(p)` (Dòng 33)
- `def pwd_hash(phone, password, base_key)` (Dòng 41)
- `def gen_zcid96(init_key)` (Dòng 50)
- `def is_valid_zcid(zcid_hex, init_key)` (Dòng 56)
- `def enc_body(params, zcid, api_key, secret)` (Dòng 74)
- `def base_params(zcid, phone, password)` (Dòng 81)
- `def http_post_curl(url, body, zcid, timeout)` (Dòng 113)
- `def http_post_json_curl(url, body, zcid, cookie, timeout)` (Dòng 125)

---

#### 📄 `core/login/password.py` (159 dòng)
**Danh sách Class:**
- `class PasswordAuth` (Dòng 16): Không có docstring
  - `def __init__(self, zcid, zcid_path, api_key, secret, client_version, renew_zcid)` (Dòng 18)
  - `def _init_zcid(self, zcid, renew_zcid)` (Dòng 25)
  - `def _save_zcid_to_file(self, val)` (Dòng 46)
  - `def authenticate(self, phone, password, real_friends, out_session_path, zaloprefs_path, target_uid, probe_socket)` (Dòng 53)
  - `def _process_login_success(self, data, t_start, out_session_path, zaloprefs_path, target_uid, probe_socket)` (Dòng 126)

**Danh sách Hàm (Functions):**
- `def login(phone, password, real_friends, out_session_path, zcid, renew_zcid, zaloprefs_path, target_uid, probe_socket)` (Dòng 157)

---

#### 📄 `core/login/probe.py` (111 dòng)
**Danh sách Hàm (Functions):**
- `def build_p110(sk_str, uid_int, vercode)` (Dòng 13)
- `def calc_cs(uid_int, ctr, cmd, dirn, sub, seq_b)` (Dòng 23)
- `def probe_socket_authen(sk, dk, ksid, servers, uid_int, ctr, timeout)` (Dòng 27)

---

#### 📄 `core/login/qr.py` (17 dòng)
**Danh sách Class:**
- `class QRAuth` (Dòng 5): Không có docstring
  - `def __init__(self, zcid)` (Dòng 7)
  - `def generate_qr(self)` (Dòng 12)
  - `def check_status(self)` (Dòng 16)

---

#### 📄 `core/login/session.py` (127 dòng)
**Danh sách Class:**
- `class SessionManager` (Dòng 42): Không có docstring
  - `def save(data, filepath)` (Dòng 45)
  - `def load(filepath)` (Dòng 49)
  - `def load_zaloprefs(prefs_path, uid)` (Dòng 54)
  - `def extract_dk(data)` (Dòng 58)
  - `def extract_cryptkey(data)` (Dòng 92)
  - `def validate(data)` (Dòng 115)

**Danh sách Hàm (Functions):**
- `def extract_all(response)` (Dòng 9)
- `def read_from_zaloprefs(prefs_path, uid)` (Dòng 21)
- `def save_session_file(session_data, filepath)` (Dòng 34)

---

#### 📄 `core/login/two_factor.py` (140 dòng)
**Hằng số / Opcodes chính:** `METHOD_NAMES`

**Danh sách Class:**
- `class TwoFactorAuth` (Dòng 12): Không có docstring
  - `def get_webview_html(session)` (Dòng 15)
  - `def post_vc_json(url, session, data)` (Dòng 22)
  - `def extract_available_methods(cls, session)` (Dòng 31)
  - `def execute_2fa_flow(cls, session, interactive)` (Dòng 55)
- `class FriendAuth` (Dòng 95): Không có docstring
  - `def execute_friend_flow(session, zcid, cookie, real_friends, interactive)` (Dòng 98)

---

### 📁 Thư mục: `core/models/`

#### 📄 `core/models/enums.py` (79 dòng)
**Danh sách Class:**
- `class ThreadType` (Dòng 4): Không có docstring
- `class Gender` (Dòng 8): Không có docstring
  - `def to_display_string(cls, code)` (Dòng 14)
- `class MessageType` (Dòng 21): Không có docstring
- `class ReactionIcon` (Dòng 28): Không có docstring
  - `def resolve(cls, val)` (Dòng 47)
  - `def from_str(cls, val)` (Dòng 60)
- `class ZaloGroupErrorCode` (Dòng 64): Không có docstring
  - `def get_message(cls, code)` (Dòng 77)

---

#### 📄 `core/models/message.py` (37 dòng)
**Danh sách Class:**
- `class Quote` (Dòng 6): Không có docstring
  - `def to_dict(self)` (Dòng 17)
- `class Message` (Dòng 26): Không có docstring

---

#### 📄 `core/models/user.py` (93 dòng)
**Hằng số / Opcodes chính:** `TZ_VN`

**Danh sách Class:**
- `class UserProfile` (Dòng 8): Không có docstring
  - `def from_dict(cls, d)` (Dòng 26)
  - `def gender_display(self)` (Dòng 70)
  - `def to_card(self)` (Dòng 73)

---

### 📁 Thư mục: `core/socket/`

#### 📄 `core/socket/blockUser.py` (2 dòng)
---

#### 📄 `core/socket/client.py` (425 dòng)
**Hằng số / Opcodes chính:** `DEFAULT_SERVERS`

**Danh sách Class:**
- `class ZaloSocketClient` (Dòng 28): Không có docstring
  - `def __init__(self, uid, dk, cryptkey, session_key, ksid, server_pubkey_b64, frame0_path, init_sequence_path, server_pool, state_file, on_message_callback, ping_interval, debug)` (Dòng 30)
  - `def _prepare_cmd_ack(self, cmd)` (Dòng 69)
  - `def _wait_cmd_ack(self, cmd, timeout)` (Dòng 78)
  - `def _try_load_frame0(self)` (Dòng 88)
  - `def _resolve_state_file(self)` (Dòng 104)
  - `def _load_or_init_state(self)` (Dòng 113)
  - `def _save_state(self, force)` (Dòng 126)
  - `def _save_state_if_needed(self)` (Dòng 141)
  - `def _next_seq(self)` (Dòng 144)
  - `def _next_cmsg_id(self)` (Dòng 149)
  - `def _next_ck_val(self)` (Dòng 154)
  - `def _get_next_counters(self)` (Dòng 159)
  - `def _select_socket_server(self)` (Dòng 170)
  - `def connect(self)` (Dòng 178)
  - `def close(self)` (Dòng 231)
  - `def disconnect(self)` (Dòng 243)
  - `def _recv_loop(self)` (Dòng 246)
  - `def _ping_loop(self)` (Dòng 379)
  - `def _disconnect_socket(self)` (Dòng 400)
  - `def _supervisor_loop(self)` (Dòng 412)

---

#### 📄 `core/socket/crypto.py` (157 dòng)
**Hằng số / Opcodes chính:** `DEFAULT_XK, DEFAULT_BASE_KEY, DEFAULT_SECRET, _P, _A24, _BASE_POINT_U`

**Danh sách Hàm (Functions):**
- `def key32(zcid)` (Dòng 16)
- `def password_hash(phone, password, base_key)` (Dòng 24)
- `def compute_sig(data_hex, api_key, secret)` (Dòng 29)
- `def encrypt_http_data(params, zcid)` (Dòng 33)
- `def decrypt_http_data(data_hex, zcid)` (Dòng 41)
- `def encrypt_aes_gcm(plaintext, dk, iv)` (Dòng 50)
- `def decrypt_aes_gcm(frame_body, dk)` (Dòng 61)
- `def encrypt_e2ee_cbc(plaintext, cryptkey, iv)` (Dòng 72)
- `def decrypt_e2ee_cbc(ciphertext, cryptkey, iv)` (Dòng 84)
- `def xor_d3(data, key)` (Dòng 96)
- `def _clamp(k_bytes)` (Dòng 103)
- `def _cswap(swap, x_2, x_3)` (Dòng 110)
- `def x25519(scalar_bytes, u_bytes)` (Dòng 114)
- `def x25519_keypair()` (Dòng 145)
- `def x25519_shared_secret(private_key, peer_public_key)` (Dòng 150)
- `def gzip_decompress(data)` (Dòng 153)
- `def gzip_compress(data)` (Dòng 156)

---

#### 📄 `core/socket/groupActions.py` (2 dòng)
---

#### 📄 `core/socket/handshake.py` (127 dòng)
**Danh sách Hàm (Functions):**
- `def build_p110(sk_str, uid, vercode)` (Dòng 9)
- `def build_authen_body(sk_str, uid, ctr)` (Dòng 17)
- `def build_prov_frame(session_key, dk, ksid, server_pubkey_b64, uid)` (Dòng 22)
- `def build_init_frames(uid, dest, vercode)` (Dòng 43)
- `def send_init_frames(sock, dk, uid, dest, vercode, send_lock)` (Dòng 113)

---

#### 📄 `core/socket/keepalive.py` (2 dòng)
---

#### 📄 `core/socket/pinTopic.py` (2 dòng)
---

#### 📄 `core/socket/poll.py` (2 dòng)
---

#### 📄 `core/socket/protocol.py` (1147 dòng)
**Hằng số / Opcodes chính:** `CKSUM_MAGIC, MAGIC_CHECKSUM_XOR, XK, FRAME_TYPE_CONTROL, FRAME_TYPE_DATA, FRAME_TYPE_KEY_EXCHANGE, FRAME_TYPE_HANDSHAKE, CMD_PING, SUB_PING, CMD_GROUP_MSG, SUB_GROUP_MSG, CMD_1TO1_MSG, SUB_1TO1_MSG, SUB_PHOTO_MSG, SUB_DOODLE_MSG, SUB_PHOTO_ATTACH_MSG, SUB_ATTACH_MSG, SUB_VIDEO_MSG, CMD_GROUP_TYPING, SUB_GROUP_TYPING, CMD_1TO1_TYPING, SUB_1TO1_TYPING, CMD_GROUP_PREPARE, SUB_GROUP_PREPARE, CMD_GROUP_SYNC_BROADCAST, SUB_GROUP_SYNC, CMD_DELIVERY_RECEIPT, SUB_DELIVERY_RECEIPT, CMD_1TO1_INCOMING, CMD_REMOVE_MEMBER, SUB_REMOVE_MEMBER, CMD_KICK_MEMBER, SUB_KICK_MEMBER, CMD_DISBAND_GROUP, SUB_DISBAND_GROUP, CMD_BLOCK_GROUP_MEMBER, SUB_BLOCK_GROUP_MEMBER, CMD_BLOCK_USER, SUB_BLOCK_USER, CMD_ADD_MEMBER, SUB_ADD_MEMBER, CMD_LEAVE_GROUP, SUB_LEAVE_GROUP, CMD_LEAVE_GROUP_225, SUB_LEAVE_GROUP_225, CMD_LEAVE_GROUP_239, SUB_LEAVE_GROUP_239, CMD_JOIN_GROUP, SUB_JOIN_GROUP, CMD_JOIN_GROUP_INVITE, SUB_JOIN_GROUP_INVITE, CMD_REQUEST_JOIN_GROUP, SUB_REQUEST_JOIN_GROUP, CMD_GROUP_LINK_INFO, SUB_GROUP_LINK_INFO, CMD_JOIN_GROUP_BY_LINK, SUB_JOIN_GROUP_BY_LINK, CMD_PIN_TOPIC, SUB_PIN_TOPIC, CMD_UNPIN_TOPIC, SUB_UNPIN_TOPIC, CMD_CREATE_POLL, SUB_CREATE_POLL, CMD_RECALL_MSG_GROUP, SUB_RECALL_MSG_GROUP, CMD_RECALL_MSG_1TO1, SUB_RECALL_MSG_1TO1, CMD_DELETE_MSG, SUB_DELETE_MSG, CMD_BLOCK_USER_1TO1, SUB_BLOCK_USER_1TO1, CMD_UNBLOCK_USER_1TO1, SUB_UNBLOCK_USER_1TO1, INNER_HEADER_FORMAT, INNER_HEADER_SIZE`

**Danh sách Class:**
- `class InnerPacketHeader` (Dòng 92): Không có docstring
  - `def pack(self)` (Dòng 102)
  - `def unpack(cls, data)` (Dòng 106)
- `class OuterFrame` (Dòng 113): Không có docstring
  - `def pack(self)` (Dòng 118)
  - `def unpack_from_buffer(cls, buf)` (Dòng 122)

**Danh sách Hàm (Functions):**
- `def compute_checksum(cmd, sub, seq, uid, target, target_type, cmsg, bb, ty, ver)` (Dòng 134)
- `def xor_encode_d3(plain, uid, xk)` (Dòng 138)
- `def xor_decode_d3(cipher, uid, xk)` (Dòng 145)
- `def dekey(a4, uid)` (Dòng 148)
- `def xor_enc(pt, uid)` (Dòng 153)
- `def build_photo_attach(url, width, height, total_size, title, description, thumb_url, hd_url, is_original)` (Dòng 157)
- `def build_video_attach(url, width, height, duration, total_size, title, description, thumb_url)` (Dòng 168)
- `def build_d3_payload_group(text, ttl_ms, quote_data, mentions, style_id, size, color, bold, italic, underline, strike, fontsize, list_type, rtf_mode, attach)` (Dòng 173)
- `def build_d3_json(style_id)` (Dòng 274)
- `def build_d3_payload_1to1(text, cryptkey, ttl_ms, quote_data, attach)` (Dòng 280)
- `def build_d3_payload_1to1_styled(text, cryptkey, style_id, size, color, bold, italic, ttl_ms)` (Dòng 343)
- `def build_d3_payload_1to1_rtf(text, cryptkey, styles, rtf_mode, list_type)` (Dòng 367)
- `def build_ping_packet(uid, seq, ck_val, dest)` (Dòng 394)
- `def build_typing_packet(uid, target_id, is_group, seq, ck_val, cmsg_id)` (Dòng 402)
- `def build_group_message_packet(uid, group_id, text, seq, ck_val, cmsg_id, ttl_ms, quote_data, mentions, style_id, size, color, bold, italic, underline, strike, fontsize, list_type, rtf_mode, attach)` (Dòng 408)
- `def build_1to1_message_packet(uid, target_uid, text, cryptkey, seq, ck_val, cmsg_id, ttl_ms, quote_data, style_id, size, color, bold, italic, underline, strike, fontsize, list_type, rtf_mode, attach)` (Dòng 415)
- `def build_photo_binary_payload(url, title, description, thumb_url, hd_url, caption, width, height, total_size, sub_type, is_original)` (Dòng 440)
- `def build_photo_message_packet(uid, target_id, photo_url, seq, ck_val, cmsg_id, is_group, caption, title, description, width, height, total_size, thumb_url, hd_url, ttl_ms, quote_data, cryptkey, native, sub_type, is_original)` (Dòng 472)
- `def build_video_binary_payload(url, title, description, thumb_url, width, height, duration_ms, total_size, sub_type)` (Dòng 495)
- `def build_video_message_packet(uid, target_id, video_url, seq, ck_val, cmsg_id, is_group, caption, title, description, thumb_url, width, height, duration_ms, total_size, ttl_ms, quote_data, cryptkey, native, sub_type)` (Dòng 517)
- `def build_reaction_packet(uid, target_id, cli_msg_id, global_msg_id, icon, is_group, seq, ck_val, cmsg_id)` (Dòng 541)
- `def build_pin_topic_packet(uid, group_id, title, cli_msg_id, global_msg_id, sender_name, seq, ck_val, vercode)` (Dòng 563)
- `def build_unpin_topic_packet(uid, group_id, topic_id, global_msg_id, cli_msg_id, seq, ck_val, vercode)` (Dòng 591)
- `def build_fetch_pinned_topics_packet(uid, group_id, from_time, seq, ck_val, vercode)` (Dòng 608)
- `def build_cmd_1705_packet(uid, group_id, field_8byte, prefix_data, seq, ck_val)` (Dòng 619)
- `def build_disband_242_packet(uid, group_id, seq, ck_val, vercode)` (Dòng 635)
- `def build_remove_member_packet(uid, group_id, member_uids, seq, ck_val)` (Dòng 647)
- `def build_kick_member_packet(uid, group_id, member_uids, is_block, seq, ck_val)` (Dòng 660)
- `def build_block_group_member_packet(uid, group_id, member_uids, seq, ck_val, vercode)` (Dòng 675)
- `def build_block_user_packet(uid, target_uid, is_block, seq, ck_val, vercode)` (Dòng 678)
- `def build_unblock_user_packet(uid, target_uid, seq, ck_val, vercode)` (Dòng 697)
- `def build_leave_group_packet(uid, group_id, new_owner_id, is_silent, is_block_readd, seq, ck_val, vercode, lang)` (Dòng 700)
- `def build_leave_group_225_packet(uid, group_id, seq, ck_val, vercode, lang)` (Dòng 721)
- `def build_create_poll_packet(uid, group_id, question, options, seq, ck_val, vercode)` (Dòng 738)
- `def build_join_group_by_link_901_packet(uid, link_url, seq, ck_val)` (Dòng 761)
- `def build_preview_link_901_packet(uid, link_url, seq, ck_val, vercode, source, sub_type)` (Dòng 777)
- `def build_query_group_906_packet(uid, group_id, seq, ck_val)` (Dòng 780)
- `def parse_d3_compressed_json(body, uid)` (Dòng 790)
- `def build_recall_message_packet(uid, target_id, cli_msg_id, global_msg_id, msg_type, owner_id, is_group, cmsg_counter, seq, ck_val)` (Dòng 855)
- `def build_delete_message_packet(uid, group_id, cli_msg_id, global_msg_id, is_group, only_me, seq, ck_val)` (Dòng 873)
- `def build_add_member_packet(uid, group_id, member_uids, is_invite, seq, ck_val)` (Dòng 886)
- `def build_join_group_packet(uid, group_id, source, seq, ck_val, vercode, ts_ms)` (Dòng 901)
- `def build_join_group_invite_packet(uid, group_id, inviter_uid, seq, ck_val, vercode)` (Dòng 914)
- `def build_request_join_group_packet(uid, group_id, msg, link_url, source, sub_source, seq, ck_val, vercode)` (Dòng 925)
- `def build_group_link_info_packet(uid, link_url, source, sub_source, seq, ck_val, vercode)` (Dòng 956)
- `def build_join_group_by_link_packet(uid, link_code, group_id, flag_byte, seq, ck_val, vercode)` (Dòng 959)
- `def build_join_group_2000_packet(uid, group_id, flag_byte, seq, ck_val, vercode)` (Dòng 977)
- `def build_outer_frame(inner_packet, dk)` (Dòng 993)
- `def parse_incoming_frame(frame, dk, cryptkey, my_uid)` (Dòng 998)
- `def parse_incoming_messages_payload(cmd, sub, uid, params_bytes, cryptkey, my_uid)` (Dòng 1031)
- `def parse_group_sync_1867(params_bytes)` (Dòng 1128)
- `def parse_delivery_receipt_202(params_bytes)` (Dòng 1132)

---

#### 📄 `core/socket/sendDoodle.py` (2 dòng)
---

#### 📄 `core/socket/sendImage.py` (2 dòng)
---

#### 📄 `core/socket/sendMessage.py` (2 dòng)
---

#### 📄 `core/socket/sendReaction.py` (2 dòng)
---

#### 📄 `core/socket/sendTyping.py` (2 dòng)
---

#### 📄 `core/socket/sendVideo.py` (2 dòng)
---

#### 📄 `core/socket/undoMessage.py` (2 dòng)
---

### 📁 Thư mục: `core/socket/actions/`

#### 📄 `core/socket/actions/block_user.py` (29 dòng)
**Danh sách Class:**
- `class BlockUserActionMixin` (Dòng 6): Không có docstring
  - `def block_user(self, target_uid, is_block)` (Dòng 8)
  - `def unblock_user(self, target_uid)` (Dòng 28)

---

#### 📄 `core/socket/actions/group_actions.py` (368 dòng)
**Danh sách Class:**
- `class GroupActionsMixin` (Dòng 7): Không có docstring
  - `def send_group_event_1705(self, group_id, owner_uid, wait_ack, timeout)` (Dòng 9)
  - `def disband_group_242(self, group_id, wait_response, timeout)` (Dòng 36)
  - `def remove_member(self, group_id, member_uids)` (Dòng 61)
  - `def kick_member(self, group_id, member_uids, is_block)` (Dòng 83)
  - `def block_group_member(self, group_id, member_uids)` (Dòng 107)
  - `def leave_group(self, group_id, new_owner_id, silent, block_readd, wait_response, timeout)` (Dòng 110)
  - `def add_member(self, group_id, member_uids, is_invite)` (Dòng 142)
  - `def join_group(self, group_id, source)` (Dòng 164)
  - `def preview_link_901(self, link_url, wait_response, timeout)` (Dòng 192)
  - `def query_group_906(self, group_id, wait_response, timeout)` (Dòng 219)
  - `def join_group_by_link(self, link_url, group_id, msg, source, wait_response, timeout)` (Dòng 241)
  - `def join_group_invite(self, group_id, inviter_uid)` (Dòng 301)
  - `def request_join_group(self, group_id, link_url, msg, source, sub_source, wait_response, timeout)` (Dòng 320)
  - `def request_group_link_info(self, link_url, source, sub_source, timeout)` (Dòng 361)

---

#### 📄 `core/socket/actions/pin_topic.py` (68 dòng)
**Danh sách Class:**
- `class PinTopicActionMixin` (Dòng 7): Không có docstring
  - `def pin_message(self, group_id, title, cli_msg_id, global_msg_id, sender_name)` (Dòng 9)
  - `def unpin_message(self, group_id, topic_id, global_msg_id, cli_msg_id)` (Dòng 26)
  - `def fetch_pinned_topics(self, group_id, wait_response, timeout)` (Dòng 45)

---

#### 📄 `core/socket/actions/poll.py` (25 dòng)
**Danh sách Class:**
- `class PollActionMixin` (Dòng 7): Không có docstring
  - `def create_poll(self, group_id, question, options, expired_time, multi_choice, allow_add_option, is_anonymous, hide_vote_result, allow_share)` (Dòng 9)

---

#### 📄 `core/socket/actions/send_doodle.py` (7 dòng)
**Danh sách Class:**
- `class SendDoodleActionMixin` (Dòng 4): Không có docstring
  - `def send_doodle(self, target_id, doodle_url_or_path, is_group, caption, title, description, width, height, total_size, thumb_url, hd_url, ttl_ms, ttl, quote_data, native, sub_type, is_original, thread_type)` (Dòng 6)

---

#### 📄 `core/socket/actions/send_image.py` (28 dòng)
**Danh sách Class:**
- `class SendImageActionMixin` (Dòng 7): Không có docstring
  - `def send_photo(self, target_id, photo_url_or_path, is_group, caption, title, description, width, height, total_size, thumb_url, hd_url, ttl_ms, ttl, quote_data, native, sub_type, is_original, thread_type)` (Dòng 9)

---

#### 📄 `core/socket/actions/send_message.py` (65 dòng)
**Danh sách Class:**
- `class SendMessageActionMixin` (Dòng 8): Không có docstring
  - `def send_group_message(self, group_id, text, ttl_ms, ttl, quote_data, mentions, style_id, size, color, bold, italic, underline, strike, fontsize, list_type, rtf_mode, attach)` (Dòng 10)
  - `def send_1to1_message(self, target_uid, text, ttl_ms, ttl, quote_data, style_id, size, color, bold, italic, underline, strike, fontsize, list_type, rtf_mode, attach)` (Dòng 29)
  - `def set_conversation_ttl(self, target_id, ttl_seconds, is_group)` (Dòng 48)

---

#### 📄 `core/socket/actions/send_reaction.py` (26 dòng)
**Danh sách Class:**
- `class SendReactionActionMixin` (Dòng 7): Không có docstring
  - `def send_reaction(self, target_id, cli_msg_id, global_msg_id, icon, is_group)` (Dòng 9)

---

#### 📄 `core/socket/actions/send_typing.py` (25 dòng)
**Danh sách Class:**
- `class SendTypingActionMixin` (Dòng 6): Không có docstring
  - `def send_typing(self, target_id, is_group)` (Dòng 8)

---

#### 📄 `core/socket/actions/send_video.py` (27 dòng)
**Danh sách Class:**
- `class SendVideoActionMixin` (Dòng 7): Không có docstring
  - `def send_video(self, target_id, video_url_or_path, is_group, caption, title, description, thumb_url, width, height, duration_ms, total_size, ttl_ms, ttl, quote_data, native, sub_type, thread_type)` (Dòng 9)

---

#### 📄 `core/socket/actions/undo_message.py` (42 dòng)
**Danh sách Class:**
- `class UndoMessageActionMixin` (Dòng 6): Không có docstring
  - `def recall_message(self, target_id, global_msg_id, cli_msg_id, is_group)` (Dòng 8)
  - `def delete_message(self, target_id, global_msg_id, cli_msg_id, owner_id, is_group)` (Dòng 26)

---

### 📁 Thư mục: `core/socket/tcp/`

#### 📄 `core/socket/tcp/send_doodle.py` (9 dòng)
**Danh sách Hàm (Functions):**
- `def build_doodle_attach(url, width, height, total_size, title, description, thumb_url)` (Dòng 5)
- `def build_doodle_message_packet(uid, target_id, doodle_url, seq, ck_val, cmsg_id, is_group, caption, title, description, width, height, total_size, thumb_url, ttl_ms, quote_data, cryptkey, native, sub_type, is_original)` (Dòng 8)

---

#### 📄 `core/socket/tcp/send_image.py` (62 dòng)
**Danh sách Hàm (Functions):**
- `def build_photo_attach(url, width, height, total_size, title, description, thumb_url, hd_url)` (Dòng 7)
- `def build_photo_binary_payload(url, title, description, thumb_url, hd_url, caption, width, height, total_size, sub_type, is_original)` (Dòng 10)
- `def build_photo_message_packet(uid, target_id, photo_url, seq, ck_val, cmsg_id, is_group, caption, title, description, width, height, total_size, thumb_url, hd_url, ttl_ms, quote_data, cryptkey, native, sub_type, is_original)` (Dòng 42)

---

#### 📄 `core/socket/tcp/send_video.py` (55 dòng)
**Danh sách Hàm (Functions):**
- `def build_video_attach(url, width, height, duration, total_size, title, description, thumb_url)` (Dòng 6)
- `def build_video_binary_payload(url, title, description, thumb_url, width, height, duration_ms, total_size, sub_type)` (Dòng 9)
- `def build_video_message_packet(uid, target_id, video_url, seq, ck_val, cmsg_id, is_group, caption, title, description, thumb_url, width, height, duration_ms, total_size, ttl_ms, quote_data, cryptkey, native, sub_type)` (Dòng 34)

---

### 📁 Thư mục: `core/utils/`

#### 📄 `core/utils/helpers.py` (190 dòng)
**Hằng số / Opcodes chính:** `API_KEY, API_SECRET, CLIENT_TYPE, CLIENT_VERSION, USER_AGENT`

**Danh sách Hàm (Functions):**
- `def sign_params(params, secret)` (Dòng 10)
- `def zalo_encode(payload, cryptkey_b64)` (Dòng 14)
- `def parse_ttl_duration(val)` (Dòng 26)
- `def utf16_len(text)` (Dòng 47)
- `def extract_target_uid(arg_text, mentioned_uids, quote_owner_id, bot_uid)` (Dòng 50)
- `def to_math_bold(text)` (Dòng 62)
- `def to_math_italic(text)` (Dòng 76)
- `def to_math_bold_italic(text)` (Dòng 91)
- `def to_combining_underline(text)` (Dòng 103)
- `def to_combining_strike(text)` (Dòng 106)
- `def apply_visual_styling(text, bold, italic, underline, strike, fontsize, color)` (Dòng 109)
- `def estimate_account_creation(uid)` (Dòng 112)
- `def get_high_res_avatar(avatar_url)` (Dòng 131)
- `def resolve_photo_metadata(source, default_width, default_height, timeout)` (Dòng 137)
- `def resolve_video_metadata(source, default_width, default_height, default_duration_ms, timeout)` (Dòng 172)

---

