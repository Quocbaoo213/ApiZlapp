#!/usr/bin/env python3
"""
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
"""

import os
import json
import base64
import logging
import time
from typing import Optional, Callable, Dict, Any, List, Union

from core.socket import ZaloSocketClient, DEFAULT_SERVERS
from core.models import ThreadType, UserProfile, Message, Quote, ReactionIcon
from core.api import (
    SendAPI,
    GroupAPI,
    GroupActionAPI,
    GroupMessageAPI,
    GroupInfoAPI,
    PropertiesAPI,
    UserAPI,
    MessageAPI
)

logger = logging.getLogger("core.client")


class ZaloClient:
    """Client tích hợp đầy đủ các tính năng cho Zalo Mobile App."""

    def __init__(
        self,
        session: Optional[Union[str, Dict[str, Any]]] = None,
        session_path: Optional[str] = None,
        frame0_path: Optional[str] = None,
        debug: bool = False
    ):
        # Ưu tiên session argument, sau đó session_path argument
        self.session_source = session if session is not None else session_path
        self.session_path = self.session_source if isinstance(self.session_source, str) else None
        self.frame0_path = frame0_path
        self.debug = debug
        self.session_data: Dict[str, Any] = {}
        self.uid: int = 0
        self._load_session_data()

        self._message_handlers: List[Callable[[Message], None]] = []

        # 1. Socket client
        self._socket: Optional[ZaloSocketClient] = None
        self._init_socket_client()

        # 2. Khởi tạo các Sub-Services theo kiến trúc Go Reference
        active_session_arg = self.session_data if self.session_data else self.session_source
        self.send = SendAPI(session_path=active_session_arg, socket_client=self._socket)
        self.group = GroupAPI(session_path=active_session_arg, socket_client=self._socket)
        self.group_action = GroupActionAPI(session_path=active_session_arg, socket_client=self._socket)
        self.group_message = GroupMessageAPI(session_path=active_session_arg, socket_client=self._socket)
        self.group_info = GroupInfoAPI(session_path=active_session_arg, socket_client=self._socket)
        self.properties = PropertiesAPI(session_path=active_session_arg, socket_client=self._socket)
        self.users = UserAPI(session_path=active_session_arg)
        
        # Facades tương thích ngược
        self.messages = MessageAPI(self._socket)
        self.groups = self.group

    @property
    def socket(self) -> Optional[ZaloSocketClient]:
        return self._socket

    @socket.setter
    def socket(self, sock: Optional[ZaloSocketClient]):
        self._socket = sock
        for attr in ('send', 'group', 'group_action', 'group_message', 'group_info', 'properties', 'messages', 'groups'):
            if hasattr(self, attr):
                obj = getattr(self, attr)
                if obj and hasattr(obj, '_socket'):
                    obj._socket = sock

    def _load_session_data(self):
        # 1. Trường hợp truyền trực tiếp dict in-memory
        if isinstance(self.session_source, dict):
            data = self.session_source
        else:
            # 2. Trường hợp truyền đường dẫn hoặc tìm kiếm mặc định
            resolved_path = None
            search_paths = []
            if isinstance(self.session_source, str) and self.session_source:
                search_paths.append(self.session_source)
            search_paths.extend([
                os.path.join(os.getcwd(), "fresh_session.json"),
                "fresh_session.json",
                os.path.expanduser("~/.zalo/fresh_session.json"),
                "/root/zalo/fresh_session.json",
                "/sdcard/Download/Zalo/zm/fresh_session.json",
                "/sdcard/Download/Zalo/active_session.json"
            ])
            for p in search_paths:
                if p and os.path.isfile(p):
                    resolved_path = p
                    break

            if not resolved_path:
                raise FileNotFoundError(
                    f"Không tìm thấy file session. Hãy chỉ định đường dẫn hoặc đăng nhập qua `python -m core.login`"
                )

            self.session_path = resolved_path
            with open(resolved_path, "r", encoding="utf-8") as f:
                data = json.load(f)

        self.session_data = data
        self.uid = int(data.get("uid") or (data.get("data") or {}).get("userId") or 0)
        dk_hex = data.get("dk_hex")
        dk_b64 = data.get("dk_b64")
        self.dk = bytes.fromhex(dk_hex) if dk_hex else (base64.b64decode(dk_b64) if dk_b64 else None)
        cryptkey_b64 = data.get("cryptkey")
        self.cryptkey = base64.b64decode(cryptkey_b64) if cryptkey_b64 else None
        self.session_key = data.get("session_key")
        self.ksid = data.get("ksid")
        self.servers = data.get("socketServers") or data.get("servers") or DEFAULT_SERVERS

    def _init_socket_client(self):
        self._socket = ZaloSocketClient(
            uid=self.uid,
            dk=self.dk,
            session_key=self.session_key,
            ksid=self.ksid,
            cryptkey=self.cryptkey,
            frame0_path=self.frame0_path,
            server_pool=self.servers,
            on_message_callback=self._on_raw_socket_frame,
            debug=self.debug
        )

    def _update_services_socket(self):
        """Cập nhật socket instance cho tất cả các sub-services sau khi khởi tạo/kết nối lại."""
        if hasattr(self, 'send'): self.send.set_socket_client(self._socket)
        if hasattr(self, 'group'): self.group.set_socket_client(self._socket)
        if hasattr(self, 'group_action'): self.group_action.set_socket_client(self._socket)
        if hasattr(self, 'group_message'): self.group_message.set_socket_client(self._socket)
        if hasattr(self, 'group_info'): self.group_info.set_socket_client(self._socket)
        if hasattr(self, 'properties'): self.properties.set_socket_client(self._socket)
        if hasattr(self, 'messages'): self.messages._socket = self._socket

    def _on_raw_socket_frame(self, parsed_frame: Dict[str, Any]):
        cmd = parsed_frame.get("cmd")
        parsed_data = parsed_frame.get("parsed_data")

        if cmd in (101, 201, 1865, 1867) and parsed_data:
            messages = parsed_data.get("messages", [])
            for m in messages:
                from_u = m.get("from_uid")
                if not from_u or from_u == self.uid:
                    continue
                to_g = m.get("to_group")
                from_d = m.get("from_display") or m.get("from_name") or str(from_u)
                content = m.get("content", "") or m.get("text", "")
                
                # Tự động học metadata người dùng
                self.users.register_seen_user(from_u, display_name=from_d)

                msg_obj = Message(
                    text=content,
                    from_uid=int(from_u),
                    from_name=from_d,
                    group_id=int(to_g) if to_g else None,
                    is_group=bool(to_g),
                    msg_id=int(m.get("msg_id") or 0),
                    cli_msg_id=int(m.get("cli_msg_id") or 0),
                    timestamp=int(m.get("ts") or time.time() * 1000),
                    mentions=m.get("mentions") or [],
                    quote=m.get("quote"),
                    raw=m
                )

                for handler in self._message_handlers:
                    try:
                        handler(msg_obj)
                    except Exception as ex:
                        logger.error(f"Lỗi trong message handler: {ex}")

    def connect(self) -> bool:
        """Kết nối tới Zalo Gateway và hoàn tất PROV Handshake."""
        if not self._socket:
            self._init_socket_client()
        self._update_services_socket()
        return self._socket.connect()

    def add_message_listener(self, handler: Callable[[Message], None]):
        """Đăng ký listener nhận tin nhắn realtime."""
        self._message_handlers.append(handler)

    # --- Shortcut Delegations (Tương thích 100% với code cũ) ---

    def send_message(
        self,
        target_id: int,
        text: str,
        thread_type: ThreadType = ThreadType.GROUP,
        ttl_seconds: int = 0,
        quote: Optional[Quote | Dict[str, Any]] = None
    ) -> bool:
        """Gửi tin nhắn (Group hoặc 1-1)."""
        return self.send.send_message(
            thread_id=target_id,
            text=text,
            thread_type=thread_type,
            ttl=ttl_seconds,
            quote_data=quote.to_dict() if isinstance(quote, Quote) else quote
        )

    def send_group_message(
        self,
        group_id: int,
        text: str,
        ttl_seconds: int = 0,
        quote: Optional[Quote | Dict[str, Any]] = None
    ) -> bool:
        """Gửi tin nhắn nhóm."""
        return self.send_message(group_id, text, thread_type=ThreadType.GROUP, ttl_seconds=ttl_seconds, quote=quote)

    def send_1to1_message(
        self,
        user_id: int,
        text: str,
        ttl_seconds: int = 0,
        quote: Optional[Quote | Dict[str, Any]] = None
    ) -> bool:
        """Gửi tin nhắn 1-1."""
        return self.send_message(user_id, text, thread_type=ThreadType.USER, ttl_seconds=ttl_seconds, quote=quote)

    def send_typing(
        self,
        target_id: int,
        is_group: bool = True
    ) -> bool:
        """Gửi trạng thái đang soạn tin nhắn."""
        return self.send.send_typing(target_id=target_id, is_group=is_group)

    def send_reaction(
        self,
        target_id: int,
        cli_msg_id: int,
        global_msg_id: int = 0,
        icon: ReactionIcon | str = ReactionIcon.HEART,
        is_group: bool = True
    ) -> bool:
        """Thả cảm xúc vào tin nhắn."""
        return self.send.send_reaction(
            target_id=target_id,
            cli_msg_id=cli_msg_id,
            global_msg_id=global_msg_id,
            icon=icon.value if isinstance(icon, ReactionIcon) else str(icon),
            is_group=is_group
        )

    def pin_message(
        self,
        group_id: int,
        title: str = "",
        cli_msg_id: int = 0,
        global_msg_id: int = 0,
        sender_name: str = "Member"
    ) -> bool:
        """Ghim tin nhắn trong nhóm."""
        return self.group_message.pin_message(
            group_id=group_id,
            title=title,
            cli_msg_id=cli_msg_id,
            global_msg_id=global_msg_id,
            sender_name=sender_name
        )

    def unpin_message(
        self,
        group_id: int,
        global_msg_id: int = 0,
        cli_msg_id: int = 0
    ) -> bool:
        """Bỏ ghim tin nhắn trong nhóm."""
        return self.group_message.unpin_message(
            group_id=group_id,
            global_msg_id=global_msg_id,
            cli_msg_id=cli_msg_id
        )

    def remove_member(
        self,
        group_id: int,
        member_uids: Union[int, List[int]],
    ) -> bool:
        """Xoá khỏi nhóm KHÔNG block (CMD 228 SUB 0, du/b.r) — nút 'Xoá khỏi nhóm' toggle TẮT."""
        return self._socket.remove_member(group_id=int(group_id), member_uids=member_uids) if self._socket else False

    def kick_member(
        self,
        group_id: int,
        member_uids: Union[int, List[int]],
        is_block: bool = False
    ) -> bool:
        """Xóa thành viên khỏi nhóm."""
        return self.group_action.kick_member(group_id=group_id, member_uids=member_uids, is_block=is_block)

    def block_group_member(
        self,
        group_id: int,
        member_uids: Union[int, List[int]]
    ) -> bool:
        """Chặn thành viên khỏi nhóm."""
        return self.group_action.block_group_member(group_id=group_id, member_uids=member_uids)

    def block_user(
        self,
        target_uid: int,
        is_block: bool = True
    ) -> bool:
        """Chặn người dùng 1-1."""
        return self.send.block_user(target_uid=target_uid, is_block=is_block)

    def unblock_user(
        self,
        target_uid: int
    ) -> bool:
        """Bỏ chặn người dùng 1-1."""
        return self.send.unblock_user(target_uid=target_uid)

    def leave_group(
        self,
        group_id: int,
        new_owner_id: int = 0,
        silent: bool = False,
        block_readd: bool = False,
        wait_response: bool = False,
        timeout: float = 8.0,
    ):
        """Rời khỏi nhóm (CMD 239 SUB 1 / CMD 225 SUB 3)."""
        if wait_response and self._socket:
            return self._socket.leave_group(
                group_id=int(group_id),
                new_owner_id=new_owner_id,
                silent=silent,
                block_readd=block_readd,
                wait_response=True,
                timeout=timeout
            )
        return self.group_action.leave_group(
            group_id=group_id,
            new_owner_id=new_owner_id,
            silent=silent,
            block_readd=block_readd
        )

    def delete_message(
        self,
        group_id: int,
        cli_msg_id: Union[int, str],
        global_msg_id: Union[int, str] = "",
        owner_id: Optional[Union[int, str]] = None,
        is_group: bool = True,
        only_me: bool = False
    ) -> bool:
        """Xóa hoặc thu hồi tin nhắn."""
        return self.send.delete_message(
            group_id=group_id,
            cli_msg_id=cli_msg_id,
            global_msg_id=global_msg_id,
            owner_id=owner_id,
            is_group=is_group,
            only_me=only_me
        )

    def recall_message(
        self,
        group_id: int,
        cli_msg_id: Union[int, str],
        global_msg_id: Union[int, str] = 0,
        owner_id: Optional[Union[int, str]] = None,
        is_group: bool = True
    ) -> bool:
        """Thu hồi tin nhắn."""
        return self.send.recall_message(
            group_id=group_id,
            cli_msg_id=cli_msg_id,
            global_msg_id=global_msg_id,
            owner_id=owner_id,
            is_group=is_group
        )

    def disband_group(
        self,
        group_id: int
    ) -> bool:
        """Giải tán nhóm chat (CMD 242 SUB 0, pn/g0.h2)."""
        return self.group_action.disband_group(group_id=group_id)

    def add_member(
        self,
        group_id: int,
        member_uids: Union[int, List[int]],
        is_invite: bool = False
    ) -> bool:
        """Thêm hoặc mời thành viên vào nhóm."""
        return self.group_action.add_member(group_id=group_id, member_uids=member_uids, is_invite=is_invite)

    def join_group(
        self,
        target: Union[int, str],
        msg: str = ""
    ) -> Dict[str, Any]:
        """Tham gia nhóm chat qua ID hoặc Link."""
        return self.group_action.join_group(target=target, msg=msg)

    def preview_group_link(
        self,
        link_or_code: str
    ) -> Dict[str, Any]:
        """Xem trước thông tin nhóm / cộng đồng qua Link (tương ứng GroupLobbyView trong app Zalo)."""
        return self.group_info.preview_group_link(link_or_code=link_or_code)

    def create_poll(
        self,
        group_id: int,
        question: str,
        options: List[str]
    ) -> bool:
        """Tạo cuộc bình chọn trong nhóm."""
        return self.group_message.create_poll(group_id=group_id, question=question, options=options)

    def send_photo(
        self,
        target_id: Union[int, str],
        photo_url_or_path: str,
        thread_type: Union[ThreadType, int] = ThreadType.GROUP,
        caption: str = "",
        title: Optional[str] = None,
        description: Optional[str] = None,
        width: int = 0,
        height: int = 0,
        total_size: int = 0,
        thumb_url: Optional[str] = None,
        hd_url: Optional[str] = None,
        ttl: int = 0,
        quote_data: Optional[Dict[str, Any]] = None,
        native: bool = True,
        sub_type: int = 32,
        is_original: bool = False
    ) -> bool:
        """Gửi hình ảnh tới nhóm hoặc cá nhân 1-1."""
        return self.send.send_photo(
            target_id=target_id,
            photo_url_or_path=photo_url_or_path,
            thread_type=thread_type,
            caption=caption,
            title=title,
            description=description,
            width=width,
            height=height,
            total_size=total_size,
            thumb_url=thumb_url,
            hd_url=hd_url,
            ttl=ttl,
            quote_data=quote_data,
            native=native,
            sub_type=sub_type,
            is_original=is_original
        )

    def send_group_photo(
        self,
        group_id: Union[int, str],
        photo_url_or_path: str,
        caption: str = "",
        **kwargs
    ) -> bool:
        """Shortcut gửi hình ảnh tới nhóm chat."""
        return self.send.send_group_photo(group_id=group_id, photo_url_or_path=photo_url_or_path, caption=caption, **kwargs)

    def send_1to1_photo(
        self,
        to_uid: Union[int, str],
        photo_url_or_path: str,
        caption: str = "",
        **kwargs
    ) -> bool:
        """Shortcut gửi hình ảnh tới cá nhân 1-1."""
        return self.send.send_1to1_photo(to_uid=to_uid, photo_url_or_path=photo_url_or_path, caption=caption, **kwargs)

    send_image = send_photo
    send_group_image = send_group_photo
    send_1to1_image = send_1to1_photo

    def send_doodle(
        self,
        target_id: Union[int, str],
        doodle_url_or_path: str,
        thread_type: Union[ThreadType, int] = ThreadType.GROUP,
        caption: str = "",
        title: Optional[str] = None,
        description: Optional[str] = None,
        thumb_url: Optional[str] = None,
        hd_url: Optional[str] = None,
        width: int = 0,
        height: int = 0,
        total_size: int = 0,
        ttl: int = 0,
        quote_data: Optional[Dict[str, Any]] = None,
        native: bool = True,
        sub_type: int = 37,
        is_original: bool = False
    ) -> bool:
        """Gửi hình vẽ (doodle / SUB 37) tới nhóm hoặc cá nhân 1-1."""
        return self.send.send_doodle(
            target_id=target_id,
            doodle_url_or_path=doodle_url_or_path,
            thread_type=thread_type,
            caption=caption,
            title=title,
            description=description,
            thumb_url=thumb_url,
            hd_url=hd_url,
            width=width,
            height=height,
            total_size=total_size,
            ttl=ttl,
            quote_data=quote_data,
            native=native,
            sub_type=sub_type,
            is_original=is_original
        )

    def send_group_doodle(
        self,
        group_id: Union[int, str],
        doodle_url_or_path: str,
        caption: str = "",
        **kwargs
    ) -> bool:
        """Shortcut gửi hình vẽ (doodle) tới nhóm chat."""
        return self.send.send_group_doodle(group_id=group_id, doodle_url_or_path=doodle_url_or_path, caption=caption, **kwargs)

    def send_1to1_doodle(
        self,
        to_uid: Union[int, str],
        doodle_url_or_path: str,
        caption: str = "",
        **kwargs
    ) -> bool:
        """Shortcut gửi hình vẽ (doodle) tới cá nhân 1-1."""
        return self.send.send_1to1_doodle(to_uid=to_uid, doodle_url_or_path=doodle_url_or_path, caption=caption, **kwargs)

    def send_video(
        self,
        target_id: Union[int, str],
        video_url_or_path: str,
        thread_type: Union[ThreadType, int] = ThreadType.GROUP,
        caption: str = "",
        title: Optional[str] = None,
        description: Optional[str] = None,
        thumb_url: Optional[str] = None,
        width: int = 0,
        height: int = 0,
        duration_ms: int = 0,
        total_size: int = 0,
        ttl: int = 0,
        quote_data: Optional[Dict[str, Any]] = None,
        native: bool = True,
        sub_type: int = 44
    ) -> bool:
        """Gửi video tới nhóm hoặc cá nhân 1-1."""
        return self.send.send_video(
            target_id=target_id,
            video_url_or_path=video_url_or_path,
            thread_type=thread_type,
            caption=caption,
            title=title,
            description=description,
            thumb_url=thumb_url,
            width=width,
            height=height,
            duration_ms=duration_ms,
            total_size=total_size,
            ttl=ttl,
            quote_data=quote_data,
            native=native,
            sub_type=sub_type
        )

    def send_group_video(
        self,
        group_id: Union[int, str],
        video_url_or_path: str,
        caption: str = "",
        **kwargs
    ) -> bool:
        """Shortcut gửi video tới nhóm chat."""
        return self.send.send_group_video(group_id=group_id, video_url_or_path=video_url_or_path, caption=caption, **kwargs)

    def send_1to1_video(
        self,
        to_uid: Union[int, str],
        video_url_or_path: str,
        caption: str = "",
        **kwargs
    ) -> bool:
        """Shortcut gửi video tới cá nhân 1-1."""
        return self.send.send_1to1_video(to_uid=to_uid, video_url_or_path=video_url_or_path, caption=caption, **kwargs)

    def close(self):
        """Đóng kết nối."""
        if self._socket:
            self._socket.close()

    def disconnect(self):
        """Đóng kết nối (alias cho close)."""
        self.close()


ZaloAPI = ZaloClient
