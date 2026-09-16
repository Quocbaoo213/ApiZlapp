#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/socket/client.py — Module Tầng Mạng Socket TCP Binary Client cho Zalo Protocol.
Hỗ trợ đầy đủ:
- HTTP Handshake & PROV Frame 0 (X25519 ECDH + AES-256-GCM)
- Server Pool Selection & Fallback
- Init Sequence Frames
- Monotonic Counter & Sequence Management
- Ping Keepalive & Supervisor Auto-Reconnect
- High-level API Sending: Group/1-1 Msg, Typing, Reactions, Pin/Unpin Topic, Disband Group (CMD 1705)
"""

import base64
import json
import logging
import os
import select
import socket
import struct
import sys
import threading
import time
from typing import Callable, Optional, Dict, Any, List, Tuple

try:
    from .crypto import (
        encrypt_aes_gcm, decrypt_aes_gcm,
        decrypt_e2ee_cbc, DEFAULT_XK
    )
    from .protocol import (
        INNER_HEADER_FORMAT, InnerPacketHeader, OuterFrame,
        compute_checksum, xor_encode_d3, xor_decode_d3, dekey,
        build_ping_packet, build_typing_packet,
        build_group_message_packet, build_1to1_message_packet,
        build_reaction_packet, build_pin_topic_packet,
        build_unpin_topic_packet, build_fetch_pinned_topics_packet, build_cmd_1705_packet,
        build_disband_group_packet, build_disband_test_frame,
        build_kick_member_packet, build_block_group_member_packet,
        build_block_user_packet, build_unblock_user_packet, build_leave_group_packet,
        build_leave_group_225_packet, build_leave_group_239_packet,
        build_create_poll_packet, build_delete_message_packet, build_recall_message_packet,
        build_add_member_packet, build_join_group_packet,
        build_join_group_invite_packet, build_request_join_group_packet,
        build_group_link_info_packet,
        build_outer_frame, parse_incoming_frame,
        parse_group_sync_1867, parse_delivery_receipt_202,
        FRAME_TYPE_HANDSHAKE, FRAME_TYPE_DATA, FRAME_TYPE_CONTROL,
        CMD_PING, SUB_PING, CMD_GROUP_MSG, SUB_GROUP_MSG, CMD_1TO1_MSG, SUB_1TO1_MSG,
        CMD_GROUP_TYPING, SUB_GROUP_TYPING, CMD_1TO1_TYPING, SUB_1TO1_TYPING,
        CMD_KICK_MEMBER, SUB_KICK_MEMBER, CMD_BLOCK_GROUP_MEMBER, SUB_BLOCK_GROUP_MEMBER,
        CMD_BLOCK_USER, SUB_BLOCK_USER, CMD_BLOCK_USER_1TO1, CMD_UNBLOCK_USER_1TO1,
        CMD_LEAVE_GROUP, SUB_LEAVE_GROUP,
        CMD_LEAVE_GROUP_225, SUB_LEAVE_GROUP_225, CMD_LEAVE_GROUP_239, SUB_LEAVE_GROUP_239,
        CMD_JOIN_GROUP, SUB_JOIN_GROUP, CMD_JOIN_GROUP_INVITE, SUB_JOIN_GROUP_INVITE,
        CMD_REQUEST_JOIN_GROUP, SUB_REQUEST_JOIN_GROUP,
        CMD_GROUP_LINK_INFO, SUB_GROUP_LINK_INFO,
        CMD_PIN_TOPIC, SUB_PIN_TOPIC, CMD_UNPIN_TOPIC, SUB_UNPIN_TOPIC,
        CMD_CREATE_POLL, SUB_CREATE_POLL, CMD_DELETE_MSG, SUB_DELETE_MSG,
        CMD_RECALL_MSG_GROUP, SUB_RECALL_MSG_GROUP, CMD_RECALL_MSG_1TO1, SUB_RECALL_MSG_1TO1,
        CMD_ADD_MEMBER, SUB_ADD_MEMBER
    )
    from .handshake import (
        build_prov_frame, send_init_frames
    )
except (ImportError, ValueError):
    from crypto import (
        encrypt_aes_gcm, decrypt_aes_gcm,
        decrypt_e2ee_cbc, DEFAULT_XK
    )
    from protocol import (
        INNER_HEADER_FORMAT, InnerPacketHeader, OuterFrame,
        compute_checksum, xor_encode_d3, xor_decode_d3, dekey,
        build_ping_packet, build_typing_packet,
        build_group_message_packet, build_1to1_message_packet,
        build_reaction_packet, build_pin_topic_packet,
        build_unpin_topic_packet, build_fetch_pinned_topics_packet, build_cmd_1705_packet,
        build_disband_group_packet, build_disband_test_frame,
        build_kick_member_packet, build_block_group_member_packet,
        build_block_user_packet, build_unblock_user_packet, build_leave_group_packet,
        build_leave_group_225_packet, build_leave_group_239_packet,
        build_create_poll_packet, build_delete_message_packet, build_recall_message_packet,
        build_add_member_packet, build_join_group_packet,
        build_join_group_invite_packet, build_request_join_group_packet,
        build_group_link_info_packet,
        build_outer_frame, parse_incoming_frame,
        parse_group_sync_1867, parse_delivery_receipt_202,
        FRAME_TYPE_HANDSHAKE, FRAME_TYPE_DATA, FRAME_TYPE_CONTROL,
        CMD_PING, SUB_PING, CMD_GROUP_MSG, SUB_GROUP_MSG, CMD_1TO1_MSG, SUB_1TO1_MSG,
        CMD_GROUP_TYPING, SUB_GROUP_TYPING, CMD_1TO1_TYPING, SUB_1TO1_TYPING,
        CMD_KICK_MEMBER, SUB_KICK_MEMBER, CMD_BLOCK_GROUP_MEMBER, SUB_BLOCK_GROUP_MEMBER,
        CMD_BLOCK_USER, SUB_BLOCK_USER, CMD_BLOCK_USER_1TO1, CMD_UNBLOCK_USER_1TO1,
        CMD_LEAVE_GROUP, SUB_LEAVE_GROUP,
        CMD_LEAVE_GROUP_225, SUB_LEAVE_GROUP_225, CMD_LEAVE_GROUP_239, SUB_LEAVE_GROUP_239,
        CMD_JOIN_GROUP, SUB_JOIN_GROUP, CMD_JOIN_GROUP_INVITE, SUB_JOIN_GROUP_INVITE,
        CMD_REQUEST_JOIN_GROUP, SUB_REQUEST_JOIN_GROUP,
        CMD_GROUP_LINK_INFO, SUB_GROUP_LINK_INFO,
        CMD_PIN_TOPIC, SUB_PIN_TOPIC, CMD_UNPIN_TOPIC, SUB_UNPIN_TOPIC,
        CMD_CREATE_POLL, SUB_CREATE_POLL, CMD_DELETE_MSG, SUB_DELETE_MSG,
        CMD_RECALL_MSG_GROUP, SUB_RECALL_MSG_GROUP, CMD_RECALL_MSG_1TO1, SUB_RECALL_MSG_1TO1,
        CMD_ADD_MEMBER, SUB_ADD_MEMBER
    )
    try:
        from core.socket.handshake import (
            build_prov_frame, send_init_frames
        )
    except (ImportError, ValueError):
        from handshake import (
            build_prov_frame, send_init_frames
        )


logger = logging.getLogger("core.socket.client")

DEFAULT_SERVERS = [
    {"host": "49.213.95.83", "port": 443},
    {"host": "49.213.95.87", "port": 443},
    {"host": "49.213.95.90", "port": 443},
    {"host": "49.213.95.92", "port": 443},
    {"host": "49.213.95.96", "port": 443},
    {"host": "49.213.95.74", "port": 443},
    {"host": "49.213.95.77", "port": 443},
    {"host": "49.213.95.86", "port": 443}
]


class ZaloSocketClient:
    def __init__(
        self,
        uid: int,
        dk: bytes,
        cryptkey: Optional[bytes] = None,
        session_key: Optional[str] = None,
        ksid: Optional[str] = None,
        server_pubkey_b64: Optional[str] = None,
        frame0_path: Optional[str] = None,
        init_sequence_path: Optional[str] = None,
        server_pool: Optional[List[Dict[str, Any]]] = None,
        state_file: Optional[str] = None,
        on_message_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        ping_interval: float = 10.0,
        debug: bool = False
    ):
        self.uid = int(uid)
        self.dk = dk
        self.cryptkey = cryptkey or bytes(16)
        self.session_key = session_key
        self.ksid = ksid
        self.server_pubkey_b64 = server_pubkey_b64
        self.frame0_path = frame0_path
        self.init_sequence_path = init_sequence_path
        self.server_pool = server_pool or DEFAULT_SERVERS
        self.state_file = state_file
        self.on_message_callback = on_message_callback
        self.ping_interval = ping_interval
        self.debug = debug

        self.sock: Optional[socket.socket] = None
        self.is_connected = False
        self.is_running = False
        self.handshake_ok = False
        self.last_traffic = time.time()
        self.current_host = None
        self.current_port = None
        self.current_pubkey = None

        self._last_save = 0.0
        self._save_interval = 5.0

        self.send_lock = threading.Lock()
        self.recv_thread: Optional[threading.Thread] = None
        self.ping_thread: Optional[threading.Thread] = None
        self.supervisor_thread: Optional[threading.Thread] = None

        self.seq_lock = threading.Lock()
        self.current_seq = -40
        self._load_or_init_state()

        self.ack_lock = threading.Lock()
        self.general_ack_event = threading.Event()
        self.last_ack_result: Dict[str, Any] = {}
        self.cmd_ack_events: Dict[int, threading.Event] = {}
        self.cmd_ack_results: Dict[int, Dict[str, Any]] = {}

    def _prepare_cmd_ack(self, cmd: int):
        with self.ack_lock:
            if cmd not in self.cmd_ack_events:
                self.cmd_ack_events[cmd] = threading.Event()
            else:
                self.cmd_ack_events[cmd].clear()
            self.cmd_ack_results.pop(cmd, None)
            self.general_ack_event.clear()

    def _wait_cmd_ack(self, cmd: int, timeout: float = 5.0) -> Tuple[bool, Dict[str, Any]]:
        with self.ack_lock:
            if cmd not in self.cmd_ack_events:
                self.cmd_ack_events[cmd] = threading.Event()
            evt = self.cmd_ack_events[cmd]
        got = evt.wait(timeout=timeout)
        with self.ack_lock:
            res = dict(self.cmd_ack_results.get(cmd, {})) if got else {}
        return got, res

    def _try_load_frame0(self) -> Optional[bytes]:
        search_paths = []
        if self.frame0_path:
            search_paths.append(self.frame0_path)
        search_paths.extend([
            os.path.join(os.getcwd(), "frame0.bin"),
            "frame0.bin",
            os.path.expanduser("~/.zalo/frame0.bin"),
            "/root/zalo/frame0.bin",
        ])
        for p in search_paths:
            if p and os.path.isfile(p):
                try:
                    with open(p, 'rb') as f:
                        data = f.read()
                    if len(data) >= 28:
                        return data
                except Exception:
                    pass
        return None

    def _resolve_state_file(self) -> Optional[str]:
        if self.state_file:
            return self.state_file
        candidates = [
            os.path.join(os.getcwd(), ".session_state.json"),
            os.path.expanduser("~/.zalo/.session_state.json"),
            "/root/zalo/.session_state.json"
        ]
        for c in candidates:
            if os.path.isfile(c):
                return c
        # Default save target
        return os.path.join(os.getcwd(), ".session_state.json")

    def _load_or_init_state(self):
        self.cmsg_id = int(time.time() * 1000) & 0x7FFFFFFF
        self.ck_val = (int(time.time() * 1000) ^ 0x6CE7DAA0) & 0xFFFFFFFF
        sf = self._resolve_state_file()
        if sf and os.path.isfile(sf):
            try:
                with open(sf, 'r', encoding='utf-8') as f:
                    s = json.load(f)
                    self.cmsg_id = max(self.cmsg_id, s.get('cmsg_id', 0) + 10)
                    self.ck_val = max(self.ck_val, s.get('ck_val', 0) + 10)
            except Exception:
                pass

    def _save_state(self, force: bool = False):
        now = time.time()
        if force or (now - self._last_save >= self._save_interval):
            self._last_save = now
            sf = self._resolve_state_file()
            if sf:
                try:
                    pdir = os.path.dirname(os.path.abspath(sf))
                    if pdir:
                        os.makedirs(pdir, exist_ok=True)
                    with open(sf, 'w', encoding='utf-8') as f:
                        json.dump({'cmsg_id': self.cmsg_id, 'ck_val': self.ck_val}, f)
                except Exception:
                    pass

    def _save_state_if_needed(self):
        self._save_state(force=False)

    def _next_seq(self) -> int:
        with self.seq_lock:
            self.current_seq -= 1
            return self.current_seq

    def _next_cmsg_id(self) -> int:
        with self.seq_lock:
            self.cmsg_id += 1
            return self.cmsg_id

    def _next_ck_val(self) -> int:
        with self.seq_lock:
            self.ck_val = (self.ck_val + 1) & 0xFFFFFFFF
            return self.ck_val

    def _get_next_counters(self) -> Tuple[int, int, int]:
        with self.seq_lock:
            self.current_seq -= 1
            seq = self.current_seq
            self.cmsg_id += 1
            cmsg = self.cmsg_id
            self.ck_val = (self.ck_val + 1) & 0xFFFFFFFF
            ck = self.ck_val
            self._save_state_if_needed()
            return seq, cmsg, ck

    def _select_socket_server(self) -> Tuple[str, int, Optional[str]]:
        import random
        # Ưu tiên IPv4 port 443
        v4_servers = [s for s in self.server_pool if ':' not in s.get('host', '') and s.get('port') == 443]
        if v4_servers:
            srv = random.choice(v4_servers)
        else:
            srv = random.choice(self.server_pool)
        return srv['host'], srv['port'], srv.get('pubKey')

    def connect(self) -> bool:
        if self.is_connected:
            return True

        self.current_host, self.current_port, srv_pk = self._select_socket_server()
        self.current_pubkey = srv_pk or self.server_pubkey_b64

        logger.info(f"[*] Đang kết nối tới Zalo Gateway: {self.current_host}:{self.current_port}...")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10.0)
            self.sock.connect((self.current_host, self.current_port))

            # 1. Gửi HTTP Handshake
            http_req = f"GET / HTTP/1.1\r\nHost: {self.current_host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode('utf-8')
            self.sock.sendall(http_req)

            # 2. Gửi Frame 0 Handshake (Type 8)
            if self.session_key and self.ksid and self.current_pubkey:
                logger.info("[*] Tự động sinh PROV Frame 0 (X25519 ECDH)...")
                prov_frame_bytes = build_prov_frame(
                    session_key=self.session_key,
                    dk=self.dk,
                    ksid=self.ksid,
                    server_pubkey_b64=self.current_pubkey,
                    uid=self.uid
                )
                self.sock.sendall(prov_frame_bytes)
            elif self.f0_bytes:
                logger.info("[*] Sử dụng ticket frame0.bin nạp sẵn...")
                raw_f0 = struct.pack('<IB', len(self.f0_bytes) + 5, FRAME_TYPE_HANDSHAKE) + self.f0_bytes
                self.sock.sendall(raw_f0)
            else:
                raise ValueError("Thiếu thông tin xác thực để sinh hoặc nạp Frame 0 Handshake!")

            # 3. Drain buffer
            time.sleep(0.15)
            self.sock.setblocking(False)
            try:
                while True:
                    d = self.sock.recv(4096)
                    if not d: break
            except BlockingIOError:
                pass
            self.sock.setblocking(True)
            self.sock.settimeout(None)

            # 4. Gửi chuỗi Init Frames
            logger.info("[*] Đang gửi chuỗi khung khởi tạo Active Session...")
            send_init_frames(self.sock, self.dk, self.uid, send_lock=self.send_lock)

            self.is_connected = True
            self.is_running = True
            self.handshake_ok = True
            self.last_traffic = time.time()
            logger.info(f"[✔] Kết nối và kích hoạt phiên Socket thành công với UID {self.uid}!")

            # 5. Khởi chạy luồng Receive & Ping Keepalive
            self.recv_thread = threading.Thread(target=self._recv_loop, name="ZaloSocketRecv", daemon=True)
            self.recv_thread.start()

            self.ping_thread = threading.Thread(target=self._ping_loop, name="ZaloSocketPing", daemon=True)
            self.ping_thread.start()

            if not self.supervisor_thread or not self.supervisor_thread.is_alive():
                self.supervisor_thread = threading.Thread(target=self._supervisor_loop, name="ZaloSupervisor", daemon=True)
                self.supervisor_thread.start()

            return True

        except Exception as e:
            logger.error(f"[!] Lỗi kết nối Socket Gateway: {e}")
            self.close()
            return False

    def close(self):
        self.is_connected = False
        self.is_running = False
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        logger.info("[*] Đã đóng kết nối Socket.")

    def _recv_loop(self):
        buf = bytearray()
        while self.is_running and self.sock:
            try:
                r, _, _ = select.select([self.sock], [], [], 1.0)
                if not r:
                    continue

                chunk = self.sock.recv(8192)
                if not chunk:
                    logger.warning("[!] Server đã đóng kết nối.")
                    break

                self.last_traffic = time.time()
                buf.extend(chunk)

                while len(buf) >= 5:
                    res = OuterFrame.unpack_from_buffer(bytes(buf))
                    if not res:
                        break
                    frame, consumed = res
                    buf = buf[consumed:]

                    try:
                        parsed = parse_incoming_frame(
                            frame,
                            dk=self.dk,
                            cryptkey=self.cryptkey,
                            my_uid=self.uid
                        )
                        cmd = parsed.get('cmd')
                        sub = parsed.get('sub')

                        # Bắt phản hồi ACK cho CMD điều khiển
                        # raw_params đã là plaintext (sau AES-GCM decrypt), KHÔNG cần XOR thêm
                        if cmd in (1705, 1703, 1708, 1752, 113, 207, 202, 228, 234, 235, 239, 242, 246, 250, 225, 241, 244, 901, 906, 2000, 1640, 382, 383):
                            raw_params = parsed.get('raw_params', b'')
                            # raw_params là plaintext, đọc status trực tiếp
                            status = struct.unpack('<i', raw_params[:4])[0] if len(raw_params) >= 4 else 0
                            ack_dict = {
                                'cmd': cmd,
                                'sub': sub,
                                'status_code': status,
                                'raw_hex': raw_params[:8].hex() if raw_params else '',
                                'raw_params': raw_params,
                                'params_len': len(raw_params),
                            }

                            # Xử lý phản hồi preview link nhóm (CMD 901 SUB 3)
                            if cmd == 901:
                                try:
                                    if b'{' in raw_params:
                                        j_idx = raw_params.find(b'{')
                                        j_obj = json.loads(raw_params[j_idx:].decode('utf-8', errors='ignore'))
                                        j_data = j_obj.get('data') or j_obj
                                        j_gid = j_data.get('groupId') or j_data.get('grid') or j_data.get('id') or j_data.get('group_id')
                                        if j_gid:
                                            ack_dict['group_id'] = int(j_gid)
                                    elif len(raw_params) >= 8:
                                        bin_gid = struct.unpack_from('<I', raw_params, 4)[0]
                                        if bin_gid > 0:
                                            ack_dict['group_id'] = int(bin_gid)
                                except Exception:
                                    pass

                            # Xử lý phản hồi phân giải link nhóm (CMD 244 SUB 4)
                            if cmd == 244:
                                try:
                                    if len(raw_params) >= 8 and status == 0:
                                        bin_gid = struct.unpack_from('<I', raw_params, 4)[0]
                                        if bin_gid > 0:
                                            ack_dict['group_id'] = int(bin_gid)
                                    if not ack_dict.get('group_id') and b'{' in raw_params:
                                        j_idx = raw_params.find(b'{')
                                        j_obj = json.loads(raw_params[j_idx:].decode('utf-8', errors='ignore'))
                                        j_data = j_obj.get('data') or j_obj
                                        j_gid = j_data.get('groupId') or j_data.get('grid') or j_data.get('id')
                                        if j_gid:
                                            ack_dict['group_id'] = int(j_gid)
                                    if ack_dict.get('group_id'):
                                        if not hasattr(self, 'known_groups'):
                                             self.known_groups = {}
                                        self.known_groups[str(ack_dict['group_id'])] = {'group_id': ack_dict['group_id'], 'ts': time.time()}
                                except Exception:
                                    pass

                            # Xử lý phản hồi danh sách tin nhắn đã ghim (CMD 1703 SUB 0)
                            if cmd == 1703:
                                try:
                                    topics_list = []
                                    if b'{' in raw_params:
                                        j_idx = raw_params.find(b'{')
                                        j_obj = json.loads(raw_params[j_idx:].decode('utf-8', errors='ignore'))
                                        j_data = j_obj.get('data') or j_obj
                                        topics_list = j_data.get('topics') or j_obj.get('topics') or []
                                        if not topics_list and isinstance(j_data, list):
                                            topics_list = j_data
                                    ack_dict['topics'] = topics_list
                                except Exception:
                                    pass

                            with self.ack_lock:
                                self.cmd_ack_results[cmd] = ack_dict
                                self.last_ack_result = ack_dict
                                if cmd in self.cmd_ack_events:
                                    self.cmd_ack_events[cmd].set()
                                self.general_ack_event.set()

                        # Bắt group_id từ CMD 201 push (server gửi sau join/message, raw_params[:4] = group_id uint32 LE)
                        if cmd == 201:
                            raw_params = parsed.get('raw_params', b'')
                            if len(raw_params) >= 4:
                                try:
                                    pushed_gid = struct.unpack_from('<I', raw_params, 0)[0]
                                    if pushed_gid > 0:
                                        if not hasattr(self, 'known_groups'):
                                            self.known_groups = {}
                                        if str(pushed_gid) not in self.known_groups:
                                            self.known_groups[str(pushed_gid)] = {'group_id': pushed_gid, 'ts': time.time()}
                                            logger.debug(f"[CMD201] Discovered group_id={pushed_gid} from server push")
                                except Exception:
                                    pass

                        if self.on_message_callback:
                            try:
                                self.on_message_callback(parsed)
                            except Exception as cb_err:
                                logger.error(f"[!] Lỗi trong on_message_callback: {cb_err}")
                    except Exception as frame_err:
                        logger.error(f"[!] Lỗi xử lý khung tin socket: {frame_err}")

            except Exception as e:
                if self.is_running:
                    logger.warning(f"[!] Ngoại lệ trong recv_loop: {e}")
                break

        self.is_connected = False

    def _ping_loop(self):
        while self.is_running and self.is_connected:
            time.sleep(self.ping_interval)
            if not self.is_running or not self.is_connected:
                break
            try:
                seq, cmsg, _ = self._get_next_counters()
                ck = compute_checksum(CMD_PING, SUB_PING, seq, self.uid, bb=0, ty=1, ver=3)
                ping_packet = build_ping_packet(self.uid, seq, ck)
                outer = build_outer_frame(ping_packet, self.dk)
                with self.send_lock:
                    if self.sock:
                        self.sock.sendall(outer)
                self.last_traffic = time.time()
                if self.debug:
                    logger.debug(f"[Ping] Sent Keepalive Ping CMD 1971 (Seq={seq}, ck={hex(ck)})")
            except Exception as e:
                logger.warning(f"[!] Gửi ping keepalive thất bại: {e}")
                self.is_connected = False
                break

    def _disconnect_socket(self):
        with self.send_lock:
            if self.sock:
                try:
                    self.sock.shutdown(socket.SHUT_RDWR)
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None
            self.is_connected = False
            self.handshake_ok = False

    def _supervisor_loop(self):
        while self.is_running:
            time.sleep(2.0)
            if not self.is_running:
                break
            now = time.time()
            if not self.is_connected or (now - self.last_traffic > 35.0):
                logger.warning(f"[Supervisor] Phát hiện kết nối bị gián đoạn (idle {now - self.last_traffic:.1f}s). Đang tự động kết nối lại...")
                self._disconnect_socket()
                time.sleep(1.0)
                try:
                    self.connect()
                except Exception as ex:
                    logger.error(f"[Supervisor] Lỗi khi kết nối lại: {ex}")

    def send_group_message(
        self,
        group_id: int,
        text: str,
        ttl_ms: int = 0,
        ttl: Optional[int] = None,
        quote_data: Optional[dict] = None,
        mentions: Optional[list] = None,
        style_id: Optional[int] = None,
        size: Optional[int] = None,
        color: Optional[str] = None,
        bold: bool = False,
        italic: bool = False,
        underline: bool = False,
        strike: bool = False,
        fontsize: Optional[int] = None,
        list_type: Optional[int] = None,
        rtf_mode: str = 'fwd'
    ) -> bool:
        if ttl is not None and ttl_ms == 0:
            ttl_ms = ttl * 1000 if ttl < 100000 else ttl
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(CMD_GROUP_MSG, SUB_GROUP_MSG, seq, self.uid, target=int(group_id), target_type=4, cmsg=cmsg, bb=1, ty=2, ver=3)
            inner = build_group_message_packet(
                uid=self.uid,
                group_id=int(group_id),
                text=text,
                seq=seq,
                ck_val=ck,
                cmsg_id=cmsg,
                ttl_ms=ttl_ms,
                quote_data=quote_data,
                mentions=mentions,
                style_id=style_id,
                size=size,
                color=color,
                bold=bold,
                italic=italic,
                underline=underline,
                strike=strike,
                fontsize=fontsize,
                list_type=list_type,
                rtf_mode=rtf_mode
            )
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi gửi group message: {e}")
            return False

    def send_1to1_message(
        self,
        target_uid: int,
        text: str,
        ttl_ms: int = 0,
        ttl: Optional[int] = None,
        quote_data: Optional[dict] = None,
        style_id: Optional[int] = None,
        size: Optional[int] = None,
        color: Optional[str] = None,
        bold: bool = False,
        italic: bool = False,
        underline: bool = False,
        strike: bool = False,
        fontsize: Optional[int] = None,
        list_type: Optional[int] = None,
        rtf_mode: str = 'fwd'
    ) -> bool:
        if ttl is not None and ttl_ms == 0:
            ttl_ms = ttl * 1000 if ttl < 100000 else ttl
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(CMD_1TO1_MSG, SUB_1TO1_MSG, seq, self.uid, target=int(target_uid), target_type=3, cmsg=cmsg, bb=1, ty=2, ver=3)
            inner = build_1to1_message_packet(
                uid=self.uid,
                target_uid=int(target_uid),
                text=text,
                cryptkey=self.cryptkey,
                seq=seq,
                ck_val=ck,
                cmsg_id=cmsg,
                ttl_ms=ttl_ms,
                quote_data=quote_data,
                style_id=style_id,
                size=size,
                color=color,
                bold=bold,
                italic=italic,
                underline=underline,
                strike=strike,
                fontsize=fontsize,
                list_type=list_type,
                rtf_mode=rtf_mode
            )
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi gửi 1-1 message: {e}")
            return False

    def send_typing(self, target_id: int, is_group: bool = True) -> bool:
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            cmd = CMD_GROUP_TYPING if is_group else CMD_1TO1_TYPING
            tt = 3  # Target type cho typing CMD 206 / CMD 106 luôn luôn là 3
            ck = compute_checksum(cmd, SUB_GROUP_TYPING, seq, self.uid, target=int(target_id), target_type=tt, cmsg=cmsg, bb=1, ty=2, ver=3)
            inner = build_typing_packet(self.uid, int(target_id), is_group, seq, ck, cmsg)
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi gửi typing: {e}")
            return False

    def set_conversation_ttl(
        self,
        target_id: int,
        ttl_seconds: int,
        is_group: bool = True
    ) -> bool:
        """Kích hoạt hoặc thay đổi chế độ Tin nhắn tự xóa (TTL) cho hội thoại (CMD 2060 SUB 0)."""
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(2060, 0, seq, self.uid, target=0, target_type=0, cmsg=0, bb=1, ty=0, ver=3)
            target_type_byte = 0x02 if is_group else 0x01
            params = (
                bytes([0x01]) +
                struct.pack('<I', 0) +
                struct.pack('<H', 0) +
                struct.pack('<I', 1) +
                bytes([target_type_byte]) +
                struct.pack('<I', int(target_id)) +
                struct.pack('<Q', int(ttl_seconds))
            )
            inner = struct.pack('<IBBiIBHB', ck, 1, 0, seq, self.uid, 3, 2060, 0) + params
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi cài đặt TTL: {e}")
            return False

    def send_reaction(
        self,
        target_id: int,
        cli_msg_id: int,
        global_msg_id: int = 0,
        icon: str = "❤️",
        is_group: bool = True
    ) -> bool:
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            cmd = 1785 if is_group else 1780
            target_type = 4 if is_group else 3
            ck = compute_checksum(cmd, 0, seq, self.uid, target=int(target_id), target_type=target_type, cmsg=cmsg, bb=1, ty=2, ver=3)
            inner = build_reaction_packet(
                uid=self.uid,
                target_id=int(target_id),
                cli_msg_id=int(cli_msg_id),
                global_msg_id=int(global_msg_id or 0),
                icon=icon,
                is_group=is_group,
                seq=seq,
                ck_val=ck,
                cmsg_id=cmsg
            )
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi gửi reaction: {e}")
            return False

    def pin_message(
        self,
        group_id: int,
        title: str = "",
        cli_msg_id: int = 0,
        global_msg_id: int = 0,
        sender_name: str = "Member"
    ) -> bool:
        """Ghim tin nhắn / Tạo Topic ghim trong nhóm qua Socket (CMD 1752 SUB 2)."""
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            inner = build_pin_topic_packet(
                uid=self.uid,
                group_id=int(group_id),
                title=title,
                cli_msg_id=int(cli_msg_id or 0),
                global_msg_id=int(global_msg_id or 0),
                sender_name=sender_name,
                seq=seq,
                ck_val=0
            )
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f"[✔] Đã gửi yêu cầu ghim tin nhắn (GID={group_id}, MsgID={global_msg_id or cli_msg_id}) qua Socket (CMD 1752 SUB 2)")
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi ghim tin nhắn: {e}")
            return False

    def unpin_message(
        self,
        group_id: int | str,
        topic_id: int = 0,
        global_msg_id: int = 0,
        cli_msg_id: int = 0
    ) -> bool:
        """Bỏ ghim tin nhắn / Topic khỏi nhóm qua Socket (CMD 1708 SUB 0)."""
        if not self.is_connected or not self.sock:
            return False
        try:
            gid = int(group_id)
            seq, cmsg, _ = self._get_next_counters()
            tid = int(topic_id or global_msg_id or 0)
            inner = build_unpin_topic_packet(
                uid=self.uid,
                group_id=gid,
                topic_id=tid,
                global_msg_id=tid,
                cli_msg_id=int(cli_msg_id or 0),
                seq=seq,
                ck_val=0
            )
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f"[✔] Đã gửi yêu cầu bỏ ghim tin nhắn (GID={gid}, TopicID={tid}) qua Socket (CMD 1708 SUB 0)")
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi bỏ ghim tin nhắn: {e}")
            return False

    def fetch_pinned_topics(
        self,
        group_id: int | str,
        wait_response: bool = True,
        timeout: float = 3.0
    ) -> Union[bool, Dict[str, Any]]:
        """Lấy danh sách các tin nhắn / topic đã ghim trong nhóm (CMD 1703 SUB 0)."""
        if not self.is_connected or not self.sock:
            return {'sent': False, 'error': 'Not connected'} if wait_response else False
        try:
            gid = int(group_id)
            seq, cmsg, _ = self._get_next_counters()
            inner = build_fetch_pinned_topics_packet(
                uid=self.uid,
                group_id=gid,
                seq=seq,
                ck_val=0
            )
            outer = build_outer_frame(inner, self.dk)
            with self.ack_lock:
                self.general_ack_event.clear()

            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f"[✔] Đã gửi yêu cầu lấy danh sách bài ghim Group {gid} qua Socket (CMD 1703 SUB 0)")

            if wait_response:
                got_ack = self.general_ack_event.wait(timeout=timeout)
                with self.ack_lock:
                    ack_res = dict(self.last_ack_result) if got_ack else {}
                topics = ack_res.get('topics', [])
                return {'sent': True, 'got_response': got_ack, 'ack_result': ack_res, 'topics': topics}
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi lấy danh sách bài ghim: {e}")
            return {'sent': False, 'error': str(e)} if wait_response else False

    def send_group_event_1705(
        self,
        group_id: int,
        owner_uid: int = 0,
        wait_ack: bool = False,
        timeout: float = 5.0
    ) -> Dict[str, Any]:
        """Gửi lệnh CMD 1705 (Giải tán / Rời nhóm & Chuyển quyền) qua socket."""
        if not self.is_connected or not self.sock:
            return {'sent': False, 'error': 'Socket not connected'}
        try:
            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(1705, 0, seq, self.uid, bb=0, ty=1, ver=3)
            inner = build_cmd_1705_packet(
                uid=self.uid,
                group_id=int(group_id),
                field_8byte=int(owner_uid or 0),
                seq=seq,
                ck_val=ck
            )
            outer = build_outer_frame(inner, self.dk)
            with self.ack_lock:
                self.general_ack_event.clear()
                self.last_ack_result = {}

            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()

            result = {'sent': True, 'group_id': int(group_id), 'owner_uid': int(owner_uid or 0), 'seq': seq}
            if wait_ack:
                got_ack = self.general_ack_event.wait(timeout=timeout)
                with self.ack_lock:
                    result['got_response'] = got_ack
                    result['ack_result'] = dict(self.last_ack_result) if got_ack else None
            return result
        except Exception as e:
            logger.error(f"[!] Lỗi gửi CMD 1705: {e}")
            return {'sent': False, 'error': str(e)}

    def disband_group_242(
        self,
        group_id: int,
        wait_response: bool = False,
        timeout: float = 8.0,
    ) -> Union[bool, Dict[str, Any]]:
        """Giải tán nhóm thật (CMD 242 SUB 0, pn/g0.h2)."""
        if not self.is_connected or not self.sock:
            return {'sent': False, 'error': 'Not connected'} if wait_response else False
        try:
            from core.socket.protocol import build_disband_242_packet, CMD_DISBAND_GROUP
            seq, cmsg, _ = self._get_next_counters()
            inner = build_disband_242_packet(
                uid=self.uid,
                group_id=int(group_id),
                seq=seq,
                ck_val=0,
                vercode=getattr(self, 'vercode', 260802903),
            )
            outer = build_outer_frame(inner, self.dk)
            if wait_response:
                self._prepare_cmd_ack(CMD_DISBAND_GROUP)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f"[✔] Đã gửi lệnh giải tán Group {group_id} qua Socket (CMD 242 SUB 0, Seq={seq})")
            if wait_response:
                got_ack, ack_res = self._wait_cmd_ack(CMD_DISBAND_GROUP, timeout=timeout)
                status = ack_res.get('status_code', -1) if got_ack else -1
                return {
                    'sent': True,
                    'got_response': got_ack,
                    'success': got_ack and status == 0,
                    'status_code': status,
                    'ack_result': ack_res,
                }
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi giải tán nhóm: {e}")
            return {'sent': False, 'error': str(e)} if wait_response else False

    disband_group = disband_group_242
    disband = disband_group_242

    def remove_member(
        self,
        group_id: int,
        member_uids: int | str | List[int | str],
    ) -> bool:
        """Xoá khỏi nhóm KHÔNG block (CMD 228 SUB 0, du/b.r)."""
        if not self.is_connected or not self.sock:
            return False
        try:
            from core.socket.protocol import build_remove_member_packet, CMD_REMOVE_MEMBER
            if isinstance(member_uids, (int, str)):
                uids = [int(member_uids)]
            else:
                uids = [int(u) for u in member_uids]
            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(CMD_REMOVE_MEMBER, 0, seq, self.uid, bb=0, ty=1, ver=3)
            inner = build_remove_member_packet(uid=self.uid, group_id=int(group_id), member_uids=uids, seq=seq, ck_val=ck)
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f"[✔] Đã gửi lệnh xoá {uids} khỏi Group {group_id} (CMD 228)")
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi xoá member: {e}")
            return False

    def kick_member(
        self,
        group_id: int,
        member_uids: int | str | List[int | str],
        is_block: bool = False
    ) -> bool:
        """Kick / xóa / ban thành viên khỏi nhóm chat qua Socket (CMD 228 hoặc CMD 234)."""
        if not is_block:
            return self.remove_member(group_id=group_id, member_uids=member_uids)
        if not self.is_connected or not self.sock:
            return False
        try:
            if isinstance(member_uids, (int, str)):
                uids = [int(member_uids)]
            else:
                uids = [int(u) for u in member_uids]

            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(CMD_KICK_MEMBER, 0, seq, self.uid, bb=0, ty=1, ver=3)
            inner = build_kick_member_packet(
                uid=self.uid,
                group_id=int(group_id),
                member_uids=uids,
                is_block=is_block,
                seq=seq,
                ck_val=ck
            )
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f"[✔] Đã gửi lệnh ban (chặn vào lại) thành viên {uids} khỏi Group {group_id} qua Socket (CMD 234)")
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi kick/ban thành viên: {e}")
            return False

    def block_group_member(
        self,
        group_id: int,
        member_uids: int | str | List[int | str]
    ) -> bool:
        """Chặn / Ban thành viên khỏi nhóm chat qua Socket (CMD 234 SUB 0 với is_block=True)."""
        return self.kick_member(group_id=group_id, member_uids=member_uids, is_block=True)

    def block_user(
        self,
        target_uid: int | str,
        is_block: bool = True
    ) -> bool:
        """Chặn / Bỏ chặn người dùng 1-1 qua Socket (CMD 382 SUB 0 cho Block, CMD 383 SUB 0 cho Unblock)."""
        if not self.is_connected or not self.sock:
            return False
        try:
            t_uid = int(target_uid)
            seq, cmsg, _ = self._get_next_counters()
            cmd = CMD_BLOCK_USER_1TO1 if is_block else CMD_UNBLOCK_USER_1TO1
            ck = compute_checksum(cmd, 0, seq, self.uid, bb=0, ty=1, ver=3)
            inner = build_block_user_packet(
                uid=self.uid,
                target_uid=t_uid,
                is_block=is_block,
                seq=seq,
                ck_val=ck
            )
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f"[✔] Đã gửi lệnh {'chặn' if is_block else 'bỏ chặn'} User {t_uid} qua Socket (CMD {cmd} SUB 0)")
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi chặn user: {e}")
            return False

    def unblock_user(self, target_uid: int | str) -> bool:
        """Bỏ chặn người dùng 1-1 qua Socket (CMD 383 SUB 0)."""
        return self.block_user(target_uid, is_block=False)

    def leave_group(
        self,
        group_id: int | str,
        new_owner_id: int = 0,
        silent: bool = False,
        block_readd: bool = False,
        wait_response: bool = False,
        timeout: float = 5.0
    ) -> Union[bool, Dict[str, Any]]:
        """Rời / Thoát khỏi nhóm chat qua Socket (CMD 225 SUB 3 & CMD 239 SUB 1).
        
        Tham số:
          - group_id: ID nhóm chat
          - new_owner_id: UID chủ nhóm mới (nếu là creator muốn chuyển nhượng)
          - silent: Rời nhóm trong im lặng (True = chỉ admin biết)
          - block_readd: Chặn không cho thêm vào nhóm này lần nữa
          - wait_response: Chờ server trả lời ACK
          - timeout: Thời gian chờ tối đa (giây)
        """
        if not self.is_connected or not self.sock:
            return {'sent': False, 'error': 'Not connected'} if wait_response else False
        try:
            gid = int(group_id)
            seq_225, _, _ = self._get_next_counters()
            seq_239, _, _ = self._get_next_counters()

            # 1. Gói tin rời nhóm trực tiếp CMD 225 SUB 3 (Chuẩn PCAP Frame 438)
            inner_225 = build_leave_group_225_packet(
                uid=self.uid,
                group_id=gid,
                seq=seq_225,
                ck_val=0,
                vercode=getattr(self, 'vercode', 260802903)
            )
            outer_225 = build_outer_frame(inner_225, self.dk)

            # 2. Gói tin rời nhóm phụ trợ CMD 239 SUB 1 (Chuẩn PCAP Frame 412/440)
            inner_239 = build_leave_group_packet(
                uid=self.uid,
                group_id=gid,
                new_owner_id=int(new_owner_id) if new_owner_id else 0,
                is_silent=silent,
                is_block_readd=block_readd,
                seq=seq_239,
                ck_val=0,
                vercode=getattr(self, 'vercode', 260802903)
            )
            outer_239 = build_outer_frame(inner_239, self.dk)

            if wait_response:
                self._prepare_cmd_ack(CMD_LEAVE_GROUP_225)
                self._prepare_cmd_ack(CMD_LEAVE_GROUP_239)

            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer_225)
                    self.sock.sendall(outer_239)

            self.last_traffic = time.time()
            logger.info(f"[✔] Đã gửi yêu cầu rời Group {gid} qua Socket (CMD 225 SUB 3 & CMD 239 SUB 1, Seq={seq_225}/{seq_239})")

            if wait_response:
                got_ack, ack_res = self._wait_cmd_ack(CMD_LEAVE_GROUP_225, timeout=timeout)
                if not got_ack:
                    got_ack, ack_res = self._wait_cmd_ack(CMD_LEAVE_GROUP_239, timeout=timeout)
                status_code = ack_res.get('status_code', 0 if got_ack else -1) if got_ack else -1
                is_success = (got_ack and (status_code == 0 or status_code == -1))
                logger.info(
                    f"[*] Phản hồi từ Server Gateway (Leave Group {gid}): "
                    f"Status={status_code} ({'Thành công 100%' if is_success else 'Không phản hồi / Lỗi'}), "
                    f"Len={ack_res.get('params_len', 0)}B"
                )
                return {
                    'sent': True,
                    'got_response': got_ack,
                    'success': is_success,
                    'status_code': status_code,
                    'ack_result': ack_res
                }
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi rời nhóm: {e}")
            return {'sent': False, 'error': str(e)} if wait_response else False

    def create_poll(
        self,
        group_id: int | str,
        question: str,
        options: List[str]
    ) -> bool:
        """Tạo cuộc bình chọn / Poll trong nhóm chat qua Socket (CMD 1640 SUB 3)."""
        if not self.is_connected or not self.sock:
            return False
        try:
            gid = int(group_id)
            seq, cmsg, _ = self._get_next_counters()
            inner = build_create_poll_packet(
                uid=self.uid,
                group_id=gid,
                question=question,
                options=options,
                seq=seq,
                ck_val=0
            )
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f"[✔] Đã gửi yêu cầu tạo bình chọn '{question}' trong Group {gid} qua Socket (CMD 1640 SUB 3)")
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi tạo bình chọn: {e}")
            return False

    def recall_message(
        self,
        group_id: int | str,
        cli_msg_id: Union[int, str],
        global_msg_id: Union[int, str] = 0,
        owner_id: Optional[Union[int, str]] = None,
        msg_type: int = 1,
        is_group: bool = True
    ) -> bool:
        """Thu hồi tin nhắn toàn nhóm / 1-1 cho tất cả mọi người qua Socket (CMD 204 SUB 2 / CMD 114 SUB 2)."""
        if not self.is_connected or not self.sock:
            return False
        try:
            gid = int(group_id)
            seq, cmsg, _ = self._get_next_counters()
            owner = int(owner_id) if owner_id else int(self.uid)
            cmd = CMD_RECALL_MSG_GROUP if is_group else CMD_RECALL_MSG_1TO1
            sub = SUB_RECALL_MSG_GROUP if is_group else SUB_RECALL_MSG_1TO1
            t_type = 4 if is_group else 3
            c_id = int(cli_msg_id) if cli_msg_id else int(time.time() * 1000)
            c_counter = c_id & 0xFFFFFFFF
            ck = compute_checksum(cmd, sub, seq, self.uid, target=gid, target_type=t_type, cmsg=c_counter, bb=0, ty=2, ver=3)
            inner = build_recall_message_packet(
                uid=self.uid,
                target_id=gid,
                cli_msg_id=c_id,
                global_msg_id=global_msg_id,
                msg_type=msg_type,
                owner_id=owner,
                is_group=is_group,
                cmsg_counter=c_counter,
                seq=seq,
                ck_val=ck
            )
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f"[✔] Đã gửi yêu cầu thu hồi tin nhắn #{cli_msg_id} trong {'Group' if is_group else 'User'} {gid} (CMD {cmd} SUB {sub})")
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi thu hồi tin nhắn: {e}")
            return False

    def delete_message(
        self,
        group_id: int | str,
        cli_msg_id: Union[int, str],
        global_msg_id: Union[int, str] = "",
        owner_id: Optional[Union[int, str]] = None,
        is_group: bool = True,
        only_me: bool = False
    ) -> bool:
        """Xóa tin nhắn qua Socket (CMD 205 SUB 3)."""
        if not self.is_connected or not self.sock:
            return False
        try:
            gid = int(group_id)
            seq, cmsg, _ = self._get_next_counters()
            inner = build_delete_message_packet(
                uid=self.uid,
                group_id=gid,
                cli_msg_id=cli_msg_id,
                global_msg_id=global_msg_id,
                is_group=is_group,
                only_me=only_me,
                seq=seq,
                ck_val=0
            )
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            action_desc = "xóa tin nhắn (chỉ phía mình)" if only_me else "xóa tin nhắn (toàn nhóm)"
            logger.info(f"[✔] Đã gửi yêu cầu {action_desc} #{cli_msg_id} trong {'Group' if is_group else 'User'} {gid} (CMD 205 SUB 3)")
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi xóa tin nhắn: {e}")
            return False

    def add_member(
        self,
        group_id: int,
        member_uids: int | str | List[int | str],
        is_invite: bool = False
    ) -> bool:
        """Thêm / mời thành viên vào nhóm chat qua Socket (CMD 235 SUB 0, bb=0, ty=1)."""
        if not self.is_connected or not self.sock:
            return False
        try:
            if isinstance(member_uids, (int, str)):
                uids = [int(member_uids)]
            else:
                uids = [int(u) for u in member_uids]

            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(CMD_ADD_MEMBER, 0, seq, self.uid, bb=0, ty=1, ver=3)
            inner = build_add_member_packet(
                uid=self.uid,
                group_id=int(group_id),
                member_uids=uids,
                is_invite=is_invite,
                seq=seq,
                ck_val=ck
            )
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f"[✔] Đã gửi lệnh thêm thành viên {uids} vào Group {group_id}")
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi thêm thành viên: {e}")
            return False

    def join_group(
        self,
        group_id: int | str,
        source: int = 1
    ) -> bool:
        """Tham gia nhóm chat qua Socket (CMD 2000 SUB 3 & CMD 246 SUB 3)."""
        if not self.is_connected or not self.sock:
            return False
        try:
            gid = int(group_id)
            seq, cmsg, _ = self._get_next_counters()

            # Gửi CMD 2000 SUB 3 (chuẩn Zalo Android mới)
            try:
                inner_2000 = build_join_group_2000_packet(
                    uid=self.uid,
                    group_id=gid,
                    flag_byte=0,
                    seq=seq,
                    ck_val=0,
                    vercode=getattr(self, 'vercode', 260802903)
                )
                outer_2000 = build_outer_frame(inner_2000, self.dk)
                with self.send_lock:
                    if self.sock:
                        self.sock.sendall(outer_2000)
            except Exception as e_2000:
                logger.debug(f"Lỗi gửi CMD 2000 join group: {e_2000}")

            # Gửi CMD 246 SUB 3 (backward compatibility)
            seq2, _, _ = self._get_next_counters()
            ck = compute_checksum(CMD_JOIN_GROUP, SUB_JOIN_GROUP, seq2, self.uid, bb=0, ty=1, ver=3)
            inner = build_join_group_packet(
                uid=self.uid,
                group_id=gid,
                source=source,
                seq=seq2,
                ck_val=ck,
                vercode=getattr(self, 'vercode', 260802903)
            )
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f"[✔] Đã gửi yêu cầu tham gia Group {gid} qua Socket (CMD 2000 & 246)")
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi tham gia nhóm qua socket: {e}")
            return False

    def preview_link_901(
        self,
        link_url: str,
        wait_response: bool = True,
        timeout: float = 6.0
    ) -> Union[bool, Dict[str, Any]]:
        """Gửi yêu cầu phân giải / Preview link nhóm (CMD 901 SUB 3, chuẩn PCAP Frame 419)."""
        if not self.is_connected or not self.sock:
            return {'sent': False, 'error': 'Not connected'} if wait_response else False
        try:
            from core.socket.protocol import build_preview_link_901_packet
            seq, cmsg, _ = self._get_next_counters()
            inner = build_preview_link_901_packet(
                uid=self.uid,
                link_url=link_url,
                seq=seq,
                ck_val=0,
                vercode=getattr(self, 'vercode', 260802903)
            )
            outer = build_outer_frame(inner, self.dk)
            if wait_response:
                self._prepare_cmd_ack(901)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f"[✔] Đã gửi yêu cầu Preview link '{link_url}' qua Socket (CMD 901 SUB 3)")
            if wait_response:
                got_ack, ack_res = self._wait_cmd_ack(901, timeout=timeout)
                return {
                    'sent': True,
                    'got_response': got_ack,
                    'group_id': ack_res.get('group_id') if got_ack else None,
                    'ack_result': ack_res
                }
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi preview link 901: {e}")
            return {'sent': False, 'error': str(e)} if wait_response else False

    def query_group_906(
        self,
        group_id: int | str,
        wait_response: bool = False,
        timeout: float = 5.0
    ) -> Union[bool, Dict[str, Any]]:
        """Gửi yêu cầu truy vấn cấu hình nhóm theo GID (CMD 906 SUB 0, chuẩn PCAP Frame 421)."""
        if not self.is_connected or not self.sock:
            return {'sent': False, 'error': 'Not connected'} if wait_response else False
        try:
            from core.socket.protocol import build_query_group_906_packet
            seq, cmsg, _ = self._get_next_counters()
            gid = int(group_id)
            inner = build_query_group_906_packet(
                uid=self.uid,
                group_id=gid,
                seq=seq,
                ck_val=0
            )
            outer = build_outer_frame(inner, self.dk)
            if wait_response:
                self._prepare_cmd_ack(906)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            if wait_response:
                got_ack, ack_res = self._wait_cmd_ack(906, timeout=timeout)
                return {'sent': True, 'got_response': got_ack, 'ack_result': ack_res}
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi truy vấn nhóm 906: {e}")
            return {'sent': False, 'error': str(e)} if wait_response else False

    def join_group_by_link(
        self,
        link_url: str,
        group_id: int | str = 0,
        msg: str = "",
        source: int = 1,
        wait_response: bool = True,
        timeout: float = 8.0
    ) -> Union[bool, Dict[str, Any]]:
        """Tham gia nhóm qua liên kết (zalo.me/g/...) hoặc link code theo quy trình chuẩn PCAP 4 bước:
        1. CMD 901 SUB 3: Phân giải link để lấy Group ID chính xác.
        2. CMD 906 SUB 0: Truy vấn thông tin cấu hình nhóm.
        3. CMD 244 SUB 4: Gửi yêu cầu tham gia nhóm kèm full URL và GID đã phân giải.
        4. CMD 2000 SUB 3 & CMD 246 SUB 3: Kích hoạt tham gia nhóm trực tiếp.
        """
        link_clean = str(link_url).strip()
        if "zalo.me/g/" in link_clean:
            link_code = link_clean.split("zalo.me/g/")[-1].split("?")[0].strip()
        else:
            link_code = link_clean

        full_url = f"https://zalo.me/g/{link_code}" if not link_clean.startswith("http") else link_clean
        gid = int(group_id or 0)

        # Bước 1: Preview link qua CMD 901 nếu chưa có group_id
        if not gid:
            res_901 = self.preview_link_901(full_url, wait_response=True, timeout=3.0)
            if isinstance(res_901, dict) and res_901.get('group_id'):
                gid = int(res_901['group_id'])

        # Bước 2: Query nhóm qua CMD 906 nếu có group_id
        if gid:
            try:
                self.query_group_906(gid, wait_response=False)
            except Exception:
                pass

        # Bước 3: Gửi CMD 244 SUB 4 tham gia nhóm qua link đầy đủ
        res = self.request_join_group(
            group_id=gid,
            link_url=full_url,
            msg=msg,
            source=source,
            sub_source=0,
            wait_response=True,
            timeout=timeout
        )

        # Bước 4: Gửi bổ sung CMD 2000 & 246
        found_gid = gid or (res.get('group_id') if isinstance(res, dict) else None)
        if found_gid:
            try:
                self.join_group(group_id=found_gid, source=source)
            except Exception:
                pass

        if wait_response:
            return res
        return bool(isinstance(res, dict) and res.get('sent', False))


    def join_group_invite(
        self,
        group_id: int | str,
        inviter_uid: int = 0
    ) -> bool:
        """Chấp nhận lời mời tham gia nhóm chat qua Socket (CMD 250 SUB 1)."""
        if not self.is_connected or not self.sock:
            return False
        try:
            gid = int(group_id)
            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(CMD_JOIN_GROUP_INVITE, SUB_JOIN_GROUP_INVITE, seq, self.uid, bb=0, ty=1, ver=3)
            inner = build_join_group_invite_packet(
                uid=self.uid,
                group_id=gid,
                inviter_uid=inviter_uid,
                seq=seq,
                ck_val=ck
            )
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f"[✔] Đã gửi yêu cầu chấp nhận lời mời Group {gid} qua Socket (CMD 250)")
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi chấp nhận lời mời nhóm qua socket: {e}")
            return False

    def request_join_group(
        self,
        group_id: int | str = 0,
        link_url: str = "",
        msg: str = "",
        source: int = 1,
        sub_source: int = 0,
        wait_response: bool = False,
        timeout: float = 8.0
    ) -> Union[bool, Dict[str, Any]]:
        """Gửi yêu cầu tham gia nhóm qua Link/Code/ID bằng Socket (CMD 244 SUB 4).
        
        Sau khi server ACK (status_code=0), lắng nghe thêm để bắt CMD 201 push
        chứa group_id thực tế của nhóm vừa tham gia.
        """
        if not self.is_connected or not self.sock:
            return {'sent': False, 'error': 'Not connected'} if wait_response else False
        try:
            gid = int(group_id or 0)
            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(CMD_REQUEST_JOIN_GROUP, SUB_REQUEST_JOIN_GROUP, seq, self.uid, bb=0, ty=1, ver=3)
            inner = build_request_join_group_packet(
                uid=self.uid,
                group_id=gid,
                msg=msg,
                link_url=link_url,
                source=source,
                sub_source=sub_source,
                seq=seq,
                ck_val=ck
            )
            outer = build_outer_frame(inner, self.dk)
            if wait_response:
                self._prepare_cmd_ack(CMD_REQUEST_JOIN_GROUP)

            # Lưu số lượng group đã biết trước khi join, để phát hiện group mới từ CMD 201
            groups_before = set(getattr(self, 'known_groups', {}).keys())

            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            logger.info(f"[✔] Đã gửi yêu cầu tham gia/link Group (GID={gid}, Link='{link_url}') qua Socket (CMD 244 SUB 4)")

            if wait_response:
                got_ack, ack_res = self._wait_cmd_ack(CMD_REQUEST_JOIN_GROUP, timeout=timeout)
                result_gid = ack_res.get('group_id')
                status_code = ack_res.get('status_code', -1) if got_ack else -1
                is_success = (got_ack and status_code == 0)

                # Nếu CMD 244 ACK status=0 nhưng chưa có group_id,
                # đợi thêm tối đa 3s để server push CMD 201 với group_id
                if got_ack and status_code == 0 and not result_gid:
                    deadline = time.time() + 3.0
                    while time.time() < deadline:
                        time.sleep(0.1)
                        new_groups = set(getattr(self, 'known_groups', {}).keys()) - groups_before
                        if new_groups:
                            result_gid = int(next(iter(new_groups)))
                            break

                logger.info(
                    f"[*] Phản hồi từ Server Gateway (CMD {ack_res.get('cmd', 244)} SUB {ack_res.get('sub', 4)}): "
                    f"Status={status_code} ({'Thành công 100%' if is_success else 'Không phản hồi / Lỗi'}), "
                    f"GroupID={result_gid or 'N/A'}, Len={ack_res.get('params_len', 0)}B"
                )

                return {'sent': True, 'got_response': got_ack, 'success': is_success, 'status_code': status_code, 'ack_result': ack_res, 'group_id': result_gid}
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi gửi yêu cầu tham gia/link nhóm qua socket: {e}")
            return {'sent': False, 'error': str(e)} if wait_response else False

    def request_group_link_info(
        self,
        link_url: str,
        source: int = 1,
        sub_source: int = 0,
        timeout: float = 8.0
    ) -> Optional[int]:
        """Gửi yêu cầu phân giải thông tin link nhóm qua Socket và trả về Group ID nếu tìm thấy."""
        res = self.preview_link_901(link_url=link_url, wait_response=True, timeout=timeout)
        if isinstance(res, dict) and res.get('group_id'):
            return int(res['group_id'])
        res2 = self.request_join_group(group_id=0, link_url=link_url, msg="", source=source, sub_source=sub_source, wait_response=True, timeout=timeout)
        if isinstance(res2, dict) and res2.get('group_id'):
            return int(res2['group_id'])
        return None

    # Đảm bảo disband_group gọi đúng CMD 242
    disband_group = disband_group_242
    send_cmd_1705 = send_group_event_1705
