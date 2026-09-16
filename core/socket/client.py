#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
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
"""

import json
import logging
import os
import random
import select
import socket
import struct
import threading
import time
from typing import Callable, Optional, Dict, Any, List, Tuple, Union

from .crypto import (
    encrypt_aes_gcm, decrypt_aes_gcm,
    decrypt_e2ee_cbc, DEFAULT_XK
)
from .protocol import (
    INNER_HEADER_FORMAT, InnerPacketHeader, OuterFrame,
    compute_checksum, xor_encode_d3, xor_decode_d3, dekey, XK,
    parse_d3_compressed_json,
    build_ping_packet,
    build_outer_frame, parse_incoming_frame,
    FRAME_TYPE_HANDSHAKE, FRAME_TYPE_DATA, FRAME_TYPE_CONTROL,
    CMD_PING, SUB_PING
)
from .handshake import (
    build_prov_frame, send_init_frames
)
from core.socket.actions.send_message import SendMessageActionMixin
from core.socket.actions.send_image import SendImageActionMixin
from core.socket.actions.send_video import SendVideoActionMixin
from core.socket.actions.send_doodle import SendDoodleActionMixin
from core.socket.actions.send_reaction import SendReactionActionMixin
from core.socket.actions.send_typing import SendTypingActionMixin
from core.socket.actions.pin_topic import PinTopicActionMixin
from core.socket.actions.poll import PollActionMixin
from core.socket.actions.undo_message import UndoMessageActionMixin
from core.socket.actions.group_actions import GroupActionsMixin
from core.socket.actions.block_user import BlockUserActionMixin

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


class ZaloSocketClient(
    SendMessageActionMixin,
    SendImageActionMixin,
    SendVideoActionMixin,
    SendDoodleActionMixin,
    SendReactionActionMixin,
    SendTypingActionMixin,
    PinTopicActionMixin,
    PollActionMixin,
    UndoMessageActionMixin,
    GroupActionsMixin,
    BlockUserActionMixin
):
    """Zalo TCP Socket Network Engine & API Hub."""

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
        self.f0_bytes = self._try_load_frame0()
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
        self.known_groups: Dict[str, Dict[str, Any]] = {}

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

    def disconnect(self):
        """Alias cho close()."""
        self.close()

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
                        if cmd in (1705, 1703, 1708, 1752, 113, 207, 202, 228, 234, 235, 239, 242, 246, 250, 225, 241, 244, 901, 902, 906, 2000, 1640, 382, 383):
                            raw_params = parsed.get('raw_params', b'')
                            status = struct.unpack('<i', raw_params[:4])[0] if len(raw_params) >= 4 else 0
                            ack_dict = {
                                'cmd': cmd,
                                'sub': sub,
                                'status_code': status,
                                'raw_hex': raw_params[:8].hex() if raw_params else '',
                                'raw_params': raw_params,
                                'params_len': len(raw_params),
                            }

                            if cmd in (901, 902):
                                try:
                                    ack_dict['status_code'] = struct.unpack_from('<i', raw_params, 0)[0] if len(raw_params) >= 4 else 0
                                    if b'{' in raw_params:
                                        j_idx = raw_params.find(b'{')
                                        j_obj = json.loads(raw_params[j_idx:].decode('utf-8', errors='ignore'))
                                        j_data = j_obj.get('data') or j_obj
                                        j_gid = (j_data.get('groupId') or j_data.get('grid') or
                                                 j_data.get('id') or j_data.get('group_id'))
                                        if j_gid:
                                            ack_dict['group_id'] = int(j_gid)
                                    import zlib as _zlib
                                    for _i in range(len(raw_params) - 1):
                                        if raw_params[_i:_i+2] == b'\x1f\x8b':
                                            try:
                                                _dec = _zlib.decompress(raw_params[_i:], 31)
                                                _j = json.loads(_dec)
                                                _d = _j.get('data') or _j
                                                _gid = _d.get('groupId') or _d.get('grid') or _d.get('id')
                                                if _gid:
                                                    ack_dict['group_id'] = int(_gid)
                                                ack_dict['json_data'] = _j
                                                break
                                            except Exception:
                                                pass
                                    if cmd == 902 and ack_dict.get('status_code') == 0:
                                        ack_dict['join_success'] = True
                                        logger.info(f"[✔] CMD 902 SUB {sub}: Join nhóm thành công! GID={ack_dict.get('group_id','?')}")
                                except Exception:
                                    pass
                                if cmd == 902:
                                    with self.ack_lock:
                                        self.cmd_ack_results[902] = ack_dict
                                        if 902 in self.cmd_ack_events:
                                            self.cmd_ack_events[902].set()
                                        self.cmd_ack_results[901] = ack_dict
                                        if 901 in self.cmd_ack_events:
                                            self.cmd_ack_events[901].set()
                                        self.general_ack_event.set()

                            if cmd in (244, 901, 902):
                                try:
                                    if len(raw_params) >= 8:
                                        ack_dict['server_time'] = struct.unpack_from('<I', raw_params, 4)[0]
                                    if len(raw_params) > 4:
                                        d3_res = parse_d3_compressed_json(raw_params[4:], self.uid)
                                        if d3_res:
                                            ack_dict['json_data'] = d3_res
                                            if 'error_code' in d3_res:
                                                ack_dict['group_error_code'] = d3_res['error_code']
                                                from core.models.enums import ZaloGroupErrorCode
                                                ack_dict['group_error_msg'] = ZaloGroupErrorCode.get_message(d3_res['error_code'])
                                            if d3_res.get('group_id'):
                                                ack_dict['group_id'] = int(d3_res['group_id'])

                                    if b'{' in raw_params and not ack_dict.get('group_id'):
                                        j_idx = raw_params.find(b'{')
                                        j_obj = json.loads(raw_params[j_idx:].decode('utf-8', errors='ignore'))
                                        j_data = j_obj.get('data') or j_obj
                                        j_gid = j_data.get('groupId') or j_data.get('grid') or j_data.get('id')
                                        if j_gid:
                                            ack_dict['group_id'] = int(j_gid)
                                    if ack_dict.get('group_id'):
                                        self.known_groups[str(ack_dict['group_id'])] = {'group_id': ack_dict['group_id'], 'ts': time.time()}
                                except Exception:
                                    pass

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

                        if cmd == 201:
                            raw_params = parsed.get('raw_params', b'')
                            if len(raw_params) >= 4:
                                try:
                                    pushed_gid = struct.unpack_from('<I', raw_params, 0)[0]
                                    if pushed_gid > 0:
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
