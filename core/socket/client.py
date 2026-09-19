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

from core.socket.constants import (
    DEFAULT_SERVERS,
    FRAME_TYPE_HANDSHAKE,
    FRAME_TYPE_DATA,
    FRAME_TYPE_CONTROL,
    CMD_PING,
    SUB_PING,
)
from core.socket.frame import (
    InnerPacketHeader,
    OuterFrame,
    compute_checksum,
    build_outer_frame,
)
from core.socket.builder import build_ping_packet
from core.socket.parser import parse_incoming_frame
from core.socket.events import EventHub, MessageEvent, ReactionEvent
from core.socket.dispatcher import PacketDispatcher
from core.socket.handshake import build_prov_frame, send_init_frames

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
from core.socket.actions.send_sticker import SendStickerActionMixin
from core.socket.actions.send_location import SendLocationActionMixin
from core.socket.actions.send_file import SendFileActionMixin
from core.socket.actions.send_contact import SendContactActionMixin
from core.socket.actions.user_actions import UserActionsMixin

logger = logging.getLogger('core.socket.client')


class ZaloSocketClient(
    SendMessageActionMixin,
    SendImageActionMixin,
    SendVideoActionMixin,
    SendDoodleActionMixin,
    SendStickerActionMixin,
    SendLocationActionMixin,
    SendFileActionMixin,
    SendContactActionMixin,
    SendReactionActionMixin,
    SendTypingActionMixin,
    PinTopicActionMixin,
    PollActionMixin,
    UndoMessageActionMixin,
    GroupActionsMixin,
    BlockUserActionMixin,
    UserActionsMixin
):
    """
    Zalo Socket Client
    High-performance, event-driven socket client for Zalo binary protocol.
    Provides typed event subscriptions (on_message, on_reaction, on_delivery)
    and full action mixins.
    """

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

        self.event_hub = EventHub()
        self.dispatcher = PacketDispatcher(self)

    def on_message(self, handler: Callable[[MessageEvent], None]):
        """Register a handler for incoming chat messages (typed MessageEvent)."""
        self.event_hub.on('message', handler)
        return handler

    def on_reaction(self, handler: Callable[[ReactionEvent], None]):
        """Register a handler for reaction push events (typed ReactionEvent)."""
        self.event_hub.on('reaction', handler)
        return handler

    def on_delivery(self, handler: Callable[[Dict[str, Any]], None]):
        """Register a handler for delivery receipts (CMD 202)."""
        self.event_hub.on('delivery', handler)
        return handler

    def on_frame(self, handler: Callable[[Dict[str, Any]], None]):
        """Register a handler for raw parsed frames."""
        self.event_hub.on('frame', handler)
        return handler

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
        return (got, res)

    def _try_load_frame0(self) -> Optional[bytes]:
        search_paths = []
        if self.frame0_path:
            search_paths.append(self.frame0_path)
        search_paths.extend([
            os.path.join(os.getcwd(), 'frame0.bin'),
            'frame0.bin',
            os.path.expanduser('~/.zalo/frame0.bin'),
            '/root/zalo/frame0.bin'
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
            os.path.join(os.getcwd(), '.session_state.json'),
            os.path.expanduser('~/.zalo/.session_state.json'),
            '/root/zalo/.session_state.json'
        ]
        for c in candidates:
            if os.path.isfile(c):
                return c
        return os.path.join(os.getcwd(), '.session_state.json')

    def _load_or_init_state(self):
        self.cmsg_id = int(time.time() * 1000) & 2147483647
        self.ck_val = (int(time.time() * 1000) ^ 1827134112) & 4294967295
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
            self.ck_val = (self.ck_val + 1) & 4294967295
            return self.ck_val

    def _get_next_counters(self) -> Tuple[int, int, int]:
        with self.seq_lock:
            self.current_seq -= 1
            seq = self.current_seq
            self.cmsg_id += 1
            cmsg = self.cmsg_id
            self.ck_val = (self.ck_val + 1) & 4294967295
            ck = self.ck_val
            self._save_state_if_needed()
            return (seq, cmsg, ck)

    def _select_socket_server(self) -> Tuple[str, int, Optional[str]]:
        v4_servers = [s for s in self.server_pool if ':' not in s.get('host', '') and s.get('port') == 443]
        if v4_servers:
            srv = random.choice(v4_servers)
        else:
            srv = random.choice(self.server_pool)
        return (srv['host'], srv['port'], srv.get('pubKey'))

    def connect(self) -> bool:
        if self.is_connected:
            return True
        self.current_host, self.current_port, srv_pk = self._select_socket_server()
        self.current_pubkey = srv_pk or self.server_pubkey_b64
        logger.info(f'[Socket] Connecting to {self.current_host}:{self.current_port}...')
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10.0)
            self.sock.connect((self.current_host, self.current_port))

            http_req = f'GET / HTTP/1.1\r\nHost: {self.current_host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n'.encode('utf-8')
            self.sock.sendall(http_req)

            if self.session_key and self.ksid and self.current_pubkey:
                logger.debug('[Handshake] Generating PROV Frame 0 (X25519 ECDH)...')
                prov_frame_bytes = build_prov_frame(
                    session_key=self.session_key,
                    dk=self.dk,
                    ksid=self.ksid,
                    server_pubkey_b64=self.current_pubkey,
                    uid=self.uid
                )
                self.sock.sendall(prov_frame_bytes)
            elif self.f0_bytes:
                logger.debug('[Handshake] Using preloaded frame0 ticket...')
                raw_f0 = struct.pack('<IB', len(self.f0_bytes) + 5, FRAME_TYPE_HANDSHAKE) + self.f0_bytes
                self.sock.sendall(raw_f0)
            else:
                raise ValueError('Missing credentials to build or load Frame 0 handshake!')

            time.sleep(0.15)
            self.sock.setblocking(False)
            try:
                while True:
                    d = self.sock.recv(4096)
                    if not d:
                        break
            except BlockingIOError:
                pass

            self.sock.setblocking(True)
            self.sock.settimeout(None)

            logger.debug('[Handshake] Sending active session initialization sequence...')
            send_init_frames(self.sock, self.dk, self.uid, send_lock=self.send_lock)

            self.is_connected = True
            self.is_running = True
            self.handshake_ok = True
            self.last_traffic = time.time()
            logger.info(f'[Socket] Connected and session active (UID: {self.uid})')

            self.recv_thread = threading.Thread(target=self._recv_loop, name='ZaloSocketRecv', daemon=True)
            self.recv_thread.start()

            self.ping_thread = threading.Thread(target=self._ping_loop, name='ZaloSocketPing', daemon=True)
            self.ping_thread.start()

            if not self.supervisor_thread or not self.supervisor_thread.is_alive():
                self.supervisor_thread = threading.Thread(target=self._supervisor_loop, name='ZaloSupervisor', daemon=True)
                self.supervisor_thread.start()

            return True
        except Exception as e:
            logger.error(f'[Socket] Connection failed: {e}')
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
        logger.debug('[Socket] Connection closed')

    def disconnect(self):
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
                    logger.warning('[Socket] Server closed connection')
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
                        parsed = parse_incoming_frame(frame, dk=self.dk, cryptkey=self.cryptkey, my_uid=self.uid)
                        self.dispatcher.dispatch(parsed)
                    except Exception as frame_err:
                        logger.error(f'[Socket] Error dispatching frame: {frame_err}')
            except Exception as e:
                if self.is_running:
                    logger.warning(f'[Socket] Exception in recv loop: {e}')
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
                    logger.debug(f'[Ping] Sent Keepalive Ping CMD 1971 (Seq={seq}, ck={hex(ck)})')
            except Exception as e:
                logger.warning(f'[Ping] Keepalive failed: {e}')
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
                logger.warning(f'[Supervisor] Connection idle ({now - self.last_traffic:.1f}s) or dropped. Reconnecting...')
                self._disconnect_socket()
                time.sleep(1.0)
                try:
                    self.connect()
                except Exception as ex:
                    logger.error(f'[Supervisor] Reconnect error: {ex}')
