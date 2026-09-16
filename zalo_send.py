#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zalo_send.py — Gửi tin nhắn Zalo Socket TCP Binary Protocol (Hỗ trợ 1-1 & Group Realtime Mới Nhất)
"""

import argparse
import base64
import gzip
import itertools
import json
import logging
import os
import re
import socket
import sqlite3
import struct
import sys
import threading
import time
import traceback
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

XK = b'P1BL2G5I7NJD2H3JAUD554G7645PH54F'
DEFAULT_HOST = "49.213.95.83"
DEFAULT_PORT = 443

def setup_logger(log_file="/root/zalo/debug.log"):
    logger = logging.getLogger("zalo_send")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        fh = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        formatter = logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    return logger

LOGGER = setup_logger()

def parse_zaloprefs(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Không tìm thấy file zaloprefs: {path}")
    db = sqlite3.connect(path)
    cur = db.cursor()
    rows = cur.execute("SELECT key, value FROM prefs_v2").fetchall()
    db.close()

    users = {}
    current_uid = None
    for k, v in rows:
        if k == 'currentUserUid':
            current_uid = str(v).strip()
            continue
        m_ks = re.match(r'KEY_STRING_SOCKET_PRO_V1_KEY_SET_(ID|VALUE)_(\d+)', k)
        if m_ks:
            kind, uid = m_ks.group(1), m_ks.group(2)
            users.setdefault(uid, {})[kind] = str(v)
            continue
        m_ck = re.match(r'CryptKey(\d+)', k)
        if m_ck:
            uid = m_ck.group(1)
            users.setdefault(uid, {})['CryptKey'] = str(v)
            continue
        if k == 'sessionKey':
            users.setdefault('_global', {})['sessionKey'] = str(v)
        elif k == 'token':
            users.setdefault('_global', {})['token'] = str(v)

    parsed_users = {}
    for uid, data in users.items():
        if uid == '_global':
            continue
        dk_bytes = None
        if 'VALUE' in data:
            try:
                dk_bytes = base64.b64decode(data['VALUE'])
            except Exception:
                pass
        ck_bytes = None
        if 'CryptKey' in data:
            try:
                ck_bytes = base64.b64decode(data['CryptKey'])
            except Exception:
                pass
        parsed_users[uid] = {
            'uid': int(uid),
            'keySetId': data.get('ID', ''),
            'dk': dk_bytes,
            'dk_b64': data.get('VALUE', ''),
            'cryptkey': ck_bytes,
            'cryptkey_b64': data.get('CryptKey', '')
        }

    return {
        'current_uid': current_uid,
        'users': parsed_users,
        'global': users.get('_global', {})
    }

def xor_encode_d3(plain: bytes, uid: int) -> bytes:
    a4 = len(plain) + 36
    le4 = struct.pack('<I', a4)
    ule = struct.pack('<I', uid)
    k = bytes(XK[i % 32] ^ le4[i % 4] ^ ule[i % 4] for i in range(32))
    return bytes(plain[i] ^ k[i % 32] for i in range(len(plain)))

def build_d3_message_group(text: str) -> bytes:
    prop_obj = {
        'sSrcType': -1,
        'sSrcStr': '',
        'msg_warning_type': 0,
        'emoji': {'content': 0, 'num': 0, 'uniq': 0, 'first': '', 'last': '', 'most': '', 'text': 1}
    }
    prop_bytes = json.dumps(prop_obj, separators=(',', ':')).encode('utf-8')
    return bytearray([0x01, 0x00, 0x01, 0x07, 0x00]) + (b'\xff' * 12) + struct.pack('<I', len(prop_bytes)) + prop_bytes + text.encode('utf-8')

def build_d3_message_1to1(text: str, cryptkey: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = AES.new(cryptkey, AES.MODE_CBC, iv=iv)
    padded = pad(text.encode('utf-8'), 16)
    ct = cipher.encrypt(padded)

    text_block = bytes([0x01]) + iv + struct.pack('<H', len(ct)) + ct

    prop_obj = {
        'sSrcType': -1,
        'sSrcStr': '',
        'msg_warning_type': 0,
        'emoji': {'content': 0, 'num': 0, 'uniq': 0, 'first': '', 'last': '', 'most': '', 'text': 1}
    }
    prop_bytes = json.dumps(prop_obj, separators=(',', ':')).encode('utf-8')
    prop_header = bytes([0x29, 0x00, 0x01, 0x07, 0x00]) + (b'\xff' * 12) + struct.pack('<I', len(prop_bytes)) + prop_bytes
    return prop_header + text_block

def compute_checksum(cmd: int, sub: int, seq: int, uid: int, target: int = 0, target_type: int = 0, cmsg: int = 0, bb: int = 1, ty: int = 2, ver: int = 3) -> int:
    """
    Tính Checksum (ck_val) chuẩn theo libznetwork.so:
    ck_val = (bb + ty + seq + uid + ver + cmd + sub + target + target_type + cmsg) mod 2^32 XOR 0x6ce7daa0
    """
    total = (bb + ty + seq + uid + ver + cmd + sub + target + target_type + cmsg) & 0xFFFFFFFF
    return total ^ 0x6ce7daa0

def build_gcm_frame(inner_pkt: bytes, dk: bytes) -> bytes:
    iv_gcm = os.urandom(12)
    cipher_gcm = AES.new(dk, AES.MODE_GCM, nonce=iv_gcm, mac_len=16)
    ct_gcm, tag_gcm = cipher_gcm.encrypt_and_digest(inner_pkt)
    body = ct_gcm + tag_gcm + iv_gcm
    return struct.pack('<IB', len(body) + 5, 4) + body

class ZaloSessionClient:
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, uid=None, dk=None, cryptkey=None, f0_bytes=None, init_frames_path=None):
        self.host = host
        self.port = port
        self.uid = uid
        self.dk = dk
        self.cryptkey = cryptkey
        self.f0_bytes = f0_bytes
        self.init_frames_path = init_frames_path or '/root/zalo/init_sequence.json'
        
        self.sock = None
        self.sock_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.recv_thread = None
        
        self.ack_event = threading.Event()
        self.ack_result = {"success": False, "err_code": None, "details": None, "receipts": []}
        self.init_data = {}

    def connect(self):
        print(f"📡 1. Đang kết nối TCP tới {self.host}:{self.port}...")
        self.sock = socket.create_connection((self.host, self.port), timeout=10)
        print(f"[✔] Đã kết nối TCP thành công!")

        if self.port == 443:
            print(f"🌐 2. Gửi HTTP Upgrade Header...")
            req = f"GET / HTTP/1.1\r\nHost: {self.host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode('latin1')
            self.sock.sendall(req)
            resp = self.sock.recv(1024).decode('latin1', errors='ignore')
            if "HTTP/1." not in resp:
                raise RuntimeError(f"HTTP Upgrade thất bại: {resp[:100]}")
            print(f"[✔] HTTP 200 OK — Kênh Socket sẵn sàng!")

        # 3. Gửi Frame 0 Handshake
        print(f"🤝 3. Gửi Frame 0 Handshake...")
        f0_frame = struct.pack('<IB', len(self.f0_bytes) + 5, 8) + self.f0_bytes
        self.sock.sendall(f0_frame)

        self.recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self.recv_thread.start()

        time.sleep(0.3)
        if self.ack_result.get("ticket_expired"):
            raise RuntimeError("Frame 0 session ticket hết hạn (Code=-22). Cần capture pcap mới trên điện thoại.")

        if os.path.isfile(self.init_frames_path):
            with open(self.init_frames_path, 'r', encoding='utf-8') as f:
                self.init_data = json.load(f)

    def _recv_loop(self):
        buf = bytearray()
        while not self.stop_event.is_set():
            try:
                self.sock.settimeout(0.5)
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)
                while len(buf) >= 5:
                    flen, ftype = struct.unpack('<IB', buf[:5])
                    if len(buf) < flen:
                        break
                    fbody = bytes(buf[5:flen])
                    del buf[:flen]

                    if ftype in (3, 4):
                        try:
                            iv, tag, ct = fbody[-12:], fbody[-28:-12], fbody[:-28]
                            pt = AES.new(self.dk, AES.MODE_GCM, nonce=iv, mac_len=16).decrypt_and_verify(ct, tag)
                            r_ck, bb, ty, r_seq, r_uid, ver, r_cmd, r_sub = struct.unpack('<IBBiIBHB', pt[:18])
                            params = pt[18:]
                            code = struct.unpack('<i', params[:4])[0] if len(params) >= 4 else (params[0] if params else 0)

                            LOGGER.debug(f"[RECV] CMD={r_cmd} SUB={r_sub} SEQ={r_seq} UID={r_uid} Code={code}")

                            # CMD 1 SUB 5: Handshake OK
                            if r_cmd == 1 and r_sub == 5:
                                LOGGER.info("[Handshake OK] Frame 0 Accepted!")

                            # CMD 3 SUB 0: Disconnect
                            elif r_cmd == 3 and r_sub == 0:
                                if code == -22:
                                    self.ack_result["ticket_expired"] = True
                                    self.ack_event.set()

                            # CMD 106 / 206 Typing ACK
                            elif (r_cmd == 106 or r_cmd == 206) and r_sub == 1:
                                if code == 0:
                                    LOGGER.info(f"[Typing Ack] CMD={r_cmd} Code=0")

                            # CMD 113 / CMD 207 Ack
                            elif (r_cmd == 113 and r_sub == 41) or (r_cmd == 207 and r_sub == 1):
                                if code == 0:
                                    self.ack_result["success"] = True
                                    self.ack_result["err_code"] = 0
                                    self.ack_event.set()

                            # CMD 102 SUB 3: Delivery Receipt cho 1-1
                            elif r_cmd == 102 and r_sub == 3:
                                json_body = params[4:]
                                try:
                                    js = json.loads(json_body.decode('utf-8', errors='ignore'))
                                    LOGGER.info(f"[102 SUB 3] {json.dumps(js, ensure_ascii=False)}")
                                    for item in js.get("data", []):
                                        for m in item.get("msg", []):
                                            if m.get("err") == 0:
                                                self.ack_result["success"] = True
                                                self.ack_result["err_code"] = 0
                                                self.ack_result["details"] = m
                                                self.ack_result["receipts"].append(m)
                                                self.ack_event.set()
                                except Exception:
                                    pass

                            # CMD 202 SUB 3: Delivery Receipt cho Group
                            elif r_cmd == 202 and r_sub == 3:
                                json_body = params[4:]
                                try:
                                    js = json.loads(json_body.decode('utf-8', errors='ignore'))
                                    LOGGER.info(f"[202 SUB 3] {json.dumps(js, ensure_ascii=False)}")
                                    for item in js.get("data", []):
                                        for m in item.get("msg", []):
                                            if m.get("err") == 0:
                                                self.ack_result["success"] = True
                                                self.ack_result["err_code"] = 0
                                                self.ack_result["details"] = m
                                                self.ack_result["receipts"].append(m)
                                                self.ack_event.set()
                                except Exception:
                                    pass

                            # CMD 1865: Broadcast 1-1
                            elif r_cmd == 1865:
                                LOGGER.info(f"[1865 Broadcast 1-1] UID={r_uid} Code={code}")

                            # CMD 1867: Broadcast Group
                            elif r_cmd == 1867:
                                LOGGER.info(f"[1867 Broadcast Group] UID={r_uid} Code={code}")

                        except Exception as de:
                            LOGGER.warning(f"Decrypt frame err: {de}")
            except socket.timeout:
                continue
            except Exception:
                break

    def send_1to1(self, target_uid: int, text: str, typing_first: bool = True, timeout: float = 6.0):
        init_frames = self.init_data.get('frames', [])[1:33]
        print(f"🔄 4. Gửi {len(init_frames)} Init Frames thiết lập phiên...")
        for fr in init_frames:
            raw_b = bytes.fromhex(fr['raw_frame_hex'])
            with self.sock_lock:
                self.sock.sendall(raw_b)
            time.sleep(0.01)
        time.sleep(0.4)

        if typing_first:
            print(f"✍️  Gửi hiệu ứng đang soạn tin nhắn (Typing CMD 106) tới {target_uid}...")
            seq_typ = -44
            cmsg_typ = int(time.time() * 1000) & 0xFFFFFFFF
            ck_typ = compute_checksum(106, 1, seq_typ, self.uid, target_uid, 3, cmsg_typ)
            params_typ = struct.pack('<IBII', target_uid, 3, cmsg_typ, 416)
            inner_typ = struct.pack('<IBBiIBHB', ck_typ, 1, 2, seq_typ, self.uid, 3, 106, 1) + params_typ
            with self.sock_lock:
                self.sock.sendall(build_gcm_frame(inner_typ, self.dk))
            time.sleep(1.0)

        print(f"\n💬 Đang gửi tin nhắn 1-1 tới UID: {target_uid}...")
        print(f"   ├─ Nội dung: {text!r}")
        
        self.ack_event.clear()
        self.ack_result["success"] = False
        self.ack_result["err_code"] = None
        self.ack_result["details"] = None
        self.ack_result["receipts"] = []

        seq_id = -45
        cmsg_id = int(time.time() * 1000) & 0xFFFFFFFF
        ck_val = compute_checksum(113, 41, seq_id, self.uid, target_uid, 3, cmsg_id)

        d3_plain = build_d3_message_1to1(text, self.cryptkey)
        d3_xor = xor_encode_d3(d3_plain, self.uid)
        params_msg = struct.pack('<IBII', target_uid, 3, cmsg_id, 416) + d3_xor
        inner_msg = struct.pack('<IBBiIBHB', ck_val, 1, 2, seq_id, self.uid, 3, 113, 41) + params_msg
        raw_frame = build_gcm_frame(inner_msg, self.dk)

        with self.sock_lock:
            self.sock.sendall(raw_frame)

        print(f"   ├─ Đã gửi {len(raw_frame)} bytes qua Socket (CMD 113 SUB 41 | Seq={seq_id} | cmsg=0x{cmsg_id:08x})")
        print(f"   ⏳ Đang chờ xác nhận từ Server Zalo...")

        got_ack = self.ack_event.wait(timeout=timeout)
        time.sleep(0.5)

        if self.ack_result["success"]:
            print(f"\n[✔ THÀNH CÔNG RỰC RỠ] Tin nhắn 1-1 đã được Server Zalo tiếp nhận & chuyển tiếp!")
            if self.ack_result.get("details"):
                d = self.ack_result["details"]
                print(f"   └─ Global Message ID (gmi): {d.get('gmi')}")
                print(f"   └─ Client Message ID (cmi): {d.get('cmi')}")
                print(f"   └─ Server Message ID (sid): {d.get('sid')}")
            return True
        else:
            print(f"\n[!] Không nhận được phản hồi ACK trong {timeout}s.")
            return False

    def send_group(self, group_id: int, text: str, typing_first: bool = True, timeout: float = 6.0):
        # 1. Replay frames 1..3
        for fr in self.init_data.get('frames', [])[1:3]:
            raw_b = bytes.fromhex(fr['raw_frame_hex'])
            with self.sock_lock:
                self.sock.sendall(raw_b)
            time.sleep(0.01)
        time.sleep(0.3)

        if typing_first:
            print(f"✍️  Gửi hiệu ứng đang soạn tin nhắn (Typing CMD 206) tới Group {group_id}...")
            seq_grp_typ = -14
            cmsg_grp_typ = int(time.time() * 1000) & 0xFFFFFFFF
            ck_grp_typ = compute_checksum(206, 1, seq_grp_typ, self.uid, group_id, 3, cmsg_grp_typ)
            params_grp_typ = struct.pack('<IBII', group_id, 3, cmsg_grp_typ, 416)
            inner_grp_typ = struct.pack('<IBBiIBHB', ck_grp_typ, 1, 2, seq_grp_typ, self.uid, 3, 206, 1) + params_grp_typ
            with self.sock_lock:
                self.sock.sendall(build_gcm_frame(inner_grp_typ, self.dk))
            time.sleep(1.0)

        # Replay Frame 4 (CMD 203 SUB 4)
        if len(self.init_data.get('frames', [])) > 4:
            f4 = self.init_data['frames'][4]
            with self.sock_lock:
                self.sock.sendall(bytes.fromhex(f4['raw_frame_hex']))
            time.sleep(0.3)

        print(f"\n👥 Đang gửi tin nhắn Group tới ID: {group_id}...")
        print(f"   ├─ Nội dung: {text!r}")

        self.ack_event.clear()
        self.ack_result["success"] = False
        self.ack_result["err_code"] = None
        self.ack_result["details"] = None
        self.ack_result["receipts"] = []

        seq_id = -16
        cmsg_id = int(time.time() * 1000) & 0xFFFFFFFF
        ck_val = compute_checksum(207, 1, seq_id, self.uid, group_id, 4, cmsg_id)

        d3_plain = build_d3_message_group(text)
        d3_xor = xor_encode_d3(d3_plain, self.uid)
        params_msg = struct.pack('<IBII', group_id, 4, cmsg_id, 416) + d3_xor
        inner_msg = struct.pack('<IBBiIBHB', ck_val, 1, 2, seq_id, self.uid, 3, 207, 1) + params_msg
        raw_frame = build_gcm_frame(inner_msg, self.dk)

        with self.sock_lock:
            self.sock.sendall(raw_frame)

        print(f"   ├─ Đã gửi {len(raw_frame)} bytes qua Socket (CMD 207 SUB 1 | Seq={seq_id} | cmsg=0x{cmsg_id:08x})")
        print(f"   ⏳ Đang chờ xác nhận từ Server Zalo...")

        got_ack = self.ack_event.wait(timeout=timeout)
        time.sleep(0.5)

        if self.ack_result["success"]:
            print(f"\n[✔ THÀNH CÔNG RỰC RỠ] Tin nhắn Group đã được Server Zalo tiếp nhận & chuyển tiếp!")
            if self.ack_result.get("details"):
                d = self.ack_result["details"]
                print(f"   └─ Global Message ID (gmi): {d.get('gmi')}")
                print(f"   └─ Client Message ID (cmi): {d.get('cmi')}")
                print(f"   └─ Số thành viên nhận xác nhận (Receipts): {len(self.ack_result['receipts'])}")
            return True
        else:
            print(f"\n[!] Không nhận được phản hồi ACK trong {timeout}s.")
            return False

    def close(self):
        self.stop_event.set()
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

def main():
    parser = argparse.ArgumentParser(
        description="Zalo Send Socket — Gửi tin nhắn Zalo qua Socket TCP Binary Protocol (Chuẩn 1-1 & Group)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--group", type=int, help="ID Group Zalo đích (ví dụ: 686355764)")
    parser.add_argument("--to", type=int, help="UID người dùng đích (1-1, ví dụ: 445460296)")
    parser.add_argument("--msg", type=str, default="hello from agent", help="Nội dung tin nhắn")
    parser.add_argument("--no-typing", action="store_true", help="Không gửi hiệu ứng Typing trước khi gửi tin")
    parser.add_argument("--zaloprefs", type=str, default="/root/zalo/zaloprefs", help="Đường dẫn database zaloprefs")
    parser.add_argument("--frame0-file", type=str, default="/root/zalo/frame0.bin", help="Đường dẫn file Frame 0 Handshake")
    parser.add_argument("--init-sequence", type=str, default="/root/zalo/init_sequence.json", help="Đường dẫn file Init Sequence")
    parser.add_argument("--server", type=str, default=DEFAULT_HOST, help="Host Socket Server")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port Socket Server")
    parser.add_argument("--keepalive", type=int, default=0, help="Duy trì kết nối thêm N giây sau khi gửi")

    args = parser.parse_args()

    if not args.group and not args.to:
        sys.exit("[!] Bắt buộc phải truyền --to <uid> hoặc --group <id>.")

    p_data = parse_zaloprefs(args.zaloprefs)
    cur_uid = p_data.get('current_uid')
    if not cur_uid or cur_uid not in p_data['users']:
        sys.exit("[!] Không tìm thấy tài khoản người dùng trong zaloprefs.")
    
    uinfo = p_data['users'][cur_uid]
    sender_uid = uinfo['uid']
    dk_bytes = uinfo['dk']
    ck_bytes = uinfo['cryptkey']

    if not os.path.isfile(args.frame0_file):
        sys.exit(f"[!] Không tìm thấy file Frame 0: {args.frame0_file}")
    f0_bytes = open(args.frame0_file, 'rb').read()

    client = ZaloSessionClient(
        host=args.server,
        port=args.port,
        uid=sender_uid,
        dk=dk_bytes,
        cryptkey=ck_bytes,
        f0_bytes=f0_bytes,
        init_frames_path=args.init_sequence
    )

    try:
        client.connect()

        if args.to:
            success = client.send_1to1(args.to, args.msg, typing_first=not args.no_typing)
        elif args.group:
            success = client.send_group(args.group, args.msg, typing_first=not args.no_typing)

        if args.keepalive > 0:
            print(f"\n📡 Đang duy trì kết nối socket thêm {args.keepalive}s...")
            time.sleep(args.keepalive)

        sys.exit(0 if success else 1)
    finally:
        client.close()

if __name__ == '__main__':
    main()
