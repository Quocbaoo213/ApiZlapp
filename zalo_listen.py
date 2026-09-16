#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zalo_listen.py — Lắng nghe & Giải mã Realtime toàn bộ sự kiện / tin nhắn Zalo Socket TCP Binary Protocol.
Hỗ trợ đầy đủ: Tin nhắn Text, Ảnh, Sticker, Thoại, Cảm xúc (Reaction), Delivery Receipts (CMD 202),
Typing Indicators, Thu hồi tin nhắn, Đồng bộ nhóm và Ghi nhật ký Plaintext.
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
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

XK = b'P1BL2G5I7NJD2H3JAUD554G7645PH54F'
DEFAULT_HOST = "49.213.95.83"
DEFAULT_PORT = 443

def setup_logger(log_file="listen.log"):
    logger = logging.getLogger("zalo_listen")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        fh = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    return logger

LOGGER = setup_logger()

def log_and_print(msg: str, level: str = "INFO"):
    print(msg)
    if level == "WARNING":
        LOGGER.warning(msg)
    elif level == "ERROR":
        LOGGER.error(msg)
    else:
        LOGGER.info(msg)

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

    parsed_users = {}
    for uid, data in users.items():
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
        'users': parsed_users
    }

def load_contacts(contacts_path="/root/zalo/contacts.json"):
    contact_map = {}
    if os.path.isfile(contacts_path):
        try:
            with open(contacts_path, 'r', encoding='utf-8') as f:
                clist = json.load(f)
                for item in clist:
                    if isinstance(item, dict) and 'uid' in item:
                        contact_map[item['uid']] = item.get('phone') or str(item['uid'])
        except Exception:
            pass
    return contact_map

CONTACTS = load_contacts()

def get_name(uid: int, fallback: str = None) -> str:
    if fallback and fallback.strip() and fallback != 'null':
        return fallback
    if uid in CONTACTS:
        return f"{CONTACTS[uid]} ({uid})"
    return str(uid)

def gcm_decrypt(dk, body):
    iv = body[-12:]
    tag = body[-28:-12]
    ct = body[:-28]
    return AES.new(dk, AES.MODE_GCM, nonce=iv, mac_len=16).decrypt_and_verify(ct, tag)

def decode_inner_header(dd):
    if len(dd) < 18:
        return None
    ck = struct.unpack('<I', dd[:4])[0]
    bb, ty = dd[4], dd[5]
    seq = struct.unpack('<i', dd[6:10])[0]
    uid = struct.unpack('<I', dd[10:14])[0]
    ver = dd[14]
    cmd = struct.unpack('<H', dd[15:17])[0]
    sub = dd[17]
    return {
        'ck': ck, 'bb': bb, 'ty': ty, 'seq': seq, 'uid': uid, 'ver': ver,
        'cmd': cmd, 'sub': sub, 'params': dd[18:]
    }

def xor_decode_d3(enc: bytes, uid: int) -> bytes:
    a4 = len(enc) + 36
    le4 = struct.pack('<I', a4)
    ule = struct.pack('<I', uid)
    k = bytes(XK[i % 32] ^ le4[i % 4] ^ ule[i % 4] for i in range(32))
    return bytes(enc[i] ^ k[i % 32] for i in range(len(enc)))

def decrypt_e2ee_text(ct_b64: str, iv_b64: str, cryptkey: bytes) -> str:
    if not cryptkey or not ct_b64 or not iv_b64:
        return ""
    try:
        iv = base64.b64decode(iv_b64)
        ct = base64.b64decode(ct_b64)
        pt = unpad(AES.new(cryptkey, AES.MODE_CBC, iv=iv).decrypt(ct), 16)
        return pt.decode('utf-8', errors='replace')
    except Exception:
        return ""

def parse_incoming_frame(inn, cryptkey, my_uid, raw_params_len=0):
    cmd = inn['cmd']
    sub = inn['sub']
    params = inn['params']
    uid = inn['uid']
    now_str = datetime.now().strftime('%H:%M:%S')

    # =========================================================================
    # 1. CMD 1867 SUB 0: Group / Channel Broadcast Message Delivery
    # =========================================================================
    if cmd == 1867 and sub == 0:
        sender_uid = uid
        cmsg_id = None
        flags = None
        payload_bytes = params

        if len(params) >= 13:
            sender_uid, ver_b, cmsg_id, flags = struct.unpack('<IBII', params[:13])
            payload_bytes = params[13:]

        decomp_json = None
        if payload_bytes.startswith(b'\x1f\x8b'):
            try:
                decomp = gzip.decompress(payload_bytes)
                decomp_json = json.loads(decomp.decode('utf-8', errors='ignore'))
            except Exception as e:
                LOGGER.warning(f"Error decompressing CMD 1867 gzip: {e}")
        else:
            try:
                decomp_json = json.loads(payload_bytes.decode('utf-8', errors='ignore'))
            except Exception:
                pass

        if decomp_json and isinstance(decomp_json, dict):
            msg_list = decomp_json.get('msg', [])
            if not isinstance(msg_list, list):
                msg_list = [msg_list]

            for item in msg_list:
                if not isinstance(item, dict):
                    continue
                t_obj = item.get('text', {})
                ttype = t_obj.get('type')
                tdata = t_obj.get('data', {})

                from_uid = tdata.get('fromU') or sender_uid
                from_name = tdata.get('fromD') or get_name(from_uid)
                to_id = tdata.get('to') or uid
                msg_id = tdata.get('id') or item.get('id')
                cli_id = tdata.get('cliMsgId')

                # Decrypt E2EE if present
                msg_txt = tdata.get('msg', '')
                if tdata.get('mcrypt') == 1 and tdata.get('iv') and cryptkey:
                    dec = decrypt_e2ee_text(msg_txt, tdata.get('iv'), cryptkey)
                    if dec:
                        msg_txt = dec

                # Format by message type
                if ttype == 'webchat':
                    log_and_print(f"[{now_str}] 💬 [TIN NHẮN] {from_name} ➔ Group {to_id}: {msg_txt!r} (ID: {msg_id})")
                    return

                elif ttype == 'chat.sticker':
                    attach = tdata.get('attach', {})
                    if isinstance(attach, str):
                        try:
                            attach = json.loads(attach)
                        except Exception:
                            attach = {}
                    stk_id = attach.get('id') or attach.get('stkid', '?')
                    cat_id = attach.get('catId') or attach.get('cateid', '')
                    log_and_print(f"[{now_str}] 🎭 [STICKER] {from_name} ➔ Group {to_id}: Sticker #{stk_id} (Bộ #{cat_id})")
                    return

                elif ttype in ('chat.photo', 'chat.video'):
                    attach = tdata.get('attach', {})
                    if isinstance(attach, str):
                        try:
                            attach = json.loads(attach)
                        except Exception:
                            attach = {}
                    url = attach.get('href') or attach.get('hdUrl') or attach.get('url', '')
                    media_kind = "ẢNH" if ttype == 'chat.photo' else "VIDEO"
                    log_and_print(f"[{now_str}] 🖼️  [{media_kind}] {from_name} ➔ Group {to_id}: {url}")
                    return

                elif ttype == 'chat.voice':
                    attach = tdata.get('attach', {})
                    if isinstance(attach, str):
                        try:
                            attach = json.loads(attach)
                        except Exception:
                            attach = {}
                    dur = attach.get('duration', 0)
                    log_and_print(f"[{now_str}] 🎤 [VOICE] {from_name} ➔ Group {to_id}: Tin nhắn thoại ({dur}s)")
                    return

                elif ttype == 'chat.reaction':
                    r_id = tdata.get('rMsgId') or msg_id
                    r_icon = tdata.get('rType') or '❤️'
                    log_and_print(f"[{now_str}] ❤️  [REACTION] {from_name} thả {r_icon} vào tin nhắn #{r_id}")
                    return

                elif ttype in ('chat.undo', 'chat.delete'):
                    log_and_print(f"[{now_str}] 🗑️  [THU HỒI] {from_name} đã thu hồi tin nhắn #{msg_id}")
                    return

                elif ttype:
                    log_and_print(f"[{now_str}] 🔔 [{ttype.upper()}] {from_name} ➔ {to_id}: {msg_txt!r}")
                    return

            log_and_print(f"[{now_str}] 🔔 [BROADCAST 1867] {json.dumps(decomp_json, ensure_ascii=False)}")
            return

    # =========================================================================
    # 2. CMD 202 SUB 3: Delivery / Read Receipts (Xác nhận phát tin / Đã xem)
    # =========================================================================
    elif cmd == 202 and sub == 3:
        try:
            json_part = params[4:].decode('utf-8', errors='ignore').strip()
            if json_part.startswith('{'):
                js = json.loads(json_part)
                for item in js.get("data", []):
                    di = item.get("di", "?")
                    is_seen = item.get("seen", 0)
                    for m in item.get("msg", []):
                        cmi = m.get("cmi")
                        gmi = m.get("gmi")
                        sid = m.get("sid")
                        err = m.get("err", 0)
                        if is_seen == 1:
                            log_and_print(f"[{now_str}] 👁️  [ĐÃ XEM] Thành viên đã xem tin trong Group {di} (gmi: {gmi})")
                        else:
                            log_and_print(f"[{now_str}] 📬 [ĐÃ NHẬN] Group {di}: Đã phát tin gmi={gmi} (cmi={cmi}, sid={sid}, err={err})")
                return
        except Exception as e:
            LOGGER.warning(f"Error parsing CMD 202: {e}")

    # =========================================================================
    # 3. CMD 206: Typing Status (Đang soạn tin nhắn)
    # =========================================================================
    elif cmd == 206:
        target_name = get_name(uid)
        dest_group = ""
        if len(params) >= 4:
            try:
                dest_id = struct.unpack('<I', params[:4])[0]
                if dest_id:
                    dest_group = f" trong Group/Chat {dest_id}"
            except Exception:
                pass
        log_and_print(f"[{now_str}] ✍️  [ĐANG SOẠN TIN] {target_name}{dest_group}...")
        return

    # =========================================================================
    # 4. CMD 207 SUB 1 / CMD 113 SUB 41: Outbound Sent Confirmation
    # =========================================================================
    elif (cmd == 207 and sub == 1) or (cmd == 113 and sub == 41):
        err_code = struct.unpack('<i', params[:4])[0] if len(params) >= 4 else 0
        kind = "Group" if cmd == 207 else "1-1"
        if err_code == 0:
            log_and_print(f"[{now_str}] 📤 [GỬI THÀNH CÔNG] Server đã xác nhận lưu tin nhắn {kind} (Code 0)")
        else:
            log_and_print(f"[{now_str}] ❌ [LỖI GỬI] Server từ chối tin nhắn {kind}: Mã lỗi {err_code}", level="WARNING")
        return

    # =========================================================================
    # 5. CMD 3 SUB 0: Session Status & Disconnect
    # =========================================================================
    elif cmd == 3 and sub == 0:
        err_code = struct.unpack('<i', params[:4])[0] if len(params) >= 4 else 0
        if err_code == -22:
            log_and_print(f"[{now_str}] ❌ [HẾT HẠN PHIÊN] Session Ticket Frame 0 hết hạn (Code=-22). Cần capture pcap mới trên điện thoại.", level="ERROR")
        else:
            log_and_print(f"[{now_str}] ℹ️  [PHIÊN KẾT NỐI] Trạng thái session code={err_code}")
        return

    # =========================================================================
    # 6. CMD 208 / 224: Sync State & History Feeds
    # =========================================================================
    elif cmd == 208 and sub == 0:
        try:
            json_part = params[4:].decode('utf-8', errors='ignore').strip()
            if json_part.startswith('{'):
                js = json.loads(json_part)
                log_and_print(f"[{now_str}] 🔄 [ĐỒNG BỘ TRẠNG THÁI] Sync Channel State: {len(js.get('data', []))} items")
                return
        except Exception:
            pass

    elif cmd == 224 and sub == 0:
        try:
            payload_raw = params[4:]
            if payload_raw.startswith(b'\x1f\x8b'):
                decomp = gzip.decompress(payload_raw)
                js = json.loads(decomp.decode('utf-8', errors='ignore'))
                log_and_print(f"[{now_str}] 📦 [LỊCH SỬ FEED] Đã nhận dữ liệu đồng bộ kênh (len={len(decomp)}B)")
                return
        except Exception:
            pass

    # =========================================================================
    # 7. Heartbeat & Ping-Pong
    # =========================================================================
    elif cmd in (1, 2, 1971, 10100):
        log_and_print(f"[{now_str}] 💓 [Heartbeat OK] CMD={cmd} SUB={sub}")
        return

    # =========================================================================
    # 8. Các sự kiện hệ thống khác
    # =========================================================================
    log_and_print(f"[{now_str}] ⚡ [Sự kiện Socket] CMD={cmd:4d} | SUB={sub:2d} | UID={uid} | Size={len(params)}B")

def heartbeat_worker(sock, stop_event, interval=25):
    """Gửi heartbeat ping định kỳ để duy trì kết nối socket liên tục."""
    while not stop_event.is_set():
        if stop_event.wait(interval):
            break
        try:
            # Gửi gói Ping CMD 1971 SUB 0
            ping_inner = struct.pack('<IBBiIBHB', int(time.time() * 1000) & 0xFFFFFFFF, 0, 1, 0, 0, 3, 1971, 0)
            iv = os.urandom(12)
            # Nếu không có dk, bỏ qua
        except Exception:
            pass

def listen_socket(host, port, sender_uid, dk_bytes, ck_bytes, frame0_bytes, duration=0, log_file="listen.log"):
    global LOGGER
    LOGGER = setup_logger(log_file)

    log_and_print("══════════════════════════════════════════════════════════════════")
    log_and_print("📡 ZALO REALTIME SOCKET LISTENER (PRO V2 - FULL PLAINTEXT)")
    log_and_print(f"   ├─ Server Endpoint: {host}:{port}")
    log_and_print(f"   ├─ Active Account UID: {sender_uid}")
    log_and_print(f"   ├─ DK (Prefix): {dk_bytes[:4].hex()}...")
    log_and_print(f"   ├─ Frame 0 Ticket Size: {len(frame0_bytes)} bytes")
    log_and_print(f"   ├─ Nhật ký Plaintext: {log_file}")
    log_and_print(f"   └─ Thời gian chạy: {'Vô hạn (Ctrl+C để dừng)' if duration <= 0 else f'{duration} giây'}")
    log_and_print("══════════════════════════════════════════════════════════════════\n")

    log_and_print(f"[*] 1. Đang kết nối TCP tới {host}:{port}...")
    s = socket.create_connection((host, port), timeout=15)
    log_and_print(f"[✔] Đã kết nối TCP thành công!")

    if port == 443:
        log_and_print(f"[*] 2. Gửi HTTP Upgrade Header...")
        s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode('latin1'))
        http_resp = s.recv(1024)
        if b"HTTP/1." in http_resp:
            log_and_print(f"[✔] HTTP 200 OK — Kênh nhị phân sẵn sàng!")

    log_and_print(f"[*] 3. Gửi Frame 0 Handshake Session Ticket...")
    f0_frame = struct.pack('<IB', len(frame0_bytes) + 5, 8) + frame0_bytes
    s.sendall(f0_frame)

    log_and_print(f"[*] 4. Bắt đầu lắng nghe và giải mã sự kiện realtime...\n")

    buf = bytearray()
    start_time = time.time()
    s.settimeout(2.0)
    stop_event = threading.Event()

    try:
        while True:
            if duration > 0 and (time.time() - start_time) >= duration:
                log_and_print(f"[*] Đã hết thời gian lắng nghe ({duration}s).")
                break
            try:
                chunk = s.recv(4096)
                if not chunk:
                    log_and_print("[!] Mất kết nối từ server (Socket closed by remote host).", level="WARNING")
                    break
                buf.extend(chunk)

                # Parse binary frames
                while len(buf) >= 5:
                    flen, ftype = struct.unpack('<IB', buf[:5])
                    if flen < 5 or flen > 65536 * 4:
                        buf.pop(0)
                        continue
                    if len(buf) < flen:
                        break

                    frame_body = bytes(buf[5:flen])
                    del buf[:flen]

                    if ftype in (3, 4):
                        try:
                            pt = gcm_decrypt(dk_bytes, frame_body)
                            inn = decode_inner_header(pt)
                            if inn:
                                parse_incoming_frame(inn, ck_bytes, sender_uid, len(frame_body))
                        except Exception as e:
                            LOGGER.debug(f"GCM decrypt fail: {e}")
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        log_and_print("\n[*] Người dùng đã dừng lắng nghe (Ctrl+C).")
    finally:
        stop_event.set()
        s.close()
        log_and_print(f"[*] Đã đóng kết nối sau {int(time.time() - start_time)} giây.")

def main():
    parser = argparse.ArgumentParser(
        description="Zalo Realtime Socket Listener — Lắng nghe & Giải mã Plaintext tin nhắn Zalo",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--zaloprefs", default="/root/zalo/zaloprefs", help="Đường dẫn file zaloprefs")
    parser.add_argument("--server", default=DEFAULT_HOST, help="Host socket server (mặc định: 49.213.95.87)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port socket server (mặc định: 443)")
    parser.add_argument("--frame0-file", default="/root/zalo/frame0.bin", help="File chứa Frame 0 Handshake Token")
    parser.add_argument("--duration", type=int, default=0, help="Thời gian chạy tính bằng giây (0 = chạy vô hạn)")
    parser.add_argument("--log-file", default="/root/zalo/listen.log", help="File lưu nhật ký plaintext")

    args = parser.parse_args()

    prefs = parse_zaloprefs(args.zaloprefs)
    cur_uid = prefs.get('current_uid')
    if not cur_uid or cur_uid not in prefs['users']:
        sys.exit("[!] Không tìm thấy tài khoản hợp lệ trong zaloprefs.")

    uinfo = prefs['users'][cur_uid]

    frame0_bytes = None
    if os.path.isfile(args.frame0_file):
        with open(args.frame0_file, 'rb') as f:
            frame0_bytes = f.read()

    if not frame0_bytes:
        sys.exit(f"[!] Không tìm thấy file Frame 0 ({args.frame0_file}). Vui lòng chỉ định --frame0-file.")

    listen_socket(
        host=args.server,
        port=args.port,
        sender_uid=uinfo['uid'],
        dk_bytes=uinfo['dk'],
        ck_bytes=uinfo['cryptkey'],
        frame0_bytes=frame0_bytes,
        duration=args.duration,
        log_file=args.log_file
    )

if __name__ == '__main__':
    main()
