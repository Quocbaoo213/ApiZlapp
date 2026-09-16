#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_init_sequence.py — Trích xuất chính xác 64 frame C2S khởi tạo session (seq -2 đến -65)
từ file PCAP capture gốc để nạp và replay trong zalo_send.py.
"""

import json
import os
import struct
import sys
import zalo_re

PCAP_PATH = '/sdcard/Download/PCAPdroid/PCAPdroid_13_thg 9_18_14_46.pcap'
PREFS_PATH = '/root/zalo/zaloprefs'
OUT_BIN = '/root/zalo/init_sequence.bin'
OUT_JSON = '/root/zalo/init_sequence.json'

def main():
    if not os.path.isfile(PCAP_PATH):
        sys.exit(f"[!] Không tìm thấy file PCAP: {PCAP_PATH}")
    if not os.path.isfile(PREFS_PATH):
        sys.exit(f"[!] Không tìm thấy file zaloprefs: {PREFS_PATH}")

    pref_info = zalo_re.parse_zaloprefs(PREFS_PATH)
    current_uid = pref_info['current_uid']
    dk = pref_info['users'][current_uid]['dk']
    print(f"[*] Đang đọc PCAP: {PCAP_PATH} (UID: {current_uid})...")

    flows = zalo_re.parse_network_capture(PCAP_PATH)
    c2s_frames = []

    for key, buf in flows:
        src, sport, dst, dport = key
        if dport in (443, 8080, 8081):
            raw_frames = list(zalo_re.parse_socket_frames(zalo_re.strip_http_handshake(buf)))
            if len(raw_frames) > 20:
                print(f"[✔] Tìm thấy luồng C2S Socket gồm {len(raw_frames)} frames.")
                for idx, (ftype, body) in enumerate(raw_frames):
                    try:
                        dec = zalo_re.gcm_decrypt_body(dk, body)
                        ck, bb, ty, seq, uid, ver, cmd, sub = struct.unpack('<IBBiIBHB', dec[:18])
                        params = dec[18:]
                        c2s_frames.append({
                            'idx': idx,
                            'ftype': ftype,
                            'raw_body_hex': body.hex(),
                            'dec_hex': dec.hex(),
                            'ck': ck,
                            'bb': bb,
                            'ty': ty,
                            'seq': seq,
                            'uid': uid,
                            'ver': ver,
                            'cmd': cmd,
                            'sub': sub,
                            'params_hex': params.hex()
                        })
                    except Exception:
                        pass

    init_frames = [f for f in c2s_frames if -65 <= f['seq'] <= -2]
    init_frames.sort(key=lambda x: -x['seq']) # Sort from -2 down to -65

    if len(init_frames) < 64:
        raise RuntimeError(f"Chỉ trích xuất được {len(init_frames)}/64 frames init! Thiếu dữ liệu trong capture.")

    print(f"[✔] Trích xuất thành công ĐỦ {len(init_frames)} frame khởi tạo (seq -2 -> -65).")

    # Ghi ra file json
    with open(OUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(init_frames, f, indent=2)
    print(f"[✔] Đã lưu thông tin chi tiết vào: {OUT_JSON}")

    # Ghi ra file bin dạng: [uint32 len_body][uint8 type][body_bytes]
    with open(OUT_BIN, 'wb') as f:
        for fr in init_frames:
            body = bytes.fromhex(fr['raw_body_hex'])
            ftype = fr['ftype']
            # Header: uint32 len (body + 5), uint8 type
            f.write(struct.pack('<IB', len(body) + 5, ftype) + body)

    print(f"[✔] Đã đóng gói file nhị phân: {OUT_BIN} ({os.path.getsize(OUT_BIN)} bytes)")

if __name__ == '__main__':
    main()
