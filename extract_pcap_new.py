#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_pcap_new.py — Extract Frame 0 & toàn bộ C2S frames từ PCAP mới (PCAPdroid_13_thg 9_19_56_02.pcap)
"""

import json
import os
import struct
import sys
import time
import glob
import zalo_re

PREFS_PATH = '/root/zalo/zaloprefs'
FRAME0_OUT = '/root/zalo/frame0.bin'
INIT_JSON_OUT = '/root/zalo/init_sequence.json'

def get_latest_pcap():
    candidates = glob.glob('/sdcard/Download/PCAPdroid/*.pcap') + glob.glob('/root/zalo/*.pcap')
    if not candidates:
        return '/root/zalo/PCAPdroid_13_thg 9_21_40_50.pcap'
    return max(candidates, key=os.path.getmtime)

PCAP_PATH = get_latest_pcap()

def main():
    if not os.path.isfile(PCAP_PATH):
        sys.exit(f"[!] Không tìm thấy file PCAP: {PCAP_PATH}")

    mtime = os.path.getmtime(PCAP_PATH)
    mtime_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))
    size = os.path.getsize(PCAP_PATH)
    print(f"=== BƯỚC 1: File PCAP Mới Nhất ===")
    print(f"Đường dẫn: {PCAP_PATH}")
    print(f"Mtime: {mtime_str} ({time.time() - mtime:.1f}s ago)")
    print(f"Kích thước: {size:,} bytes")

    pref_info = zalo_re.parse_zaloprefs(PREFS_PATH)
    uid = pref_info['current_uid']
    dk = pref_info['users'][uid]['dk']
    print(f"UID: {uid}, DK Prefix: {dk[:4].hex()}")

    flows = zalo_re.parse_network_capture(PCAP_PATH)
    c2s_frames = []
    frame0_bytes = None
    server_host = '49.213.95.83'
    server_port = 443

    for key, buf in flows:
        src, sport, dst, dport = key
        if dport in (443, 8080, 8081):
            raw_frames = list(zalo_re.parse_socket_frames(zalo_re.strip_http_handshake(buf)))
            if len(raw_frames) > 5:
                server_host = dst
                server_port = dport
                print(f"[✔] Tìm thấy luồng C2S: {src}:{sport} -> {dst}:{dport} ({len(raw_frames)} frames)")
                for idx, (ftype, body) in enumerate(raw_frames):
                    raw_frame_full = struct.pack('<IB', len(body) + 5, ftype) + body
                    if idx == 0 and ftype == 8:
                        frame0_bytes = body
                        c2s_frames.append({
                            'idx': idx,
                            'dir': 'C2S',
                            'ftype': ftype,
                            'seq': -1,
                            'cmd': 0,
                            'sub': 0,
                            'ty': 0,
                            'uid': int(uid),
                            'ck': 0,
                            'raw_frame_hex': raw_frame_full.hex(),
                            'raw_body_hex': body.hex(),
                            'decrypted_inner_hex': '',
                            'params_hex': ''
                        })
                    else:
                        try:
                            dec = zalo_re.gcm_decrypt_body(dk, body)
                            ck_val, bb, ty, seq, flow_uid, ver, cmd, sub = struct.unpack('<IBBiIBHB', dec[:18])
                            params = dec[18:]
                            c2s_frames.append({
                                'idx': idx,
                                'dir': 'C2S',
                                'ftype': ftype,
                                'seq': seq,
                                'cmd': cmd,
                                'sub': sub,
                                'ty': ty,
                                'uid': flow_uid,
                                'ck': ck_val,
                                'ck_hex': f"0x{ck_val:08x}",
                                'raw_frame_hex': raw_frame_full.hex(),
                                'raw_body_hex': body.hex(),
                                'decrypted_inner_hex': dec.hex(),
                                'params_hex': params.hex()
                            })
                        except Exception as e:
                            print(f"[!] Lỗi giải mã frame #{idx}: {e}")

    print(f"\n=== BƯỚC 2: Phân loại {len(c2s_frames)} frames C2S ===")
    for f in c2s_frames:
        print(f"  Frame #{f['idx']:02d}: Type={f['ftype']} Seq={f['seq']:4d} CMD={f['cmd']:4d} SUB={f['sub']:2d} ck={f.get('ck_hex','0')} Len={len(f['raw_body_hex'])//2:3d}B")

    # BƯỚC 3: Ghi Frame 0 binary
    if frame0_bytes:
        with open(FRAME0_OUT, 'wb') as f:
            f.write(frame0_bytes)
        print(f"\n=== BƯỚC 3: Frame 0 Binary ===")
        print(f"[✔] Đã ghi {len(frame0_bytes)} bytes vào {FRAME0_OUT}")
        print(f"    Hex: {frame0_bytes.hex()}")

    # BƯỚC 4: Ghi init_sequence.json
    first_msg_idx = next((i for i, f in enumerate(c2s_frames) if f['cmd'] == 207 and f['sub'] == 1), None)
    base_cmsg = None
    base_ck = None
    first_msg_seq = -7
    if first_msg_idx is not None:
        params = bytes.fromhex(c2s_frames[first_msg_idx]['params_hex'])
        d3_xor = params[13:]
        d3_plain = zalo_re.xor_decode_d3(d3_xor, int(uid))
        d3_payload_hex = d3_plain.hex()
        base_ck = c2s_frames[first_msg_idx].get('ck')
        first_msg_seq = c2s_frames[first_msg_idx].get('seq', -7)
        if len(params) >= 13:
            _, _, base_cmsg, _ = struct.unpack('<IBII', params[:13])
        print(f"\n=== BƯỚC 4: Metadata CMD 207 (Idx={first_msg_idx}) ===")
        print(f"D3 Plain Hex: {d3_payload_hex}")
        print(f"D3 Plain: {d3_plain}")
        print(f"Base cmsg_id: 0x{base_cmsg:08x} ({base_cmsg})" if base_cmsg else "")
        print(f"Base ck_val:  0x{base_ck:08x} ({base_ck})" if base_ck else "")

    metadata = {
        'capture_file': PCAP_PATH,
        'capture_time_mtime': mtime,
        'sender_uid': int(uid),
        'server_host': server_host,
        'server_port': server_port,
        'total_c2s_frames': len(c2s_frames),
        'first_message_idx': first_msg_idx,
        'first_message_seq': first_msg_seq,
        'base_cmsg_id': base_cmsg,
        'base_ck_val': base_ck,
        'target_group_id': 686355764,
        'd3_payload_hex': d3_payload_hex,
        'frames': c2s_frames
    }

    with open(INIT_JSON_OUT, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)
    print(f"[✔] Đã lưu {INIT_JSON_OUT}")

if __name__ == '__main__':
    main()
