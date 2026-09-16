#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zalo_re.py — Công cụ RE & Giải mã TOÀN BỘ Network Traffic (.pcap, .pcapng) và HTTP API (.har) Zalo Mobile.
"""

import argparse
import base64
import gzip
import json
import os
import re
import sqlite3
import struct
import sys
import time
import urllib.parse
from collections import Counter

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Util.Padding import unpad
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding

        class _AESWrapper:
            MODE_GCM = 'GCM'
            MODE_CBC = 'CBC'
            def __init__(self, key, mode, nonce=None, iv=None, mac_len=16):
                self.key = key
                self.mode = mode
                self.nonce = nonce or iv
                self.mac_len = mac_len

            @staticmethod
            def new(key, mode, nonce=None, iv=None, mac_len=16):
                return _AESWrapper(key, mode, nonce=nonce, iv=iv, mac_len=mac_len)

            def decrypt_and_verify(self, ct, tag):
                dec = Cipher(algorithms.AES(self.key), modes.GCM(self.nonce, tag)).decryptor()
                return dec.update(ct) + dec.finalize()

            def decrypt(self, ct):
                dec = Cipher(algorithms.AES(self.key), modes.CBC(self.nonce)).decryptor()
                return dec.update(ct) + dec.finalize()

        AES = _AESWrapper

        def unpad(data, block_size):
            unpadder = padding.PKCS7(block_size * 8).unpadder()
            return unpadder.update(data) + unpadder.finalize()

XK = b'P1BL2G5I7NJD2H3JAUD554G7645PH54F'
CRLF_CRLF = bytes([13, 10, 13, 10])

DEFAULT_PREFS_PATHS = [
    'zaloprefs',
    '/sdcard/download/zaloprefs',
    '/sdcard/Download/zaloprefs',
    '/sdcard/download/zalo/zaloprefs',
    '/sdcard/Download/Zalo/zaloprefs',
    '/root/zalo/zaloprefs',
    '/data/user/0/com.zing.zalo/databases/zaloprefs'
]

DEFAULT_ZCID_PATHS = [
    'zalo_zcid.txt',
    '/sdcard/download/zalo/zalo_zcid.txt',
    '/sdcard/Download/Zalo/zalo_zcid.txt',
    '/root/zalo/zalo_zcid.txt'
]

def parse_zaloprefs(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Không tìm thấy file zaloprefs: {path}")

    db = sqlite3.connect(path)
    cur = db.cursor()
    users = {}
    current_uid = None

    try:
        rows = cur.execute("SELECT key, value FROM prefs_v2").fetchall()
    except Exception as e:
        db.close()
        raise RuntimeError(f"Lỗi đọc bảng prefs_v2 từ {path}: {e}")

    db.close()

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

        m_vk = re.match(r'CLOUD_VIEWER_KEY_(\d+)', k)
        if m_vk:
            uid = m_vk.group(1)
            users.setdefault(uid, {})['ViewerKey'] = str(v)
            continue

        m_pk = re.match(r'KEY_LONG_SOCKET_AUTHEN_V3_(PRIVATE|PUBLIC)_KEY_(\d+)', k)
        if m_pk:
            kind, uid = m_pk.group(1), m_pk.group(2)
            users.setdefault(uid, {})[f'SocketAuth_{kind}'] = str(v)
            continue

        if k == 'sessionKey':
            users.setdefault('_global', {})['sessionKey'] = str(v)
        elif k == 'token':
            users.setdefault('_global', {})['token'] = str(v)
        elif k == 'sign':
            users.setdefault('_global', {})['sign'] = str(v)

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
            'dk_hex': dk_bytes.hex() if dk_bytes else '',
            'cryptkey': ck_bytes,
            'cryptkey_b64': data.get('CryptKey', ''),
            'viewerKey': data.get('ViewerKey', ''),
            'raw': data
        }

    return {
        'current_uid': current_uid,
        'users': parsed_users,
        'global': users.get('_global', {})
    }

def find_default_zaloprefs():
    for p in DEFAULT_PREFS_PATHS:
        if os.path.isfile(p):
            return p
    return None

def find_default_zcid():
    for p in DEFAULT_ZCID_PATHS:
        if os.path.isfile(p):
            try:
                txt = open(p, 'r', encoding='utf-8', errors='ignore').read().strip()
                if len(txt) >= 96:
                    return txt
            except Exception:
                pass
    return None

def parse_pcap_packets(data):
    magic = struct.unpack('<I', data[:4])[0]
    if magic in (0xa1b2c3d4, 0xa1b23c4d):
        endian = '<'
        ts_div = 1e6 if magic == 0xa1b2c3d4 else 1e9
    elif magic in (0xd4c3b2a1, 0x4d3cb2a1):
        endian = '>'
        ts_div = 1e6 if magic == 0xd4c3b2a1 else 1e9
    else:
        raise ValueError(f"Không phải định dạng PCAP hợp lệ (magic: {hex(magic)})")

    vmaj, vmin, tz, sig, snaplen, linktype = struct.unpack(endian + 'HHIIII', data[4:24])
    off = 24
    pkts = []
    data_len = len(data)

    while off + 16 <= data_len:
        ts_sec, ts_sub, incl_len, orig_len = struct.unpack(endian + 'IIII', data[off:off+16])
        pkt = data[off+16:off+16+incl_len]
        off += 16 + incl_len
        ts = ts_sec + (ts_sub / ts_div)
        pkts.append((ts, pkt, linktype))

    return pkts

def parse_pcapng_packets(data):
    bom = struct.unpack('<I', data[8:12])[0]
    endian = '<' if bom == 0x1a2b3c4d else '>'
    off = 0
    pkts = []
    interfaces = []
    data_len = len(data)

    while off + 12 <= data_len:
        btype, blen = struct.unpack(endian + 'II', data[off:off+8])
        if blen < 12 or off + blen > data_len:
            break
        body = data[off+8:off+blen-4]
        if btype == 0x00000001:
            lt = struct.unpack(endian + 'H', body[:2])[0]
            interfaces.append(lt)
        elif btype == 0x00000006:
            ifid, ts_hi, ts_lo, cap, orig = struct.unpack(endian + 'IIIII', body[:20])
            pkt = body[20:20+cap]
            ts = ((ts_hi << 32) | ts_lo) / 1e6
            lt = interfaces[ifid] if ifid < len(interfaces) else 1
            pkts.append((ts, pkt, lt))
        elif btype == 0x00000003:
            orig = struct.unpack(endian + 'I', body[:4])[0]
            pkt = body[4:4+min(orig, len(body)-4)]
            lt = interfaces[0] if interfaces else 1
            pkts.append((0.0, pkt, lt))
        off += blen

    return pkts

def parse_network_capture(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Không tìm thấy file capture: {path}")

    with open(path, 'rb') as f:
        data = f.read()

    if len(data) < 24:
        raise ValueError(f"File quá nhỏ hoặc rỗng: {path}")

    magic = data[:4]
    if magic == bytes([0x0a, 0x0d, 0x0d, 0x0a]):
        pkts = parse_pcapng_packets(data)
    elif struct.unpack('<I', magic)[0] in (0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1):
        pkts = parse_pcap_packets(data)
    else:
        raise ValueError(f"Định dạng không được hỗ trợ (magic: {magic.hex()})")

    segs = []
    for ts, pkt, linktype in pkts:
        if linktype == 1:
            if len(pkt) < 14 + 20:
                continue
            eth_type = struct.unpack('>H', pkt[12:14])[0]
            if eth_type != 0x0800:
                continue
            ip = pkt[14:]
        elif linktype in (101, 12, 228):
            ip = pkt
        elif linktype == 113:
            if len(pkt) < 16 + 20:
                continue
            ip = pkt[16:]
        elif linktype == 276:
            if len(pkt) < 20 + 20:
                continue
            ip = pkt[20:]
        else:
            ip = pkt[14:] if len(pkt) > 34 else pkt

        if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 6:
            continue

        ihl = (ip[0] & 0x0f) * 4
        ip_tot = struct.unpack('>H', ip[2:4])[0]
        src = '.'.join(str(b) for b in ip[12:16])
        dst = '.'.join(str(b) for b in ip[16:20])
        tcp = ip[ihl:]
        if len(tcp) < 20:
            continue

        sport, dport = struct.unpack('>HH', tcp[:4])
        seq = struct.unpack('>I', tcp[4:8])[0]
        doff = (tcp[12] >> 4) * 4

        tcp_len = ip_tot - ihl - doff
        if tcp_len > 0 and len(tcp) >= doff + tcp_len:
            payload = tcp[doff:doff+tcp_len]
            segs.append((ts, src, dst, sport, dport, seq, payload))

    flows = {}
    for ts, src, dst, sport, dport, seq, payload in segs:
        key = (src, sport, dst, dport)
        flows.setdefault(key, {})[seq] = (ts, payload)

    assembled_flows = []
    for key, d in flows.items():
        seqs = sorted(d)
        buf, base = b'', seqs[0]
        for s in seqs:
            ts, pl = d[s]
            if s < base:
                continue
            gap = s - (base + len(buf))
            if gap > 0:
                buf += bytes([0]) * min(gap, 65536)
            buf += pl
        assembled_flows.append((key, buf))

    return assembled_flows

def strip_http_handshake(buf):
    i = buf.find(CRLF_CRLF)
    if i >= 0 and buf[:4] in (b'GET ', b'GET/', b'POST', b'CONN', b'PUT ', b'HEAD', b'HTTP'):
        return buf[i+4:]
    return buf

def parse_socket_frames(buf):
    off = 0
    buf_len = len(buf)
    while off + 5 <= buf_len:
        tot = int.from_bytes(buf[off:off+4], 'little')
        if tot < 5 or off + tot > buf_len:
            break
        yield buf[off+4], buf[off+5:off+tot]
        off += tot

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

def xor_decode_d3(enc, uid):
    a4 = len(enc) + 36
    le4 = struct.pack('<I', a4)
    ule = struct.pack('<I', uid)
    k = bytes(XK[i % 32] ^ le4[i % 4] ^ ule[i % 4] for i in range(32))
    return bytes(enc[i] ^ k[i % 32] for i in range(len(enc)))

def analyze_d3_message(d3, cryptkey=None):
    out = {'raw_hex': d3.hex()}
    if len(d3) < 5:
        return out

    hdr = d3[:5]
    if hdr[:2] == bytes([0x29, 0x00]) or hdr[0] == 0x29:
        if len(d3) >= 3:
            out['count'] = d3[2]
        if len(d3) >= 5:
            out['fmt'] = f"{d3[3]:02x}{d3[4]:02x}"

    if d3[:3] in (bytes([0x29, 0x00, 0x01]), bytes([0x29, 0x00, 0x02])) and len(d3) >= 21 and d3[3] == 0x07:
        size, color, typ = struct.unpack('<iii', d3[5:17])
        jlen = struct.unpack('<I', d3[17:21])[0]
        out.update({'size': size, 'color': color, 'type': typ})
        try:
            out['prop_json'] = json.loads(d3[21:21+jlen].decode('utf-8'))
        except Exception:
            out['prop_json'] = d3[21:21+jlen].decode('utf-8', errors='replace')

        tail = d3[21+jlen:]
        p = 0
        while p < len(tail):
            t = tail[p]
            if t == 0x01 and cryptkey and p + 19 <= len(tail):
                iv = tail[p+1:p+17]
                ctlen = struct.unpack('<H', tail[p+17:p+19])[0]
                if p + 19 + ctlen <= len(tail):
                    ct = tail[p+19:p+19+ctlen]
                    try:
                        pt = unpad(AES.new(cryptkey, AES.MODE_CBC, iv=iv).decrypt(ct), 16)
                        out['text'] = pt.decode('utf-8', errors='replace')
                        p += 19 + ctlen
                        continue
                    except Exception as e:
                        out['aes_err'] = str(e)
            elif t == 0x08 and p + 9 <= len(tail):
                out['ttl_ms'] = struct.unpack('<I', tail[p+1:p+5])[0]
                p += 9
                continue
            elif t == 0x0f and p + 5 <= len(tail):
                slen = struct.unpack('<I', tail[p+1:p+5])[0]
                if p + 5 + slen <= len(tail):
                    try:
                        out['styles'] = json.loads(tail[p+5:p+5+slen].decode('utf-8'))
                    except Exception:
                        out['styles_raw'] = tail[p+5:p+5+slen].hex()
                    p += 5 + slen
                    continue
            p += 1

    elif d3[:2] == bytes([0x29, 0x00]) and len(d3) >= 12 and d3[2] == 0x04:
        p = 8
        try:
            n1 = struct.unpack('<I', d3[p:p+4])[0]
            out['fw_meta'] = d3[p+4:p+4+n1].decode('utf-8', errors='replace')
            p += 4 + n1
            if p < len(d3) and d3[p] == 0x06:
                n2 = struct.unpack('<I', d3[p+1:p+5])[0]
                out['fw_info'] = json.loads(gzip.decompress(d3[p+5:p+5+n2]))
                p += 5 + n2
            if p + 2 <= len(d3) and d3[p:p+2] == bytes([0x07, 0x00]):
                q = p + 2
                out['size'] = struct.unpack('<i', d3[q:q+4])[0]
                out['color_x'] = struct.unpack('<I', d3[q+4:q+8])[0]
                out['type'] = struct.unpack('<i', d3[q+8:q+12])[0]
                jlen = struct.unpack('<I', d3[q+12:q+16])[0]
                out['prop_json'] = json.loads(d3[q+16:q+16+jlen].decode('utf-8', errors='replace'))
                q += 16 + jlen
                if q < len(d3) and d3[q] == 0x0f:
                    slen = struct.unpack('<I', d3[q+1:q+5])[0]
                    out['styles'] = json.loads(d3[q+5:q+5+slen].decode('utf-8', errors='replace'))
                    q += 5 + slen
                if q < len(d3) and d3[q] == 0x01 and cryptkey:
                    iv, ctlen = d3[q+1:q+17], struct.unpack('<H', d3[q+17:q+19])[0]
                    ct = d3[q+19:q+19+ctlen]
                    pt = unpad(AES.new(cryptkey, AES.MODE_CBC, iv=iv).decrypt(ct), 16)
                    out['text'] = pt.decode('utf-8', errors='replace')
        except Exception as e:
            out['parse_err'] = str(e)

    return out

def try_decompress_payload(params, peer_uids):
    gi = params.find(bytes([0x1f, 0x8b]))
    if gi >= 0:
        try:
            decomp = gzip.decompress(params[gi:])
            try:
                return json.loads(decomp)
            except Exception:
                return decomp.decode('utf-8', errors='replace')
        except Exception:
            pass

    for peer in peer_uids:
        for so in [0, 4, 8, 9, 13, 14, 18]:
            if so >= len(params):
                continue
            seg = params[so:]
            a4 = len(seg) + 36
            le4 = struct.pack('<I', a4)
            ule = struct.pack('<I', peer)
            k1 = bytes(XK[i % 32] ^ le4[i % 4] ^ ule[i % 4] for i in range(32))
            key = bytes(k1[i % 32] ^ ule[i % 4] for i in range(32))
            dec = bytes(seg[i] ^ key[i % 32] for i in range(len(seg)))
            gi = dec.find(bytes([0x1f, 0x8b]))
            if gi >= 0:
                try:
                    decomp = gzip.decompress(dec[gi:])
                    try:
                        return json.loads(decomp)
                    except Exception:
                        return decomp.decode('utf-8', errors='replace')
                except Exception:
                    pass
            if dec.startswith(b'{') or dec.startswith(b'['):
                try:
                    return json.loads(dec.decode('utf-8'))
                except Exception:
                    pass

    for so in range(0, min(10, len(params))):
        if params[so:].startswith(b'{') or params[so:].startswith(b'['):
            try:
                return json.loads(params[so:].decode('utf-8'))
            except Exception:
                pass

    return None

def decrypt_nested_messages(obj, cryptkey):
    if isinstance(obj, dict):
        if obj.get('mcrypt') == 1 and obj.get('iv') and obj.get('msg') and cryptkey:
            try:
                iv_b = base64.b64decode(obj['iv'])
                ct_b = base64.b64decode(obj['msg'])
                pt = unpad(AES.new(cryptkey, AES.MODE_CBC, iv=iv_b).decrypt(ct_b), 16)
                obj['decrypted_text'] = pt.decode('utf-8', errors='replace')
            except Exception as e:
                obj['decrypt_err'] = str(e)
        for v in obj.values():
            decrypt_nested_messages(v, cryptkey)
    elif isinstance(obj, list):
        for item in obj:
            decrypt_nested_messages(item, cryptkey)

def gcm_decrypt_body(key, body):
    iv, tag, ct = body[-12:], body[-28:-12], body[:-28]
    return AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=16).decrypt_and_verify(ct, tag)

def format_chat_event(ev):
    kind = ev['kind']
    sender = ev.get('sender', '?')
    recipient = ev.get('recipient', '?')
    ts = ev.get('ts')
    ts_str = time.strftime('%H:%M:%S', time.localtime(ts/1000)) if ts and ts > 1e11 else '--:--:--'

    if kind == 'TEXT_OUT':
        ttl_str = f" [⏱ TTL: {ev.get('ttl_ms')}ms]" if ev.get('ttl_ms') else ""
        return f"[{ts_str}] 📤 {sender} ➔ {recipient}: {ev.get('text')!r}{ttl_str}"
    elif kind == 'CHAT_MSG':
        return f"[{ts_str}] 💬 {sender} ➔ {recipient}: {ev.get('text')!r}"
    elif kind == 'PHOTO':
        cap = f" {ev.get('caption')!r}" if ev.get('caption') else ""
        url = ev.get('url', '')
        return f"[{ts_str}] 📷 {sender} ➔ {recipient}: [ẢNH]{cap} ➔ {url}"
    elif kind == 'STICKER':
        return f"[{ts_str}] 🎭 {sender} ➔ {recipient}: [STICKER cat={ev.get('catId')} id={ev.get('stickerId')}]"
    elif kind == 'REACTION':
        icon = ev.get('icon', '❤️')
        t_id = ev.get('targetMsgId', '?')
        return f"[{ts_str}] ❤️  {sender} ➔ {recipient}: Thả cảm xúc {icon} vào tin nhắn #{t_id}"
    elif kind == 'DELETE':
        d_id = ev.get('deletedMsgId', '?')
        return f"[{ts_str}] 🗑️  {sender} ➔ {recipient}: Thu hồi tin nhắn #{d_id}"
    elif kind == 'VIDEO':
        title = ev.get('title', '')
        url = ev.get('url', '')
        return f"[{ts_str}] 🎥 {sender} ➔ {recipient}: [VIDEO] {title!r} ➔ {url}"
    else:
        return f"[{ts_str}] ⚡ {kind}: {ev}"

def run_pcap_pipeline(args, dks_map, default_uid, cryptkeys_map):
    print(f"\n📂 [PCAP] Đang phân tích file capture: {args.pcap}")
    flows = parse_network_capture(args.pcap)
    print(f"[*] Tìm thấy {len(flows)} TCP flows.")

    matched_flows = []
    for key, buf in flows:
        b = strip_http_handshake(buf)
        if len(b) < 30:
            continue

        best_uid = None
        best_dk = None
        best_ok = 0
        total_tried = 0

        for uid_str, dk_bytes in dks_map.items():
            ok = 0
            tried = 0
            for t, body in parse_socket_frames(b):
                try:
                    gcm_decrypt_body(dk_bytes, body)
                    ok += 1
                except Exception:
                    pass
                tried += 1
                if tried >= 10:
                    break
            if ok > best_ok:
                best_ok = ok
                best_uid = uid_str
                best_dk = dk_bytes
            total_tried = max(total_tried, tried)

        if best_ok > 0:
            src, sport, dst, dport = key
            direction = 'C2S' if dport in (443, 8080, 8081) else 'S2C'
            matched_flows.append({
                'key': key,
                'buf': b,
                'direction': direction,
                'uid': best_uid,
                'dk': best_dk,
                'ok': best_ok,
                'tried': total_tried
            })

    if not matched_flows:
        print("[!] Không tìm thấy luồng Zalo Socket hoặc DK không khớp với traffic.")
        return []

    for m in matched_flows:
        k = m['key']
        print(f"  ➜ Flow {k[0]}:{k[1]} -> {k[2]}:{k[3]} [{m['direction']}] (UID: {m['uid']}) test {m['ok']}/{m['tried']} frames OK")

    results = []
    chat_events = []
    n_ok = n_fail = 0

    for m in matched_flows:
        buf = m['buf']
        dk = m['dk']
        direction = m['direction']
        flow_uid = int(m['uid']) if m['uid'].isdigit() else default_uid
        ckey = cryptkeys_map.get(m['uid']) or cryptkeys_map.get(str(default_uid))

        peer_uids = {flow_uid, 0, default_uid}

        for t, body in parse_socket_frames(buf):
            try:
                dd = gcm_decrypt_body(dk, body)
                n_ok += 1
            except Exception:
                n_fail += 1
                continue

            inn = decode_inner_header(dd)
            if not inn:
                results.append({'dir': direction, 'type': t, 'raw_hex': dd.hex()})
                continue

            peer_uids.add(inn['uid'])
            rec = {
                'dir': direction,
                'type': t,
                'cmd': inn['cmd'],
                'sub': inn['sub'],
                'ty': inn['ty'],
                'seq': inn['seq'],
                'uid': inn['uid'],
                'payload_len': len(inn['params'])
            }

            params = inn['params']

            if inn['cmd'] == 113 and inn['sub'] == 41:
                d3_raw = params[13:] if len(params) > 13 else params
                if d3_raw:
                    d3_dec = xor_decode_d3(d3_raw, flow_uid)
                    d3_info = analyze_d3_message(d3_dec, ckey)
                    rec['d3'] = d3_info
                    if 'text' in d3_info:
                        rec['text'] = d3_info['text']
                        chat_events.append({
                            'kind': 'TEXT_OUT',
                            'sender': str(flow_uid),
                            'recipient': str(inn['uid']) if inn['uid'] != flow_uid else 'peer',
                            'text': d3_info['text'],
                            'ttl_ms': d3_info.get('ttl_ms', 0),
                            'ts': int(time.time() * 1000),
                            'styles': d3_info.get('styles'),
                            'prop_json': d3_info.get('prop_json')
                        })

            decomp_data = try_decompress_payload(params, peer_uids)
            if decomp_data is not None:
                if isinstance(decomp_data, (dict, list)):
                    decrypt_nested_messages(decomp_data, ckey)
                rec['payload_decoded'] = decomp_data

                if isinstance(decomp_data, dict) and 'msg' in decomp_data:
                    for item in decomp_data['msg']:
                        t_obj = item.get('text', {})
                        ttype = t_obj.get('type')
                        tdata = t_obj.get('data', {})
                        sender_name = tdata.get('fromD') or str(tdata.get('fromU', '?'))
                        recipient_id = str(tdata.get('to', '?'))
                        ts_val = tdata.get('ts') or (tdata.get('time', 0) * 1000)

                        msg_txt = tdata.get('decrypted_text') or tdata.get('msg', '')
                        att_obj = tdata.get('attach') or {}
                        if isinstance(att_obj, str):
                            try:
                                att_obj = json.loads(att_obj)
                            except Exception:
                                att_obj = {}

                        if ttype == 'webchat':
                            chat_events.append({
                                'kind': 'CHAT_MSG',
                                'sender': sender_name,
                                'sender_uid': tdata.get('fromU'),
                                'recipient': recipient_id,
                                'text': msg_txt,
                                'ts': ts_val,
                                'msg_id': tdata.get('id'),
                                'raw': tdata
                            })
                        elif ttype == 'chat.photo':
                            chat_events.append({
                                'kind': 'PHOTO',
                                'sender': sender_name,
                                'sender_uid': tdata.get('fromU'),
                                'recipient': recipient_id,
                                'caption': att_obj.get('title') or msg_txt,
                                'url': att_obj.get('href', ''),
                                'thumb': att_obj.get('thumb', ''),
                                'ts': ts_val,
                                'msg_id': tdata.get('id'),
                                'raw': tdata
                            })
                        elif ttype == 'chat.sticker':
                            chat_events.append({
                                'kind': 'STICKER',
                                'sender': sender_name,
                                'sender_uid': tdata.get('fromU'),
                                'recipient': recipient_id,
                                'stickerId': att_obj.get('id'),
                                'catId': att_obj.get('catId'),
                                'ts': ts_val,
                                'msg_id': tdata.get('id'),
                                'raw': tdata
                            })
                        elif ttype == 'chat.reaction':
                            r_params = att_obj.get('params') or {}
                            if isinstance(r_params, str):
                                try:
                                    r_params = json.loads(r_params)
                                except Exception:
                                    r_params = {}
                            r_msg_arr = r_params.get('rMsg') or [{}]
                            chat_events.append({
                                'kind': 'REACTION',
                                'sender': sender_name,
                                'sender_uid': tdata.get('fromU'),
                                'recipient': recipient_id,
                                'icon': r_params.get('rIcon', '❤️'),
                                'rType': r_params.get('rType'),
                                'targetMsgId': r_msg_arr[0].get('gMsgID'),
                                'ts': ts_val,
                                'raw': tdata
                            })
                        elif ttype == 'chat.delete':
                            del_contents = (att_obj.get('contents') or [{}])[0]
                            chat_events.append({
                                'kind': 'DELETE',
                                'sender': sender_name,
                                'sender_uid': tdata.get('fromU'),
                                'recipient': recipient_id,
                                'deletedMsgId': del_contents.get('globalDelMsgId'),
                                'ts': ts_val,
                                'raw': tdata
                            })
                        elif ttype == 'chat.video.msg':
                            chat_events.append({
                                'kind': 'VIDEO',
                                'sender': sender_name,
                                'sender_uid': tdata.get('fromU'),
                                'recipient': recipient_id,
                                'title': att_obj.get('title', ''),
                                'url': att_obj.get('href', ''),
                                'thumb': att_obj.get('thumb', ''),
                                'ts': ts_val,
                                'msg_id': tdata.get('id'),
                                'raw': tdata
                            })

            results.append(rec)

    print(f"\n[✔] Giải mã Socket hoàn tất: {n_ok} frames OK, {n_fail} frames fail.")

    cnt = Counter((r.get('dir'), r.get('cmd'), r.get('sub')) for r in results if 'cmd' in r)
    print("\n╔═══════════════════════════════════════════════════════╗")
    print("║               BẢNG THỐNG KÊ LỆNH SOCKET               ║")
    print("╠══════════╦═══════════════╦═══════════════╦════════════╣")
    print("║ Chiều    ║ CMD           ║ SUB           ║ Số lượng   ║")
    print("╠══════════╬═══════════════╬═══════════════╬════════════╣")
    for (d, c, s), n in sorted(cnt.items()):
        print(f"║ {d:<8} ║ {c:<13} ║ {s:<13} ║ {n:<10} ║")
    print("╚══════════╩═══════════════╩═══════════════╩════════════╝")

    if chat_events:
        print(f"\n💬 TOÀN BỘ SỰ KIỆN TIN NHẮN & MEDIA ({len(chat_events)} sự kiện):")
        print("─" * 80)
        for ev in chat_events:
            print(" ", format_chat_event(ev))
        print("─" * 80)

    out_file = args.out or (os.path.splitext(args.pcap)[0] + '_dec.json')
    full_output = {
        'summary': {
            'total_flows': len(flows),
            'matched_flows': len(matched_flows),
            'total_frames_decrypted': n_ok,
            'total_chat_events': len(chat_events),
            'cmd_breakdown': {f"{d}_{c}_{s}": n for (d, c, s), n in cnt.items()}
        },
        'chat_events': chat_events,
        'frames': results
    }

    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(full_output, f, ensure_ascii=False, indent=2)
    print(f"\n💾 Đã lưu toàn bộ kết quả giải mã PCAP vào: {out_file}")
    return full_output

def derive_har_key32(zcid_160):
    z = zcid_160.strip()
    if len(z) < 96:
        raise ValueError(f"zcid quá ngắn ({len(z)} chars), cần ít nhất 96 chars")
    part1 = "".join(z[i] for i in range(0, 32, 2))
    part2 = "".join(z[len(z) - 1 - 2 * i] for i in range(16))
    return (part1 + part2).encode('latin1')

def decrypt_har_payload(hex_data, zcid_160):
    try:
        key = derive_har_key32(zcid_160)
        cipher = AES.new(key, AES.MODE_CBC, iv=bytes([0]) * 16)
        raw = cipher.decrypt(bytes.fromhex(hex_data))
        pad_len = raw[-1]
        if 1 <= pad_len <= 16 and all(c == pad_len for c in raw[-pad_len:]):
            raw = raw[:-pad_len]
        return raw.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"[Lỗi giải mã: {e}]"

def run_har_pipeline(args, zcid_cli=None):
    print(f"\n📂 [HAR] Đang phân tích file HTTP Capture: {args.har}")
    entries = []

    try:
        har = json.load(open(args.har, 'r', encoding='utf-8', errors='ignore'))
        entries = har.get('log', {}).get('entries', har.get('entries', []))
    except Exception as e:
        print(f"[!] Lỗi đọc JSON ({e}). Kích hoạt bộ phục hồi stream...")
        raw_txt = open(args.har, 'r', encoding='utf-8', errors='ignore').read()
        entry_blocks = re.findall(r'(\{"startedDateTime":.+?"timings":\{.+?\}\})', raw_txt, re.DOTALL)
        for eb in entry_blocks:
            try:
                entries.append(json.loads(eb))
            except Exception:
                pass

    print(f"[*] Tìm thấy {len(entries)} HTTP entries.")

    zcid = zcid_cli or args.zcid or find_default_zcid()
    if not zcid:
        for e in entries:
            txt = json.dumps(e)
            m160 = re.search(r'([0-9A-Fa-f]{160})', txt)
            if m160:
                zcid = m160.group(1)
                break
            m96 = re.search(r'([0-9A-Fa-f]{96})', txt)
            if m96:
                zcid = m96.group(1)
                break

    if zcid:
        print(f"[*] zcid: {zcid[:32]}...{zcid[-16:]} (độ dài {len(zcid)})")
    else:
        print("[!] Không tìm thấy zcid.")

    out_records = []
    decrypted_count = 0

    for idx, e in enumerate(entries, 1):
        req = e.get('request', {})
        resp = e.get('response', {})
        url = req.get('url', '')
        method = req.get('method', 'GET')

        rec = {
            'idx': idx,
            'method': method,
            'url': url,
            'status': resp.get('status')
        }

        hex_candidates = []
        post_data = (req.get('postData') or {}).get('text', '')
        if post_data:
            for m in re.finditer(r'data=([0-9A-Fa-f]{32,})', post_data):
                hex_candidates.append(('postData_data', m.group(1)))
            for m in re.finditer(r'params=([0-9A-Fa-f]{32,})', post_data):
                hex_candidates.append(('postData_params', m.group(1)))
            if not hex_candidates and len(post_data) >= 32 and all(c in '0123456789abcdefABCDEF' for c in post_data.strip()):
                hex_candidates.append(('postData_raw', post_data.strip()))

        if '?' in url:
            query = url.split('?', 1)[1]
            for m in re.finditer(r'data=([0-9A-Fa-f]{32,})', query):
                hex_candidates.append(('query_data', urllib.parse.unquote(m.group(1))))
            for m in re.finditer(r'params=([0-9A-Fa-f]{32,})', query):
                hex_candidates.append(('query_params', urllib.parse.unquote(m.group(1))))

        if hex_candidates and zcid:
            rec['decrypted_requests'] = []
            for src_label, hex_str in hex_candidates:
                dec = decrypt_har_payload(hex_str, zcid)
                decrypted_count += 1
                try:
                    rec['decrypted_requests'].append({'source': src_label, 'json': json.loads(dec)})
                except Exception:
                    rec['decrypted_requests'].append({'source': src_label, 'text': dec})

        resp_text = (resp.get('content') or {}).get('text', '')
        if resp_text:
            try:
                rj = json.loads(resp_text)
                if isinstance(rj, dict):
                    rec['response_json'] = rj
                    data_obj = rj.get('data')
                    if isinstance(data_obj, dict):
                        ks = data_obj.get('keySet')
                        if isinstance(ks, dict) and ks.get('keySetValue'):
                            rec['extracted_keySet'] = {
                                'keySetId': ks.get('keySetId'),
                                'DK_base64': ks.get('keySetValue'),
                                'DK_hex': base64.b64decode(ks.get('keySetValue')).hex()
                            }
            except Exception:
                if zcid and len(resp_text) >= 32 and all(c in '0123456789abcdefABCDEF' for c in resp_text.strip()):
                    dec_resp = decrypt_har_payload(resp_text.strip(), zcid)
                    try:
                        rec['response_json'] = json.loads(dec_resp)
                    except Exception:
                        rec['response_text'] = dec_resp

        out_records.append(rec)

    print(f"\n[✔] Giải mã HAR hoàn tất: {decrypted_count} request payloads được giải mã.")

    decrypted_entries = [r for r in out_records if 'decrypted_requests' in r or 'extracted_keySet' in r]
    if decrypted_entries:
        print(f"\n🔑 TOÀN BỘ CÁC REQUEST ĐÃ GIẢI MÃ ({len(decrypted_entries)} endpoints):")
        print("─" * 80)
        for r in decrypted_entries:
            print(f"[{r['idx']}] {r['method']} {r['url']}")
            if 'decrypted_requests' in r:
                for d in r['decrypted_requests']:
                    content = json.dumps(d['json'], ensure_ascii=False) if 'json' in d else d.get('text', '')
                    print(f"  ➜ Request ({d['source']}): {content}")
            if 'extracted_keySet' in r:
                ks = r['extracted_keySet']
                print(f"  ⭐ Extracted KeySet: keySetId={ks['keySetId']} | DK_hex={ks['DK_hex']}")
            print()
        print("─" * 80)

    out_file = args.out or (os.path.splitext(args.har)[0] + '_dec.json')
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(out_records, f, ensure_ascii=False, indent=2)
    print(f"\n💾 Đã lưu toàn bộ kết quả giải mã HAR vào: {out_file}")
    return out_records

def main():
    parser = argparse.ArgumentParser(
        description="Zalo RE Tool — Giải mã TOÀN BỘ Socket PCAP/PCAPNG & HTTP HAR bằng zaloprefs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
  # Giải toàn bộ PCAP với zaloprefs:
  python3 zalo_re.py --pcap traffic.pcap --zaloprefs zaloprefs

  # Giải toàn bộ HAR:
  python3 zalo_re.py --har capture.har --zaloprefs zaloprefs
"""
    )
    parser.add_argument('--pcap', help='Đường dẫn file .pcap / .pcapng')
    parser.add_argument('--har', help='Đường dẫn file .har')
    parser.add_argument('--zaloprefs', help='Đường dẫn database zaloprefs (SQLite)')
    parser.add_argument('--dk', help='DK hex (64 chars) hoặc base64 (44 chars)')
    parser.add_argument('--cryptkey', help='CryptKey base64')
    parser.add_argument('--uid', type=int, help='UID Zalo')
    parser.add_argument('--zcid', help='zcid 160-hex')
    parser.add_argument('--out', help='Đường dẫn file JSON xuất kết quả')

    args = parser.parse_args()

    if not args.pcap and not args.har:
        parser.print_help()
        sys.exit(0)

    prefs_path = args.zaloprefs or find_default_zaloprefs()
    dks_map = {}
    cryptkeys_map = {}
    default_uid = args.uid or 0

    if prefs_path and os.path.isfile(prefs_path):
        try:
            prefs_info = parse_zaloprefs(prefs_path)
            print(f"[*] Đã tải zaloprefs từ: {prefs_path}")
            if prefs_info.get('current_uid'):
                cur_uid = int(prefs_info['current_uid'])
                if not args.uid:
                    default_uid = cur_uid
                print(f"[*] Active UID: {prefs_info['current_uid']}")

            for uid_s, udata in prefs_info['users'].items():
                if udata.get('dk'):
                    dks_map[uid_s] = udata['dk']
                if udata.get('cryptkey'):
                    cryptkeys_map[uid_s] = udata['cryptkey']
                print(f"    ├─ UID: {uid_s} | keySetId: {udata['keySetId']} | DK: {udata['dk_hex'][:16]}... | CryptKey: {udata['cryptkey_b64']}")
        except Exception as e:
            print(f"[!] Cảnh báo khi đọc zaloprefs ({prefs_path}): {e}")

    if args.dk:
        try:
            dk_bytes = bytes.fromhex(args.dk) if len(args.dk) == 64 else base64.b64decode(args.dk)
            uid_key = str(args.uid or default_uid or 'custom')
            dks_map[uid_key] = dk_bytes
        except Exception as e:
            sys.exit(f"[!] Tham số --dk không hợp lệ: {e}")

    if args.cryptkey:
        try:
            ck_bytes = base64.b64decode(args.cryptkey) if len(args.cryptkey) <= 24 else bytes.fromhex(args.cryptkey)
            uid_key = str(args.uid or default_uid or 'custom')
            cryptkeys_map[uid_key] = ck_bytes
        except Exception as e:
            sys.exit(f"[!] Tham số --cryptkey không hợp lệ: {e}")

    if args.pcap:
        if not dks_map:
            sys.exit("[!] Lỗi: Không có DK để giải mã Socket. Vui lòng truyền --zaloprefs hoặc --dk.")
        run_pcap_pipeline(args, dks_map, default_uid, cryptkeys_map)

    if args.har:
        run_har_pipeline(args, args.zcid)

if __name__ == '__main__':
    main()
