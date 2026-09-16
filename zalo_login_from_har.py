#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zalo_login_from_har.py — Tự động phân tích HAR & thực hiện đăng nhập Zalo (Phương án A Replay & Phương án B Fingerprint Login).
"""

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import time
from urllib.parse import parse_qs, unquote
from Crypto.Cipher import AES

SECRET = "8cd0fc6c58e88e78d62db52f0e093367"
BASE_KEY = "d902f34a77e3084b9034eb0caee3e019"
CLIENT_VERSION = "260802903"

def key32(zcid: str) -> bytes:
    z = zcid.strip()
    if len(z) < 96:
        raise ValueError(f"ZCID quá ngắn ({len(z)} ký tự), cần tối thiểu 96 ký tự hex.")
    part1 = "".join(z[i] for i in range(0, 32, 2))
    part2 = "".join(z[len(z) - 1 - 2 * i] for i in range(16))
    return (part1 + part2).encode('latin1')

def encrypt_data(params: dict, zcid: str) -> str:
    k = key32(zcid)
    plain = json.dumps(params, separators=(',', ':')).encode('utf-8')
    pad_len = 16 - len(plain) % 16
    plain += bytes([pad_len]) * pad_len
    return AES.new(k, AES.MODE_CBC, iv=bytes(16)).encrypt(plain).hex().upper()

def decrypt_data(data_hex: str, zcid: str) -> dict:
    k = key32(zcid)
    cipher = AES.new(k, AES.MODE_CBC, iv=bytes(16))
    raw = cipher.decrypt(bytes.fromhex(data_hex))
    pad_len = raw[-1]
    if 1 <= pad_len <= 16:
        raw = raw[:-pad_len]
    return json.loads(raw.decode('utf-8', errors='ignore'))

def compute_sig(data_hex: str, api_key: str, secret: str = SECRET) -> str:
    return hashlib.md5((f"api_key={api_key}data={data_hex}{secret}").encode('utf-8')).hexdigest()

def password_hash(phone: str, password: str) -> str:
    key = hashlib.md5((BASE_KEY + phone).encode('utf-8')).hexdigest()[5:21].encode('utf-8')
    blk = password.encode('utf-8').ljust(16, b"\x00")[:16]
    return AES.new(key, AES.MODE_ECB).encrypt(blk).hex()

def extract_har_info(har_path: str):
    if not os.path.isfile(har_path):
        raise FileNotFoundError(f"Không tìm thấy file HAR: {har_path}")

    with open(har_path, 'r', encoding='utf-8', errors='ignore') as f:
        har = json.load(f)

    entries = har.get('log', {}).get('entries', [])
    if not entries:
        raise ValueError("File HAR không chứa entry nào.")

    verify_entry = None
    active_entry = None

    for e in entries:
        req = e.get('request', {})
        url = req.get('url', '')
        if 'api/v1/login/phone/verify' in url:
            verify_entry = e
        elif 'api/register/activeAccountByPassword' in url:
            active_entry = e

    if not verify_entry and not active_entry:
        raise ValueError("HAR không có login flow (thiếu phone/verify và activeAccountByPassword).")

    info = {
        'total_entries': len(entries),
        'capture_time': entries[0].get('startedDateTime', 'Unknown'),
        'has_verify': verify_entry is not None,
        'has_active': active_entry is not None,
        'verify_entry': verify_entry,
        'active_entry': active_entry,
    }

    # Trích xuất zcid từ headers
    target_entry = active_entry or verify_entry
    zcid = None
    req_headers = {}
    for h in target_entry['request'].get('headers', []):
        req_headers[h['name'].lower()] = h['value']
        if h['name'].lower() == 'zcid':
            zcid = h['value'].replace('1_', '')

    info['zcid'] = zcid
    info['req_headers'] = req_headers

    # Trích xuất fingerprint từ verify_entry
    if verify_entry:
        v_body = verify_entry['request'].get('postData', {}).get('text', '')
        v_qs = parse_qs(v_body)
        v_data_hex = v_qs.get('data', [''])[0]
        if v_data_hex and zcid:
            try:
                dec_v = decrypt_data(v_data_hex, zcid)
                info['verify_params'] = dec_v
            except Exception as ex:
                info['verify_params_err'] = str(ex)

        # Trích xuất sessionToken từ response verify
        v_res_text = verify_entry['response'].get('content', {}).get('text', '')
        try:
            v_res_json = json.loads(v_res_text)
            info['sessionToken'] = v_res_json.get('data', {}).get('sessionToken')
        except Exception:
            info['sessionToken'] = None

    # Trích xuất active_params từ active_entry
    if active_entry:
        a_body = active_entry['request'].get('postData', {}).get('text', '')
        a_qs = parse_qs(a_body)
        a_data_hex = a_qs.get('data', [''])[0]
        info['active_raw_body'] = a_body
        info['active_data_hex'] = a_data_hex
        info['active_sig'] = a_qs.get('sig', [''])[0]
        info['active_api_key'] = a_qs.get('api_key', ['0be3747aacc670a51a83230bcfe80173'])[0]
        if a_data_hex and zcid:
            try:
                dec_a = decrypt_data(a_data_hex, zcid)
                info['active_params'] = dec_a
            except Exception as ex:
                info['active_params_err'] = str(ex)

        # Trích xuất response data
        a_res_text = active_entry['response'].get('content', {}).get('text', '')
        try:
            info['active_res_json'] = json.loads(a_res_text)
        except Exception:
            info['active_res_json'] = None

    return info

def build_curl_headers(headers_list_or_dict) -> list:
    args = []
    if isinstance(headers_list_or_dict, list):
        for h in headers_list_or_dict:
            name = h.get('name', '')
            val = h.get('value', '')
            if not name.startswith(':') and name.lower() != 'content-length':
                args.extend(["-H", f"{name}: {val}"])
    elif isinstance(headers_list_or_dict, dict):
        for k, v in headers_list_or_dict.items():
            if not k.startswith(':') and k.lower() != 'content-length':
                args.extend(["-H", f"{k}: {v}"])
    return args

def execute_replay_method_a(har_info: dict) -> dict:
    """Phương án A: Gửi lại nguyên vẹn request activeAccountByPassword từ HAR."""
    active_entry = har_info.get('active_entry')
    if not active_entry:
        return {'success': False, 'error': 'HAR không có entry activeAccountByPassword'}

    raw_body = har_info.get('active_raw_body')
    req_headers = active_entry['request'].get('headers', [])

    cmd = [
        "curl", "--http2", "-sS", "-X", "POST", "https://register.zaloapp.com/api/register/activeAccountByPassword"
    ]
    cmd.extend(build_curl_headers(req_headers))
    cmd.extend(["-d", raw_body])

    res = subprocess.run(cmd, capture_output=True, text=True)
    try:
        j = json.loads(res.stdout)
    except Exception:
        return {'success': False, 'error': f'Lỗi parse JSON phản hồi: {res.stdout[:200]}'}

    ec = j.get('error_code', -1)
    if ec == 0:
        return {'success': True, 'data': j.get('data', {}), 'source': 'har_replay'}
    return {'success': False, 'error_code': ec, 'error_message': j.get('error_message', '')}

def execute_login_method_b(har_info: dict, phone: str = None, password: str = None) -> dict:
    """Phương án B: Đăng nhập mới 2 bước sử dụng Device Fingerprint & ZCID trích xuất từ HAR."""
    verify_entry = har_info.get('verify_entry')
    active_entry = har_info.get('active_entry')
    v_params = har_info.get('verify_params')
    a_params = har_info.get('active_params')
    zcid = har_info.get('zcid')

    if not v_params or not a_params or not zcid:
        return {'success': False, 'error': 'Không đủ tham số device fingerprint trích xuất từ HAR.'}

    target_phone = phone or v_params.get('phone_num')
    if not target_phone:
        return {'success': False, 'error': 'Thiếu số điện thoại (phone_num).'}

    if not target_phone.startswith("+"):
        target_phone = "+" + target_phone if target_phone.startswith("84") else "+84" + target_phone.lstrip("0")

    # Bước 1: phone/verify
    v_headers = verify_entry['request'].get('headers', []) if verify_entry else har_info.get('req_headers', {})
    v_raw_body = verify_entry['request'].get('postData', {}).get('text', '') if verify_entry else None

    # Nếu cùng số điện thoại, có thể gửi trực tiếp verify body hoặc tái tạo
    if v_raw_body and (not phone or phone == v_params.get('phone_num')):
        v_body = v_raw_body
    else:
        v_params_copy = dict(v_params)
        v_params_copy['phone_num'] = target_phone
        v_params_copy['local_time'] = str(int(time.time() * 1000))
        v_params_copy['ts'] = str(int(time.time()))
        v_data = encrypt_data(v_params_copy, zcid)
        v_api_key = v_params_copy.get('api_key', '0be3747aacc670a51a83230bcfe80173')
        v_sig = compute_sig(v_data, v_api_key)
        v_body = f"sig={v_sig}&api_key={v_api_key}&data={v_data}"

    cmd1 = ["curl", "--http2", "-sS", "-X", "POST", "https://register.zaloapp.com/api/v1/login/phone/verify"]
    cmd1.extend(build_curl_headers(v_headers))
    cmd1.extend(["-d", v_body])

    res_v = subprocess.run(cmd1, capture_output=True, text=True)
    try:
        j_v = json.loads(res_v.stdout)
    except Exception:
        return {'success': False, 'error': f'Lỗi parse JSON verify: {res_v.stdout[:200]}'}

    if j_v.get("error_code") != 0:
        return {'success': False, 'error_code': j_v.get('error_code'), 'error_message': j_v.get('error_message')}

    new_session_token = j_v.get("data", {}).get("sessionToken", "")
    if not new_session_token:
        return {'success': False, 'error': 'Không nhận được sessionToken từ bước 1.'}

    # Bước 2: activeAccountByPassword
    a_headers = active_entry['request'].get('headers', []) if active_entry else har_info.get('req_headers', {})
    a_params_copy = dict(a_params)
    a_params_copy['phone_num'] = target_phone
    a_params_copy['session_token'] = new_session_token
    if password:
        a_params_copy['password'] = password_hash(target_phone, password)

    a_data = encrypt_data(a_params_copy, zcid)
    a_api_key = a_params_copy.get('api_key', '0be3747aacc670a51a83230bcfe80173')
    a_sig = compute_sig(a_data, a_api_key)
    a_body = f"sig={a_sig}&api_key={a_api_key}&data={a_data}"

    cmd2 = ["curl", "--http2", "-sS", "-X", "POST", "https://register.zaloapp.com/api/register/activeAccountByPassword"]
    cmd2.extend(build_curl_headers(a_headers))
    cmd2.extend(["-d", a_body])

    res_a = subprocess.run(cmd2, capture_output=True, text=True)
    try:
        j_a = json.loads(res_a.stdout)
    except Exception:
        return {'success': False, 'error': f'Lỗi parse JSON active: {res_a.stdout[:200]}'}

    if j_a.get("error_code") != 0:
        return {'success': False, 'error_code': j_a.get('error_code'), 'error_message': j_a.get('error_message')}

    return {'success': True, 'data': j_a.get('data', {}), 'source': 'har_fingerprint_login'}

def verify_frame0_with_dk(dk_b64: str, frame0_path: str = "/root/zalo/frame0.bin") -> dict:
    """Xác thực tính tương thích giữa Frame 0 hiện tại và DK mới."""
    if not os.path.isfile(frame0_path):
        return {'status': 'MISSING', 'message': f'Không tìm thấy file {frame0_path}'}

    try:
        dk_bytes = base64.b64decode(dk_b64)
        f0_bytes = open(frame0_path, 'rb').read()
        if len(f0_bytes) < 28:
            return {'status': 'INVALID', 'message': 'Frame 0 quá ngắn.'}

        # Thử giải mã Frame 0 bằng AES-GCM với DK
        iv = f0_bytes[-12:]
        tag = f0_bytes[-28:-12]
        ct = f0_bytes[:-28]
        cipher = AES.new(dk_bytes, AES.MODE_GCM, nonce=iv, mac_len=16)
        dec = cipher.decrypt_and_verify(ct, tag)
        return {'status': 'MATCHED', 'decrypted_len': len(dec)}
    except Exception as ex:
        return {'status': 'MISMATCH', 'error': str(ex)}

def main():
    parser = argparse.ArgumentParser(description="Zalo Login & Session Recovery from HAR")
    parser.add_argument("--har", default="/sdcard/Download/Reqable/a.har", help="Đường dẫn file HAR")
    parser.add_argument("--phone", default="+84993903236", help="Số điện thoại")
    parser.add_argument("--password", default="141722789@Ss", help="Mật khẩu tài khoản")
    parser.add_argument("--out", default="/root/zalo/fresh_session.json", help="File lưu session mới")
    args = parser.parse_args()

    print(f"[*] 1. Bắt đầu phân tích file HAR: {args.har}...")
    try:
        har_info = extract_har_info(args.har)
    except Exception as e:
        print(f"[!] LỖI: {e}")
        sys.exit(1)

    print(f"[✔] Số lượng HTTP entries: {har_info['total_entries']}")
    print(f"[✔] Thời gian capture: {har_info['capture_time']}")
    print(f"[✔] ZCID: {har_info['zcid']} (Độ dài: {len(har_info['zcid']) if har_info['zcid'] else 0} hex)")
    print(f"[✔] SessionToken trích xuất: {har_info.get('sessionToken')}")

    # Thử Phương án A
    print(f"\n[*] 2. Thử PHƯƠNG ÁN A — Replay Request từ HAR...")
    res_a = execute_replay_method_a(har_info)
    session_result = None

    if res_a.get('success'):
        print(f"[⭐⭐⭐] Phương án A THÀNH CÔNG! Đã lấy được phiên mới qua Replay.")
        session_result = res_a
    else:
        print(f"[!] Phương án A thất bại (Mã lỗi: {res_a.get('error_code')}, Thông báo: {res_a.get('error_message') or res_a.get('error')}).")
        print(f"[*] 3. Chuyển sang PHƯƠNG ÁN B — Login mới với Device Fingerprint trích xuất từ HAR...")
        res_b = execute_login_method_b(har_info, phone=args.phone, password=args.password)
        if res_b.get('success'):
            print(f"[⭐⭐⭐] Phương án B THÀNH CÔNG! Đã đăng nhập mới và sinh bộ khóa phiên hoàn chỉnh.")
            session_result = res_b
        else:
            print(f"[❌] Phương án B thất bại (Mã lỗi: {res_b.get('error_code')}, Thông báo: {res_b.get('error_message') or res_b.get('error')}).")
            if res_b.get('error_code') == 2048:
                print(f"[⚠️ CẢNH BÁO] Server yêu cầu xác thực 2FA/Thiết bị mới (Code=2048). Cần hoàn tất trên thiết bị thật.")

    if session_result:
        d = session_result['data']
        keyset = d.get('keySet', {})
        dk_b64 = keyset.get('keySetValue', '')
        dk_hex = base64.b64decode(dk_b64).hex() if dk_b64 else ''
        
        output_data = {
            "uid": d.get('user_id'),
            "dk_hex": dk_hex,
            "dk_b64": dk_b64,
            "ksid": keyset.get('keySetId'),
            "session_key": d.get('session_key'),
            "cryptkey": d.get('CrypKey'),
            "socketServers": d.get('socketServers', []),
            "source": session_result.get('source'),
            "har_timestamp": har_info.get('capture_time'),
            "login_timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }

        with open(args.out, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        print(f"\n💾 [✔] Đã lưu thông tin phiên mới vào: {args.out}")

        # Kiểm tra tính tương thích của Frame 0
        print(f"\n[*] 4. Kiểm tra tính tương thích với Frame 0 (/root/zalo/frame0.bin)...")
        f0_check = verify_frame0_with_dk(dk_b64)
        print(f"    ├─ Kết quả kiểm tra: {f0_check.get('status')}")
        if f0_check.get('status') == 'MATCHED':
            print(f"    └─ Frame 0 khớp 100% với DK mới! Có thể kết nối Socket ngay.")
        else:
            print(f"    └─ Frame 0 hiện tại không khớp DK mới ({f0_check.get('error') or f0_check.get('message')}). Cần cập nhật Frame 0 tương ứng.")

if __name__ == '__main__':
    main()
