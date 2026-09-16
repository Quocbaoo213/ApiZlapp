#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zalo_login_1.py — Đăng nhập Zalo tự động qua HTTP/2 (2-Step Verify & ActiveAccount).
Đã đồng bộ 100% Device Parameters, Headers & Build Info từ Xiaomi_M2007J20CG.
"""

import sys, os, time, json, hashlib, subprocess
from Crypto.Cipher import AES

API_KEY = "0be3747aacc670a51a83230bcfe80173"
SECRET = "8cd0fc6c58e88e78d62db52f0e093367"
BASE_KEY = "d902f34a77e3084b9034eb0caee3e019"
CS = "7ad1cddec8101b35cc2fa47c46b8c84f"
CERT_KEY = "9487ba76b32e9e36785fb4c3540021f85af8d7b7"
CLIENT_VERSION = "260802903"

DEFAULT_ZCID = "75BBAA2486F8843614C94034EF9D7C1F90BF780A1AAB94D80726CBCB02533A554A29B2526E6BBEC721CC041C63F6A361400973B7D0988F9112BDCFF9B5A001AAE4D92C55DBC81593C2DAB614C5C188B6"

BUILD_INFO_STR = json.dumps({
    "APK_LANGUAGE": "0", "APPLICATION_ID": "com.zing.zalo", "BUILD_FOR_TESTING": "false",
    "BUILD_PLAY_STORE": "true", "BUILD_TYPE": "release", "CI": "true", "DEBUG": "false",
    "DISTRIBUTOR": "GOO", "ENABLE_BITMAP_POOL": "true", "ENABLE_FIREBASE_CRASHLYTICS": "true",
    "ENABLE_NETWORK_CONTROL": "true", "FLAVOR": "prod", "PRELOAD_BUILD": "false",
    "PRODUCTION": "true", "USE_FILE_LOGGING": "true", "USE_QUICK_STICKER_POPUP_MSG": "true",
    "VERSION_CODE": "260802903", "VERSION_NAME": "26.08.02",
    "BUILD_ID": "a4690650-cb29-49d6-abe1-b48427b5a4e9", "BUILD_TIME": "2026/04/09 17:11:51",
    "GIT_BRANCH": "main", "GIT_COMMIT": "55ccc6b8", "BUILDER": "CI by phuongvh", "CI_PIPELINE_ID": "1504823"
}, separators=(',', ':'))

DEVICE_INFO_STR = json.dumps({
    "CPU_Processor": "AArch64 Processor rev 14 (aarch64)", "CPU_Hardware": "Qualcomm Technologies, Inc SDMMAGPIE",
    "CPU_Architecture": "8", "CPU_MAXFreq": "1804", "CPU_MINFreq": "300", "CPU_NumCore": "8",
    "Model": "M2007J20CG", "Battery_Technology": "Li-poly", "Temperature": "24.9", "Voltage": "3766",
    "SimCardSlot": "2", "SimCardNumber": "", "SensorStepCount": "1", "SensorAccelerator": "1",
    "NonMarketAllowed": "1"
}, separators=(',', ':'))

def password_hash(phone, password):
    key = hashlib.md5((BASE_KEY + phone).encode()).hexdigest()[5:21].encode()
    blk = password.encode().ljust(16, b"\x00")
    return AES.new(key, AES.MODE_ECB).encrypt(blk).hex()

def key32(zcid):
    return ("".join(zcid[i] for i in range(0, 32, 2)) + "".join(zcid[159 - 2 * i] for i in range(16))).encode()

def encrypt_data(params, zcid):
    k = key32(zcid)
    plain = json.dumps(params, separators=(',', ':')).encode()
    pad_len = 16 - len(plain) % 16
    plain += bytes([pad_len]) * pad_len
    return AES.new(k, AES.MODE_CBC, iv=bytes(16)).encrypt(plain).hex().upper()

def compute_sig(data_hex):
    return hashlib.md5((f"api_key={API_KEY}data={data_hex}{SECRET}").encode()).hexdigest()

def do_login(phone, password, zcid=DEFAULT_ZCID):
    if not phone.startswith("+"):
        phone = "+" + phone if phone.startswith("84") else "+84" + phone.lstrip("0")
    
    print(f"[*] 1. Đang thực hiện xác thực bước 1 (phone/verify) cho: {phone}...")
    now_sec = int(time.time())
    now_ms = int(time.time() * 1000)
    
    v_params = {
        "width": "1080", "captcha_value": "", "height": "2306", "model": "Xiaomi_M2007J20CG_14",
        "distributor_mobile_tracking": "", "clientVersion": CLIENT_VERSION, "heap": "512",
        "session_token": "", "avatarSize": "160", "client_version": CLIENT_VERSION,
        "advertising_id": "6fafe86a-68af-4ffb-b9f2-cda2119c0b1e", "phone_num": phone,
        "build_info": BUILD_INFO_STR, "mac_address": "",
        "device_identifier": "3000.SSZ-xCSL8Q0CiyhOwZice5B-qzUXEspfLhE4sxWzRw02e8lG-MLpi5cnn9dwONQtNVh2dF4aTRTIyyQODZWo.1",
        "local_time": str(now_ms), "sign": "", "zcid": "1_" + zcid, "network": "0",
        "time_zone": "+07:00", "src_type": "1", "distributor": "GOO", "language": "vi_VN",
        "android_id": "196e91185b0fba4e", "imei": "000000", "client_type": "1", "cs": CS,
        "deviceInfo": DEVICE_INFO_STR, "captcha_token": "", "preload_info": "unknown",
        "user_language": "vi", "iso_country_code": "VN", "hcm_token": "", "api_key": API_KEY,
        "certificatedKey": CERT_KEY, "inc_p": "1",
        "fcm_token": "cbihaiUoRWeRKF4j2Ml1En:APA91bF6rcorLBmCmM8zwR_xgHmnihy39hWg3UJgatJ26-qU3cd6zjuiZloKLkGHPVT0DBwO0kGW4gjba5XikN-LE8nYU275mJFS6r9N-pGM186ulMTddfA",
        "operator": "45204", "clientType": "1", "ts": str(now_sec), "session_key": "", "type": "1"
    }
    
    v_data = encrypt_data(v_params, zcid)
    v_sig = compute_sig(v_data)
    v_body = f"sig={v_sig}&api_key={API_KEY}&data={v_data}"
    
    res_v = subprocess.run([
        "curl", "--http2", "-sS", "-X", "POST", "https://register.zaloapp.com/api/v1/login/phone/verify",
        "-H", "user-agent: znetwork/8.14.1",
        "-H", f"clientversion: {CLIENT_VERSION}",
        "-H", "content-type: application/x-www-form-urlencoded",
        "-H", "networktype: 0", "-H", "operator: 45204", "-H", "nretry: 1",
        "-H", "v: v2", "-H", "platform: 1", "-H", f"zcid: {zcid}", "-d", v_body
    ], capture_output=True, text=True)
    
    try:
        j_v = json.loads(res_v.stdout)
    except Exception:
        raise RuntimeError(f"Lỗi response từ verify: {res_v.stdout}")
        
    if j_v.get("error_code") != 0:
        raise RuntimeError(f"Verify failed ({j_v.get('error_code')}): {j_v.get('error_message')}")
        
    session_token = j_v.get("data", {}).get("sessionToken", "")
    print(f"[✔] Bước 1 thành công — SessionToken: {session_token}")
    
    print(f"[*] 2. Đang thực hiện kích hoạt tài khoản bước 2 (activeAccountByPassword)...")
    a_params = {
        "ckeyset": "AAEodckkKr0", "width": "1080", "captcha_value": "", "height": "2306",
        "error_code_fallback": "1", "model": "Xiaomi_M2007J20CG_14", "distributor_mobile_tracking": "",
        "log_disk": '{"free_MB":"4284","total_MB":"46331"}', "clientVersion": CLIENT_VERSION,
        "heap": "512", "session_token": session_token, "avatarSize": "160",
        "client_version": CLIENT_VERSION, "advertising_id": "6fafe86a-68af-4ffb-b9f2-cda2119c0b1e",
        "phone_num": phone, "build_info": BUILD_INFO_STR, "mac_address": "",
        "device_identifier": "3000.SSZ-xCSL8Q0CiyhOwZice5B-qzUXEspfLhE4sxWzRw02e8lG-MLpi5cnn9dwONQtNVh2dF4aTRTIyyQODZWo.1",
        "local_time": str(int(time.time() * 1000)), "sign": "", "zcid": "1_" + zcid,
        "network": "0", "time_zone": "+07:00", "protover": "1", "distributor": "GOO",
        "source_type": "1", "language": "vi_VN", "android_id": "196e91185b0fba4e",
        "imei": "000000", "client_type": "1", "cs": CS, "checkActiveCode": "1",
        "deviceInfo": DEVICE_INFO_STR, "source_action": "0", "captcha_token": "",
        "preload_info": "unknown", "source_switch": "0", "answer_type": "",
        "password": password_hash(phone, password), "user_language": "vi",
        "iso_country_code": "", "hcm_token": "", "api_key": API_KEY, "certificatedKey": CERT_KEY,
        "inc_p": "1",
        "fcm_token": "cbihaiUoRWeRKF4j2Ml1En:APA91bF6rcorLBmCmM8zwR_xgHmnihy39hWg3UJgatJ26-qU3cd6zjuiZloKLkGHPVT0DBwO0kGW4gjba5XikN-LE8nYU275mJFS6r9N-pGM186ulMTddfA",
        "operator": "45204", "answer_value": "", "question_type": "", "clientType": "1",
        "ts": str(int(time.time())), "switch_account": "", "session_key": "", "type": "1"
    }
    
    a_data = encrypt_data(a_params, zcid)
    a_sig = compute_sig(a_data)
    a_body = f"sig={a_sig}&api_key={API_KEY}&data={a_data}"
    
    res_a = subprocess.run([
        "curl", "--http2", "-sS", "-X", "POST", "https://register.zaloapp.com/api/register/activeAccountByPassword",
        "-H", "user-agent: znetwork/8.14.1",
        "-H", f"clientversion: {CLIENT_VERSION}",
        "-H", "content-type: application/x-www-form-urlencoded",
        "-H", "networktype: 0", "-H", "operator: 45204", "-H", "nretry: 1",
        "-H", "v: v2", "-H", "platform: 1", "-H", f"zcid: {zcid}", "-d", a_body
    ], capture_output=True, text=True)
    
    try:
        j_a = json.loads(res_a.stdout)
    except Exception:
        raise RuntimeError(f"Lỗi response từ active account: {res_a.stdout}")
        
    if j_a.get("error_code") != 0:
        raise RuntimeError(f"Active account failed ({j_a.get('error_code')}): {j_a.get('error_message')}")
        
    data = j_a.get("data", {})
    print(f"\n[⭐⭐⭐] ĐĂNG NHẬP THÀNH CÔNG!")
    print(f"   ├─ Session Key : {data.get('session_key')}")
    print(f"   ├─ KeySetId    : {data.get('keySet', {}).get('keySetId')}")
    print(f"   ├─ DK (Base64) : {data.get('keySet', {}).get('keySetValue')}")
    print(f"   ├─ CryptKey    : {data.get('CrypKey')}")
    print(f"   └─ SocketServers: {len(data.get('socketServers', []))} servers")
    
    save_path = "/sdcard/Download/Zalo/active_session.json"
    with open(save_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[✔] Đã lưu thông tin phiên mới nhất vào: {save_path}")
    return data

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Zalo Auto Login (2-Step)")
    parser.add_argument("--phone", default="+84993903236", help="Số điện thoại")
    parser.add_argument("--password", default="141722789@Ss", help="Mật khẩu")
    args = parser.parse_args()
    
    do_login(args.phone, args.password)

if __name__ == "__main__":
    main()
