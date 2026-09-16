#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/login/device.py — Quản lý cấu hình thiết bị, mã hóa HTTP và ZCID cho Login.
Tương thích 100% với zalo_login_v10.py.
"""

import os
import time
import json
import base64
import hashlib
import secrets
import subprocess
from typing import Dict, Any, Optional
from Crypto.Cipher import AES

# ═══ HẰNG SỐ MÃ HÓA HTTP & XÁC THỰC ═══
INIT_KEY = b"IXX3RM3GABH3NS0AED3VV04N9ABCDA1D"
DEFAULT_API_KEY = "0be3747aacc670a51a83230bcfe80173"
DEFAULT_SECRET = "8cd0fc6c58e88e78d62db52f0e093367"
DEFAULT_BASE_KEY = "d902f34a77e3084b9034eb0caee3e019"
DEFAULT_CS = "7ad1cddec8101b35cc2fa47c46b8c84f"
DEFAULT_CERT = "9487ba76b32e9e36785fb4c3540021f85af8d7b7"
DEFAULT_CLIENT_VERSION = "260801901"
DEFAULT_USER_AGENT = "znetwork/8.14.1"

# Endpoints
REG_URL = "https://register.zaloapp.com"
ACC_URL = "https://accounts.zalo.me"
ZMVC_URL = "https://zm-verification-center.zaloapp.com"
ZMCAP_URL = "https://zmcaptcha.zaloapp.com"


# ═══ CẤU HÌNH THIẾT BỊ SAMSUNG SM-J610F (HAR-EXACT) ═══
HAR_DEVICE: Dict[str, Any] = {
    "advertising_id": "unknown",
    "android_id": "ba1a2432a7ffd531",
    "avatarSize": "160",
    "device_identifier": "2002.SSZ-wu8DGTLrXQddcmj2d26MfkpQKrwCVu7geDnKNevvWk_kt59IodY3uUFSNLF6C0.1",
    "device_spec_id": "samsung-smj610f-3-32-30",
    "distributor": "GOO",
    "heap": "384",
    "height": "1396",
    "imei": "000000",
    "model": "samsung_SM-J610F_11",
    "network": "0",
    "operator": "-1",
    "preload_info": "unknown",
    "protover": "1",
    "time_zone": "+07:00",
    "user_language": "vi",
    "language": "vi_VN",
    "width": "720",
    "clientType": "1",
    "client_type": "1",
    "clientVersion": DEFAULT_CLIENT_VERSION,
    "client_version": DEFAULT_CLIENT_VERSION,
    "checkActiveCode": "1",
    "inc_p": "1",
    "error_code_fallback": "1",
    "source_action": "0",
    "source_switch": "0",
    "src_type": "1",
    "type": "1",
    "distributor_mobile_tracking": "",
    "iso_country_code": "",
    "mac_address": "",
    "fcm_token": "",
    "hcm_token": "",
    "pwd_token": "",
    "switch_account": "",
    "answer_type": "",
    "answer_value": "",
    "question_type": "",
    "session_key": "",
    "sign": "",
    "cs": DEFAULT_CS,
    "certificatedKey": DEFAULT_CERT,
    "api_key": DEFAULT_API_KEY,
}

HAR_LONG: Dict[str, Any] = {
    "ckeyset": "AAAVH3sm6OE",
    "width": "720",
    "height": "1396",
    "error_code_fallback": "1",
    "model": "samsung_SM-J610F_11",
    "distributor_mobile_tracking": "",
    "log_disk": json.dumps({"free_MB": "17600", "total_MB": "24573"}, separators=(',', ':')),
    "clientVersion": DEFAULT_CLIENT_VERSION,
    "heap": "384",
    "avatarSize": "160",
    "client_version": DEFAULT_CLIENT_VERSION,
    "advertising_id": "unknown",
    "build_info": json.dumps({
        "APK_LANGUAGE": "0", "APPLICATION_ID": "com.zing.zalo", "BUILD_FOR_TESTING": "false",
        "BUILD_PLAY_STORE": "true", "BUILD_TYPE": "release", "CI": "true", "DEBUG": "false",
        "DISTRIBUTOR": "GOO", "ENABLE_BITMAP_POOL": "true", "ENABLE_FIREBASE_CRASHLYTICS": "true",
        "ENABLE_NETWORK_CONTROL": "true", "FLAVOR": "prod", "PRELOAD_BUILD": "false",
        "PRODUCTION": "true", "USE_FILE_LOGGING": "true", "USE_QUICK_STICKER_POPUP_MSG": "true",
        "VERSION_CODE": "260801901", "VERSION_NAME": "26.08.01",
        "BUILD_ID": "b798fdd1-6526-4be8-bc61-354edf5d64e1", "BUILD_TIME": "2026/08/03 10:58:20",
        "GIT_BRANCH": "main", "GIT_COMMIT": "b53de1ae", "BUILDER": "CI by phuongvh", "CI_PIPELINE_ID": "1652913"
    }, separators=(',', ':')),
    "mac_address": "",
    "device_identifier": "2002.SSZ-wu8DGTLrXQddcmj2d26MfkpQKrwCVu7geDnKNevvWk_kt59IodY3uUFSNLF6C0.1",
    "network": "0",
    "time_zone": "+07:00",
    "protover": "1",
    "src_type": "1",
    "distributor": "GOO",
    "language": "vi_VN",
    "android_id": "ba1a2432a7ffd531",
    "imei": "000000",
    "client_type": "1",
    "cs": DEFAULT_CS,
    "checkActiveCode": "1",
    "deviceInfo": json.dumps({
        "CPU_Processor": "aarch64", "CPU_Hardware": "Qualcomm Technologies, Inc MSM8917",
        "CPU_Architecture": "8", "CPU_MAXFreq": "1401", "CPU_MINFreq": "960", "CPU_NumCore": "4",
        "Model": "SM-J610F", "Battery_Technology": "Li-ion", "Temperature": "34.0", "Voltage": "3768",
        "SimCardSlot": "2", "SimCardNumber": "", "SensorStepCount": "0", "SensorAccelerator": "1",
        "NonMarketAllowed": "1"
    }, separators=(',', ':')),
    "source_action": "0",
    "preload_info": "unknown",
    "source_switch": "0",
    "user_language": "vi",
    "iso_country_code": "",
    "hcm_token": "",
    "api_key": DEFAULT_API_KEY,
    "certificatedKey": DEFAULT_CERT,
    "inc_p": "1",
    "fcm_token": "",
    "operator": "-1",
    "clientType": "1",
    "device_spec_id": "samsung-smj610f-3-32-30",
    "switch_account": "",
    "session_key": "",
    "type": "1"
}


# ═══ MÃ HÓA & HÀM TIỆN ÍCH ═══

def pad16(d: bytes) -> bytes:
    """PKCS7 padding cho khối 16 bytes."""
    p = 16 - len(d) % 16
    return d + bytes([p]) * p


def key32_96(zcid: str) -> bytes:
    """
    Trích xuất khóa 32 bytes từ chuỗi ZCID 96-hex.
    Lấy các ký tự chẵn từ 0..31 + 16 ký tự từ cuối lùi dần.
    """
    z = zcid.strip()
    return (
        "".join(z[i] for i in range(0, 32, 2)) +
        "".join(z[95 - 2 * i] for i in range(16))
    ).encode()


def norm_phone(p: str) -> str:
    """Chuẩn hóa số điện thoại về định dạng +84..."""
    p = p.strip().lstrip('+')
    if p.startswith('84') and len(p) >= 10:
        return '+' + p
    if p.startswith('0'):
        return '+84' + p[1:]
    return '+84' + p


def pwd_hash(phone: str, password: str, base_key: str = DEFAULT_BASE_KEY) -> str:
    """Tính mã băm mật khẩu AES-ECB với key MD5(BASE_KEY + phone)[5:21]."""
    ph = norm_phone(phone)
    a = hashlib.md5((base_key + ph).encode()).hexdigest()
    key = a[5:21].encode()
    padded_pw = password.encode().ljust(16, b"\0")
    if len(padded_pw) > 16 and len(padded_pw) % 16 != 0:
        padded_pw = pad16(password.encode())
    return AES.new(key, AES.MODE_ECB).encrypt(padded_pw[:16]).hex()


def gen_zcid96(init_key: bytes = INIT_KEY) -> str:
    """
    Sinh ZCID 96 hex UPPERCASE hợp lệ.
    AES-CBC(INIT_KEY, '0,unknown,SM-J610F,{ts_ms},0').
    """
    now_ms = int(time.time() * 1000)
    raw = f"0,unknown,SM-J610F,{now_ms},0".encode()
    padded = pad16(raw)
    return AES.new(init_key, AES.MODE_CBC, bytes(16)).encrypt(padded).hex().upper()


def is_valid_zcid(zcid_hex: str, init_key: bytes = INIT_KEY) -> bool:
    """Kiểm tra xem chuỗi ZCID 96-hex có giải mã được bằng INIT_KEY và hợp lệ không."""
    if not zcid_hex:
        return False
    z_clean = zcid_hex.strip()
    if len(z_clean) != 96:
        return False
    try:
        raw_bytes = bytes.fromhex(z_clean)
        dec = AES.new(init_key, AES.MODE_CBC, bytes(16)).decrypt(raw_bytes)
        pad = dec[-1]
        if 1 <= pad <= 16:
            plain = dec[:-pad].decode('utf-8', errors='ignore')
            if plain.startswith('0,') and 'SM-J610F' in plain:
                return True
    except Exception:
        pass
    return False



def enc_body(params: dict, zcid: str, api_key: str = DEFAULT_API_KEY, secret: str = DEFAULT_SECRET) -> str:
    """Mã hóa AES-CBC toàn bộ body params và tính chữ ký MD5 signature."""
    key = key32_96(zcid)
    payload_json = json.dumps(params, separators=(",", ":")).encode("utf-8")
    data_hex = AES.new(key, AES.MODE_CBC, bytes(16)).encrypt(pad16(payload_json)).hex().upper()
    sig = hashlib.md5((f"api_key={api_key}data={data_hex}" + secret).encode("utf-8")).hexdigest()
    return f"sig={sig}&api_key={api_key}&data={data_hex}"


def base_params(zcid: str, phone: str, password: str) -> dict:
    """Tạo bộ tham số mặc định kết hợp HAR device và thông tin người dùng."""
    p = dict(HAR_DEVICE)
    for k in ("build_info", "deviceInfo", "log_disk"):
        if k in HAR_LONG:
            p[k] = HAR_LONG[k]
    now = int(time.time() * 1000)
    ph = norm_phone(phone)
    p.update({
        "phone_num": ph,
        "password": pwd_hash(ph, password),
        "session_token": "",
        "ckeyset": "",
        "captcha_token": "",
        "captcha_value": "",
        "verificationToken": "",
        "zcid": "1_" + zcid,
        "ts": str(now // 1000),
        "local_time": str(now),
    })
    return p


class DeviceProfile:
    """Quản lý thông tin cấu hình thiết bị di động."""
    def __init__(self, params: Optional[Dict[str, Any]] = None):
        self.params = dict(HAR_DEVICE)
        if params:
            self.params.update(params)

    @classmethod
    def default(cls):
        return cls()

    def to_dict(self) -> dict:
        return dict(self.params)

    def __getattr__(self, item: str) -> Any:
        if item in self.params:
            return self.params[item]
        raise AttributeError(f"'DeviceProfile' object has no attribute '{item}'")

    def __getitem__(self, item: str) -> Any:
        return self.params[item]


def http_post_curl(url: str, body: Optional[str] = None, zcid: Optional[str] = None, timeout: int = 30) -> dict:
    """Gửi HTTP/2 POST qua cURL với headers chuẩn Zalo Native."""
    cmd = [
        "curl", "--http2", "-sS", "-m", str(timeout), "-X", "POST", url,
        "-H", f"user-agent: {DEFAULT_USER_AGENT}",
        "-H", "accept: */*",
        "-H", "accept-encoding: gzip,deflate",
        "-H", "operator: -1",
        "-H", "networktype: 0",
        "-H", f"clientversion: {DEFAULT_CLIENT_VERSION}",
        "-H", "content-type: application/x-www-form-urlencoded",
        "-H", "v: v2",
        "-H", "platform: 1",
        "-H", "nretry: 1"
    ]
    if zcid:
        cmd += ["-H", f"zcid: {zcid}"]
    if body:
        cmd += ["--data", body]

    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"raw": r.stdout[:300], "error_code": -1}


def http_post_json_curl(url: str, body: Optional[str] = None, zcid: Optional[str] = None, cookie: Optional[str] = None, timeout: int = 30) -> dict:
    """Gửi HTTP/2 POST dạng Webview JSON/Form qua cURL."""
    cmd = [
        "curl", "--http2", "--compressed", "-sS", "-m", str(timeout), "-X", "POST", url,
        "-H", "user-agent: Mozilla/5.0 (Linux; Android 11; SM-J610F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "-H", "accept: application/json, text/plain, */*",
        "-H", "accept-encoding: gzip,deflate",
        "-H", "content-type: application/x-www-form-urlencoded",
        "-H", "origin: https://accounts.zalo.me",
        "-H", "referer: https://accounts.zalo.me/",
        "-H", f"clientversion: {DEFAULT_CLIENT_VERSION}",
        "-H", "v: v2",
        "-H", "platform: 1"
    ]
    if zcid:
        cmd += ["-H", f"zcid: {zcid}"]
    if cookie:
        cmd += ["-H", f"cookie: {cookie}"]
    if body:
        cmd += ["--data", body]

    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"raw": r.stdout[:300], "error_code": -1}
