#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/login/password.py — Đăng nhập 2 bước chuẩn qua Số điện thoại & Mật khẩu.
Tự động xử lý Captcha trượt, xác thực 2FA OTP, xác thực bạn bè và kiểm tra Socket PROV Handshake tức thì.
Tương thích 100% với zalo_login_v10.py.
"""

import os
import sys
import time
import json
import base64
import secrets
import logging
from typing import Dict, Any, Optional, List, Tuple

from .device import (
    REG_URL,
    DEFAULT_CLIENT_VERSION,
    DEFAULT_API_KEY,
    DEFAULT_SECRET,
    DEFAULT_BASE_KEY,
    norm_phone,
    pwd_hash,
    gen_zcid96,
    is_valid_zcid,
    base_params,
    enc_body,
    http_post_curl
)
from .captcha import captcha_flow
from .two_factor import TwoFactorAuth, FriendAuth
from .probe import probe_socket_authen
from .session import extract_all, read_from_zaloprefs, save_session_file

logger = logging.getLogger("core.login.password")


class PasswordAuth:
    """Xử lý toàn bộ quy trình đăng nhập Zalo qua HTTP/2 APIs và xác thực Socket PROV."""

    def __init__(
        self,
        zcid: Optional[str] = None,
        zcid_path: Optional[str] = None,
        api_key: str = DEFAULT_API_KEY,
        secret: str = DEFAULT_SECRET,
        client_version: str = DEFAULT_CLIENT_VERSION,
        renew_zcid: bool = False
    ):
        self.zcid_path = zcid_path or "zcid_trusted.txt"
        self.api_key = api_key
        self.secret = secret
        self.client_version = client_version
        self.zcid = self._init_zcid(zcid, renew_zcid)

    def _init_zcid(self, zcid: Optional[str], renew_zcid: bool) -> str:
        """Khởi tạo ZCID: Ưu tiên zcid truyền vào -> file lưu trữ -> sinh mới."""
        if zcid and is_valid_zcid(zcid):
            val = zcid.strip()
            self._save_zcid_to_file(val)
            return val

        if os.path.exists(self.zcid_path) and not renew_zcid:
            try:
                with open(self.zcid_path, 'r', encoding='utf-8') as f:
                    cached = f.read().strip()
                if is_valid_zcid(cached):
                    logger.info(f"[*] Sử dụng ZCID từ file: {cached[:24]}...")
                    return cached
                else:
                    logger.warning("[!] ZCID trong file không hợp lệ, sẽ tự động sinh mới.")
            except Exception as e:
                logger.warning(f"[!] Lỗi đọc ZCID file ({e}), sẽ sinh mới.")

        # Sinh mới ZCID 96-hex
        new_zcid = gen_zcid96()
        self._save_zcid_to_file(new_zcid)
        logger.info(f"[*] Đã sinh ZCID mới: {new_zcid[:24]}...")
        return new_zcid


    def _save_zcid_to_file(self, val: str):
        try:
            with open(self.zcid_path, 'w', encoding='utf-8') as f:
                f.write(val.strip())
        except Exception:
            pass

    def authenticate(
        self,
        phone: str,
        password: str,
        real_friends: Optional[List[str]] = None,
        out_session_path: str = "fresh_session.json",
        zaloprefs_path: Optional[str] = None,
        target_uid: Optional[str | int] = None,
        probe_socket: bool = True
    ) -> Dict[str, Any]:
        """
        Thực hiện toàn bộ quy trình đăng nhập:
        1. phone/verify (tự động giải captcha slide nếu mã 2060)
        2. activeAccountByPassword
           - Thành công trực tiếp (Trusted Device)
           - 2048: Yêu cầu 2FA OTP hoặc Xác thực Bạn bè
        3. verifyAccount với verificationToken + ckeyset
        4. Lưu fresh_session.json
        5. Kiểm tra socket PROV authen tức thì
        """
        ph = norm_phone(phone)
        t_start = time.time()
        print("=" * 62)
        print(f"  🚀 ZALO FRESH LOGIN (Auto Captcha + 2FA / Friend Verify)")
        print(f"  ⏰ Thời gian bắt đầu: {time.strftime('%H:%M:%S')}")
        print("=" * 62)

        # ── BƯỚC 1: XÁC THỰC SỐ ĐIỆN THOẠI ──
        print("\n[1] Xác thực số điện thoại (phone/verify)...")
        p1 = base_params(self.zcid, ph, password)
        p1.update({
            "password": "",
            "imei": f"{secrets.randbelow(9 * 10**14) + 10**14}",
            "android_id": secrets.token_hex(8),
            "device_spec_id": f"samsung-{secrets.token_hex(8)}",
            "serial_number": f"R58M{secrets.token_hex(6).upper()}",
            "device_identifier": "",
            "zcid": "1_" + self.zcid
        })

        r1 = http_post_curl(f"{REG_URL}/api/v1/login/phone/verify", enc_body(p1, self.zcid, self.api_key, self.secret), self.zcid)
        ec1 = r1.get('error_code')
        st = (r1.get('data') or {}).get('sessionToken', '')
        print(f"    Mã phản hồi: {ec1}")

        # Xử lý Captcha trượt tự động nếu gặp lỗi 2060
        if ec1 == 2060:
            print("    ⚠️ Phát hiện CAPTCHA trượt (2060) — Đang tiến hành giải tự động...")
            cap_session = (r1.get('data') or {}).get('sessionToken', '')
            token = captcha_flow(cap_session, zcid=self.zcid)
            if not token:
                raise ValueError("Giải Captcha trượt thất bại hoặc bị từ chối.")

            p1b = dict(p1)
            p1b["captcha_token"] = token
            r1 = http_post_curl(f"{REG_URL}/api/v1/login/phone/verify", enc_body(p1b, self.zcid, self.api_key, self.secret), self.zcid)
            ec1 = r1.get('error_code')
            st = (r1.get('data') or {}).get('sessionToken', '')
            print(f"    Thử lại sau Captcha: ec={ec1}")

        if ec1 not in (0, None) and not st:
            raise ValueError(f"Xác thực số điện thoại thất bại: {r1.get('error_message', json.dumps(r1))}")

        # ── BƯỚC 2: ĐĂNG NHẬP MẬT KHẨU ──
        print("\n[2] Gửi thông tin đăng nhập (activeAccountByPassword)...")
        p2 = dict(p1)
        p2["password"] = pwd_hash(ph, password)
        if st:
            p2["session_token"] = st

        r2 = http_post_curl(f"{REG_URL}/api/register/activeAccountByPassword", enc_body(p2, self.zcid, self.api_key, self.secret), self.zcid)
        ec2 = r2.get('error_code')
        d2 = r2.get('data') or {}
        print(f"    Mã phản hồi: {ec2}")

        session_result = None

        # Trường hợp A: Đăng nhập thành công trực tiếp (Thiết bị tin cậy / Trusted Device)
        if ec2 == 0 and (d2.get('keySet') or d2.get('session_key')):
            print("    ✔ Đăng nhập THÀNH CÔNG trực tiếp (Thiết bị tin cậy, không cần 2FA)!")
            session_result = self._process_login_success(d2, t_start, out_session_path, zaloprefs_path, target_uid, probe_socket)
            return session_result

        # Trường hợp B: Bắt buộc xác thực 2 bước (2FA hoặc Bạn bè)
        if ec2 != 2048:
            if ec2 == 2017:
                raise ValueError("Mật khẩu không chính xác (Mã 2017).")
            raise ValueError(f"Đăng nhập thất bại với mã lỗi {ec2}: {r2.get('error_message', json.dumps(r2))}")

        # Bóc tách session 2FA từ secureUrl
        secure_url = d2.get('secureUrl', '')
        session_token_2fa = secure_url.split('session=')[-1].split('&')[0] if 'session=' in secure_url else ''
        if not session_token_2fa:
            raise ValueError(f"Không tìm thấy session 2FA trong phản hồi server: {secure_url}")

        cookie_2fa = f"accounts.zalo.me_zacc_session={session_token_2fa}"
        ok2fa = False

        # ── BƯỚC 3a: 2FA VERIFICATION CENTER (SMS / Email / Cuộc gọi / Tổng đài) ──
        try:
            vt = TwoFactorAuth.execute_2fa_flow(session_token_2fa)
            if vt:
                print("\n[3b] verifyAccount (2FA token + ckeyset)...")
                pb = base_params(self.zcid, ph, password)
                pb.update({
                    "imei": p1["imei"],
                    "android_id": p1["android_id"],
                    "device_spec_id": p1["device_spec_id"],
                    "serial_number": p1["serial_number"],
                    "device_identifier": "",
                    "zcid": "1_" + self.zcid,
                    "verificationToken": vt,
                    "ckeyset": "AAAVH3sm6OE",
                    "ts": "0",
                    "local_time": str(int(time.time() * 1000))
                })
                rb = http_post_curl(f"{REG_URL}/api/register/verifyAccount", enc_body(pb, self.zcid, self.api_key, self.secret), self.zcid)
                ecb = rb.get('error_code')
                print(f"    ec={ecb} {rb.get('error_message', '')}")
                d5 = rb.get('data') or {}
                if ecb == 0 and (d5.get('keySet') or d5.get('session_key')):
                    return self._process_login_success(d5, t_start, out_session_path, zaloprefs_path, target_uid, probe_socket)
                ok2fa = True
        except (EOFError, KeyboardInterrupt):
            raise
        except Exception as ex_2fa:
            logger.warning(f"[!] Lỗi khi thực hiện luồng 2FA: {ex_2fa}")

        if not ok2fa:
            print("    (2FA không khả dụng — fallback friend verify)")

        # ── BƯỚC 3: XÁC THỰC BẠN BÈ (Friend Verification) ──
        at = FriendAuth.execute_friend_flow(
            session=session_token_2fa,
            zcid=self.zcid,
            cookie=cookie_2fa,
            real_friends=real_friends
        )

        if not at:
            raise PermissionError("Không thể hoàn tất xác thực 2 bước (2FA hoặc Bạn bè).")

        # ── BƯỚC 4: verifyAccount (Friend Verify token + ckeyset) ──
        print("\n[4] verifyAccount (random dev + ckeyset)...")
        pb = base_params(self.zcid, ph, password)
        pb.update({
            "imei": p1["imei"],
            "android_id": p1["android_id"],
            "device_spec_id": p1["device_spec_id"],
            "serial_number": p1["serial_number"],
            "device_identifier": "",
            "zcid": "1_" + self.zcid,
            "verificationToken": at,
            "ckeyset": "AAAVH3sm6OE",
            "ts": "0",
            "local_time": str(int(time.time() * 1000))
        })

        rb = http_post_curl(f"{REG_URL}/api/register/verifyAccount", enc_body(pb, self.zcid, self.api_key, self.secret), self.zcid)
        ecb = rb.get('error_code')
        d5 = rb.get('data') or {}
        print(f"    ec={ecb} {rb.get('error_message', '')}")

        if ecb != 0 or not (d5.get('keySet') or d5.get('session_key')):
            raise ValueError(f"Xác thực tài khoản verifyAccount thất bại: {rb.get('error_message', json.dumps(rb))}")

        return self._process_login_success(d5, t_start, out_session_path, zaloprefs_path, target_uid, probe_socket)


    def _process_login_success(
        self,
        data: dict,
        t_start: float,
        out_session_path: str,
        zaloprefs_path: Optional[str] = None,
        target_uid: Optional[str | int] = None,
        probe_socket: bool = True
    ) -> Dict[str, Any]:
        """Xử lý khi đăng nhập thành công: bóc tách khóa, lưu file và probe socket."""
        ks = data.get('keySet') or {}
        ksid = ks.get('keySetId', '')
        dk_raw = ks.get('keySetValue', '')
        sk = data.get('session_key', '')
        uid = str(data.get('user_id', ''))
        servers = [s for s in (data.get('socketServers') or data.get('uploadServers') or []) if ':' not in s.get('host', '')]

        # Đọc DK từ zaloprefs nếu được chỉ định
        if zaloprefs_path and (not dk_raw or not ksid):
            uid_lookup = target_uid or uid
            if uid_lookup:
                try:
                    dk_pref, ksid_pref = read_from_zaloprefs(zaloprefs_path, uid_lookup)
                    if dk_pref:
                        dk_raw = dk_pref
                        ksid = ksid_pref or ksid
                        print(f"    🔑 Đã nạp DK từ zaloprefs: {dk_pref.hex()[:24]}...")
                except Exception as ex:
                    logger.warning(f"[!] Lỗi đọc zaloprefs: {ex}")

        if not dk_raw or not sk:
            raise ValueError("Không nhận được đủ bộ khóa (DK hoặc session_key) từ server.")

        dk_bytes = base64.b64decode(dk_raw) if isinstance(dk_raw, str) and dk_raw.endswith('=') else (bytes.fromhex(dk_raw) if isinstance(dk_raw, str) and len(dk_raw) == 64 else (dk_raw if isinstance(dk_raw, bytes) else b''))

        session_dict = {
            "uid": int(uid) if uid.isdigit() else 0,
            "dk_hex": dk_bytes.hex(),
            "dk_b64": base64.b64encode(dk_bytes).decode('utf-8'),
            "ksid": ksid,
            "session_key": sk,
            "cryptkey": data.get('CrypKey', ''),
            "sign": data.get('sign', ''),
            "token": data.get('token', ''),
            "ssPubKey": data.get('ssPubKey', ''),
            "socketServers": servers,
            "zcid": self.zcid,
            "login_timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        }

        t_login = time.time()
        print(f"    ⏱️ Đăng nhập hoàn tất trong {t_login - t_start:.2f}s")
        save_session_file(session_dict, out_session_path)
        print(f"    💾 Đã lưu session vào: {out_session_path}")

        # Thử nghiệm Socket PROV Handshake tức thì (<60s từ lúc login)
        if probe_socket:
            print(f"\n[5] Kiểm tra Socket PROV Handshake tức thì (Độ trễ: {time.time() - t_login:.2f}s)...")
            uid_int = int(uid) if uid.isdigit() else 0
            results, ok = probe_socket_authen(
                sk=sk,
                dk=dk_bytes,
                ksid=ksid,
                servers=servers[:8],
                uid_int=uid_int
            )
            if ok:
                print(f"\n🏆🏆🏆 PROV AUTHEN SUCCESS! Phiên hoạt động chuẩn xác trong {time.time() - t_start:.2f}s!")
            else:
                print(f"\n⚠️ Socket PROV chưa phản hồi status 0 (Trạng thái: {[(r[2], r[3]) for r in results]}).")

        return session_dict


def login(
    phone: str,
    password: str,
    real_friends: Optional[List[str]] = None,
    out_session_path: str = "fresh_session.json",
    zcid: Optional[str] = None,
    renew_zcid: bool = False,
    zaloprefs_path: Optional[str] = None,
    target_uid: Optional[str | int] = None,
    probe_socket: bool = True
) -> Dict[str, Any]:
    """Hàm tiện ích đăng nhập nhanh từ Python script hoặc module khác."""
    auth = PasswordAuth(zcid=zcid, renew_zcid=renew_zcid)
    return auth.authenticate(
        phone=phone,
        password=password,
        real_friends=real_friends,
        out_session_path=out_session_path,
        zaloprefs_path=zaloprefs_path,
        target_uid=target_uid,
        probe_socket=probe_socket
    )
