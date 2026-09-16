#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/login/two_factor.py — Quản lý các phương thức xác thực nâng cao (2FA OTP & Bạn bè).
Bao gồm:
1. Nhánh 2FA Verification Center (SMS, Email, Cuộc gọi OTP, Tổng đài)
2. Nhánh Friend Verification (Auto-match theo danh sách tên hoặc lựa chọn thủ công)
Tương thích 100% với zalo_login_v10.py.
"""

import sys
import re
import json
import logging
import subprocess
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple, Set

from .device import ZMVC_URL, ACC_URL, http_post_json_curl

logger = logging.getLogger("core.login.two_factor")

METHOD_NAMES = {
    1: "SMS",
    2: "Email",
    3: "Số điện thoại / Cuộc gọi",
    6: "Tổng đài OTP"
}


class TwoFactorAuth:
    """Quản lý xác thực 2 lớp qua Webview Verification Center."""

    @staticmethod
    def get_webview_html(session: str) -> str:
        """Tải mã HTML của giao diện 2FA từ Verification Center."""
        url = f"{ZMVC_URL}/2fa?session={session}&lang=vi"
        cmd = [
            "curl", "--compressed", "-sS", "-m", "30", url,
            "-H", "user-agent: Mozilla/5.0 (Linux; Android 11; SM-J610F) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/83.0.4103.120 Mobile Safari/537.36 Zalo android/260801901",
            "-H", "x-requested-with: com.zing.zalo"
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
        return r.stdout

    @staticmethod
    def post_vc_json(url: str, session: str, data: dict) -> dict:
        """Gửi request JSON tới Verification Center API."""
        cmd = [
            "curl", "--compressed", "-sS", "-m", "30", "-X", "POST", url,
            "-H", "content-type: application/json",
            "-H", "accept: application/json, text/plain, */*",
            "-H", f"origin: {ZMVC_URL}",
            "-H", f"referer: {ZMVC_URL}/2fa?session={session}&lang=vi",
            "-H", "user-agent: Mozilla/5.0 (Linux; Android 11; SM-J610F) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/83.0.4103.120 Mobile Safari/537.36 Zalo android/260801901",
            "--data", json.dumps(data, separators=(',', ':'))
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
        try:
            return json.loads(r.stdout)
        except Exception:
            return {"raw": r.stdout[:300], "error_code": -1}

    @classmethod
    def extract_available_methods(cls, session: str) -> Tuple[List[int], Dict[int, str], Set[int]]:
        """Bóc tách danh sách các phương thức 2FA khả dụng và bị khóa (rate-limited)."""
        methods: List[int] = []
        dests: Dict[int, str] = {}
        blocked: Set[int] = set()

        try:
            rhtml = cls.get_webview_html(session)
            for m in re.finditer(r'<div class="login-option"[^>]*>(.*?)<hr class="divider"', rhtml, re.S):
                blk_all = m.group(1)
                mm0 = re.search(r'method="(\d+)"', blk_all)
                if not mm0:
                    continue
                mid = int(mm0.group(1))
                methods.append(mid)
                dm = re.search(r'button-description">(.*?)</div>', blk_all, re.S)
                desc = re.sub(r'<[^>]+>|\s+', ' ', dm.group(1)).strip() if dm else ''
                dests[mid] = desc
                if re.search(r'dùng hết|hết số lần|không khả dụng|tạm thời', desc, re.I):
                    blocked.add(mid)

            methods = sorted(set(methods))
        except Exception as ex:
            logger.warning(f"[!] Lỗi phân tích HTML 2FA: {ex}")

        return methods, dests, blocked

    @classmethod
    def execute_2fa_flow(cls, session: str, interactive: bool = True) -> Optional[str]:
        """
        Thực hiện toàn bộ quy trình 2FA chuẩn zalo_login_v10:
        1. Liệt kê phương thức khả dụng (SMS, email, SĐT, tổng đài OTP)
        2. Người dùng tự chọn phương thức mong muốn (input)
        3. Gửi mã OTP tới phương thức đã chọn
        4. Người dùng tự nhập mã OTP (input, tối đa 3 lần)
        5. Trả về verificationToken
        """
        names = {1: "SMS", 2: "email", 3: "SĐT", 6: "tổng đài OTP"}
        methods, dests, blocked = cls.extract_available_methods(session)
        avail = [m for m in methods if m not in blocked]

        print("[3a] 2FA — GET /2fa?session=... (webview html)...")
        print("    methods khả dụng:")
        for mm in methods:
            mark = " ⛔" if mm in blocked else ""
            print(f"      [{mm}] {names.get(mm, '?')}" + (f" → {dests[mm]}" if dests.get(mm) else "") + mark)

        if blocked:
            print(f"    ⛔ rate-limited: {sorted(blocked)} — dùng method khác hoặc chờ reset")

        if not avail:
            print("    (2FA không khả dụng — fallback friend verify)")
            return None

        pick = avail[0]
        if len(avail) > 1:
            try:
                ch = input(f"  chọn method {avail} (enter = {avail[0]}): ").strip()
                if ch.isdigit() and int(ch) in avail:
                    pick = int(ch)
            except (EOFError, KeyboardInterrupt):
                raise
            except Exception:
                pick = avail[0]

        nm = names.get(pick, str(pick))
        print(f"  → method {pick} ({nm}): POST methods (gửi mã)...")

        q2fa = urllib.parse.urlencode({"session": session, "lang": "vi"})
        r3m = cls.post_vc_json(f"{ZMVC_URL}/api/v1/2fa/methods?{q2fa}", session, {"method": pick})
        ec3m = r3m.get('error_code')
        print(f"    methods: ec={ec3m} {r3m.get('error_message', '')}")
        if ec3m != 0:
            return None

        vt = ""
        for attempt in range(3):
            try:
                otp = input(f"  ✉️ Nhập mã ({nm}) [lần {attempt+1}/3]: ").strip()
            except (EOFError, KeyboardInterrupt):
                raise
            except Exception:
                break

            if not otp:
                continue

            r3v = cls.post_vc_json(f"{ZMVC_URL}/api/v1/2fa/verify?{q2fa}&method={pick}", session, {"method": pick, "code": otp})
            ecv = r3v.get('error_code')
            vt = (r3v.get('data') or {}).get('verificationToken', '')
            print(f"    verify: ec={ecv} {r3v.get('error_message', '')} | token: {vt[:30] + '...' if vt else 'FAIL'}")
            if vt:
                return vt

            # Sai mã: KHÔNG resend (mã cũ vẫn dùng được, resend → -1001 rate-limit)
            if attempt < 2:
                print(f"    → nhập lại mã (cùng mã đã gửi)...")

        return None


class FriendAuth:
    """Quản lý xác thực tài khoản qua danh sách bạn bè gần đây."""

    @staticmethod
    def execute_friend_flow(
        session: str,
        zcid: str,
        cookie: str,
        real_friends: Optional[List[str]] = None,
        interactive: bool = True
    ) -> Optional[str]:
        """
        Thực hiện chu trình xác thực bạn bè chuẩn zalo_login_v10:
        1. Tải danh sách câu hỏi / bạn bè
        2. Tự động so khớp với real_friends nếu có
        3. Nếu không đủ tên → người dùng tự nhập số thứ tự các bạn bè qua input()
        4. Trả về access_token (verificationToken)
        """
        print("[3] friend verify (auto-match theo tên)...")
        http_post_json_curl(f"{ACC_URL}/verify/v3/api/check-session", body=f"session={session}", zcid=zcid, cookie=cookie)
        r3b = http_post_json_curl(f"{ACC_URL}/verify/v3/api/seq/get-question", body=f"session={session}", zcid=zcid, cookie=cookie)
        d3 = r3b.get('data') or {}
        choices = d3.get('choices', [])
        q_type = d3.get('question_type', 2)

        if not choices:
            print(f"    ❌ {json.dumps(r3b)[:200]}")
            return None

        real_friends = real_friends or []
        mapping: Dict[str, int] = {}
        for name in real_friends:
            hits = [i for i, c in enumerate(choices) if name.lower() in c.get('title', '').lower()]
            if hits:
                mapping[name] = hits[0]

        if mapping:
            print(f"    mapping: {mapping}")

        picked: List[int] = [mapping[n] for n in real_friends if n in mapping][:3]

        if len(picked) >= 2:
            print(f"    → auto chọn {len(picked)} tên: {[choices[i]['title'] for i in picked]}")
        else:
            if real_friends:
                print(f"    ⚠️ auto-match chỉ tìm được {len(picked)} tên.")
            print("    → chuyển sang chọn thủ công:")

            for i, c in enumerate(choices):
                print(f"      [{i}] {c.get('title')}")

            while True:
                try:
                    raw = input(
                        f"  Chọn ít nhất 2 tên (số thứ tự, cách nhau bằng dấu phẩy, tối đa 3): "
                    ).strip()
                    selected = [int(x.strip()) for x in raw.split(',') if x.strip()]
                except (EOFError, KeyboardInterrupt):
                    raise
                except ValueError:
                    print("    ❌ Nhập số thứ tự, ví dụ: 0,3,5")
                    continue

                # Loại trùng nhưng giữ nguyên thứ tự
                selected = list(dict.fromkeys(selected))

                if len(selected) < 2:
                    print("    ❌ Phải chọn ít nhất 2 tên.")
                    continue
                if len(selected) > 3:
                    print("    ❌ Chỉ được chọn tối đa 3 tên.")
                    continue
                if any(i < 0 or i >= len(choices) for i in selected):
                    print("    ❌ Có số thứ tự không hợp lệ.")
                    continue

                picked = selected
                break

            print(f"    → chọn thủ công: {[choices[i]['title'] for i in picked]}")

        answers = ','.join(choices[i]['value'] for i in picked)
        body = urllib.parse.urlencode({
            'session': session,
            'question_type': str(q_type),
            'answers': answers
        })

        r4 = http_post_json_curl(f"{ACC_URL}/verify/v3/api/seq/answer", body=body, zcid=zcid, cookie=cookie)
        at = (r4.get('data') or {}).get('access_token', '')
        print(f"    answer ec={r4.get('error_code')} | token len={len(at)}")
        return at if at else None

