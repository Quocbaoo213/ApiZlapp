#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/login/session.py — Quản lý trích xuất, đọc zaloprefs SQLite và lưu Session Zalo.
Tương thích 100% với zalo_login_v10.py.
"""

import os
import json
import base64
import sqlite3
import logging
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger("core.login.session")


def extract_all(response: dict) -> dict:
    """Bóc tách tất cả các khóa và thông tin xác thực từ response đăng nhập."""
    d = response.get('data') or {}
    ks = d.get('keySet') or {}
    
    val_b64 = ks.get('keySetValue', '')
    dk_hex = ''
    if val_b64:
        try:
            dk_hex = base64.b64decode(val_b64).hex()
        except Exception:
            dk_hex = str(val_b64)

    return {
        'error_code': response.get('error_code'),
        'dk_hex': dk_hex,
        'ksid': ks.get('keySetId', ''),
        'session_key': d.get('session_key', ''),
        'uid': str(d.get('user_id', '')),
        'cryptkey': d.get('CrypKey', ''),
        'sign': d.get('sign', ''),
        'token': d.get('token', ''),
        'servers': [s for s in (d.get('uploadServers') or d.get('socketServers') or []) if ':' not in s.get('host', '')],
        'raw_session_key_len': len(d.get('session_key', '')),
    }


def read_from_zaloprefs(prefs_path: str, uid: str | int) -> Tuple[bytes, str]:
    """
    Đọc trực tiếp DK (Session KeySet Value) và KeySet ID từ tệp zaloprefs (SQLite database).
    Bảng: prefs_v2
    Khóa: KEY_STRING_SOCKET_PRO_V1_KEY_SET_VALUE_{UID}, KEY_STRING_SOCKET_PRO_V1_KEY_SET_ID_{UID}
    """
    if not os.path.isfile(prefs_path):
        raise FileNotFoundError(f"Không tìm thấy tệp zaloprefs tại: {prefs_path}")

    dbp = sqlite3.connect(prefs_path)
    try:
        kv = dbp.execute(
            "SELECT value FROM prefs_v2 WHERE key=?",
            (f'KEY_STRING_SOCKET_PRO_V1_KEY_SET_VALUE_{uid}',)
        ).fetchone()

        kid = dbp.execute(
            "SELECT value FROM prefs_v2 WHERE key=?",
            (f'KEY_STRING_SOCKET_PRO_V1_KEY_SET_ID_{uid}',)
        ).fetchone()

        dk = base64.b64decode(kv[0]) if kv and kv[0] else b''
        ksid = kid[0] if kid and kid[0] else ''
        return dk, ksid
    finally:
        dbp.close()


def save_session_file(session_data: dict, filepath: str = "fresh_session.json"):
    """Lưu session dictionary ra tệp JSON hoàn chỉnh."""
    target_dir = os.path.dirname(os.path.abspath(filepath))
    if target_dir and not os.path.exists(target_dir):
        os.makedirs(target_dir, exist_ok=True)

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(session_data, f, ensure_ascii=False, indent=2)

    logger.info(f"[✔] Đã lưu session vào {filepath}")


class SessionManager:
    """Quản lý đọc và ghi session file và zaloprefs SQLite."""
    @staticmethod
    def save(data: dict, filepath: str = "fresh_session.json"):
        save_session_file(data, filepath)

    @staticmethod
    def load(filepath: str = "fresh_session.json") -> dict:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def load_zaloprefs(prefs_path: str, uid: str | int) -> Tuple[bytes, str]:
        return read_from_zaloprefs(prefs_path, uid)

    @staticmethod
    def extract_dk(data: dict) -> Optional[bytes]:
        """Trích xuất DK (32 bytes) từ session dictionary."""
        if not isinstance(data, dict):
            return None
        # 1. dk trực tiếp (bytes / hex)
        dk = data.get('dk')
        if isinstance(dk, bytes):
            return dk
        if isinstance(dk, str):
            try:
                return bytes.fromhex(dk)
            except Exception:
                pass
        # 2. dk_hex
        dk_hex = data.get('dk_hex')
        if dk_hex and isinstance(dk_hex, str):
            try:
                return bytes.fromhex(dk_hex)
            except Exception:
                pass
        # 3. dk_b64
        dk_b64 = data.get('dk_b64')
        if dk_b64 and isinstance(dk_b64, str):
            try:
                return base64.b64decode(dk_b64)
            except Exception:
                pass
        # 4. keySet.keySetValue (base64)
        ks = data.get('keySet') or (data.get('data') or {}).get('keySet')
        if isinstance(ks, dict):
            val_b64 = ks.get('keySetValue')
            if val_b64:
                try:
                    return base64.b64decode(val_b64)
                except Exception:
                    pass
        return None

    @staticmethod
    def extract_cryptkey(data: dict) -> Optional[bytes]:
        """Trích xuất cryptkey từ session dictionary."""
        if not isinstance(data, dict):
            return None
        ck = data.get('cryptkey') or data.get('CrypKey') or (data.get('data') or {}).get('CrypKey')
        if isinstance(ck, bytes):
            return ck
        if isinstance(ck, str):
            try:
                dec = base64.b64decode(ck)
                if len(dec) in (16, 32):
                    return dec
            except Exception:
                pass
            try:
                dec = bytes.fromhex(ck)
                if len(dec) in (16, 32):
                    return dec
            except Exception:
                pass
            return ck.encode('utf-8')
        return None

    @staticmethod
    def validate(data: dict) -> bool:
        """Kiểm tra tính hợp lệ tối thiểu của một session dictionary."""
        if not isinstance(data, dict):
            return False
        uid = data.get('uid') or data.get('user_id') or (data.get('data') or {}).get('user_id')
        if not uid:
            return False
        dk = SessionManager.extract_dk(data)
        if dk and len(dk) == 32:
            return True
        session_key = data.get('session_key') or (data.get('data') or {}).get('session_key')
        if session_key:
            return True
        return False
