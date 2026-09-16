#!/usr/bin/env python3
"""
test_user_info.py — Bộ kiểm thử tự động cho module zalo_user_info.py và lệnh /info trong main.py
"""

import unittest
import time
from zalo_user_info import ZaloUserInfoAPI, sign_params, extract_target_uid, API_SECRET
from main import generate_bot_response


class TestZaloUserInfo(unittest.TestCase):
    def test_sign_params(self):
        """Kiểm thử thuật toán sinh chữ ký sig MD5 sorted keys."""
        params = {
            "api_key": "0be3747aacc670a51a83230bcfe80173",
            "clientType": "1",
            "clientVersion": "260802903",
            "session_key": "test_session",
            "sign": "test_sign",
            "ts": "1789354128"
        }
        sig1 = sign_params(params, secret=API_SECRET)
        self.assertIsInstance(sig1, str)
        self.assertEqual(len(sig1), 32)
        # Verify deterministic
        sig2 = sign_params(params, secret=API_SECRET)
        self.assertEqual(sig1, sig2)

    def test_extract_target_uid(self):
        """Kiểm thử trích xuất target UID từ @tag, arg số, và quote reply."""
        bot_uid = 463450795
        target_uid = 277635559

        # Case 1: Tag chứa bot và user khác -> chọn user khác
        res1 = extract_target_uid("", mentioned_uids=[bot_uid, target_uid], bot_uid=bot_uid)
        self.assertEqual(res1, target_uid)

        # Case 2: Chỉ tag bot -> trả về None (hiển thị bot info)
        res2 = extract_target_uid("", mentioned_uids=[bot_uid], bot_uid=bot_uid)
        self.assertIsNone(res2)

        # Case 3: Arg dạng số UID (VD: /info 277635559)
        res3 = extract_target_uid("277635559", bot_uid=bot_uid)
        self.assertEqual(res3, target_uid)

        # Case 4: Arg không phải số và không có tag -> None
        res4 = extract_target_uid("abc", bot_uid=bot_uid)
        self.assertIsNone(res4)

        # Case 5: Reply quote từ user khác
        res5 = extract_target_uid("", quote_owner_id=target_uid, bot_uid=bot_uid)
        self.assertEqual(res5, target_uid)

        # Case 6: Reply quote từ chính bot -> None
        res6 = extract_target_uid("", quote_owner_id=bot_uid, bot_uid=bot_uid)
        self.assertIsNone(res6)

    def test_format_user_info(self):
        """Kiểm thử định dạng thẻ thông tin người dùng với chuẩn Zalo (0=Nam, 1=Nữ)."""
        user_mock = {
            "userId": 432577723,
            "displayName": "Qbn",
            "alias": "Quý Bửu",
            "uname": "qbn_official",
            "gender": 0,  # Nam trong chuẩn Zalo
            "dob": 1206032400,
            "sdob": "21/03/2008",
            "phoneNumber": "+84384872105",
            "isFr": 1,
            "isBlock": 0,
            "avatar": "https://example.com/avatar.jpg",
            "business_account": {"package_id": 1, "label_name": "Business"}
        }
        card = ZaloUserInfoAPI.format_user_info(user_mock)
        self.assertIn("THÔNG TIN NGƯỜI DÙNG", card)
        self.assertIn("Qbn", card)
        self.assertIn("Quý Bửu", card)
        self.assertIn("432577723", card)
        self.assertIn("@qbn_official", card)
        self.assertIn("Nam", card)
        self.assertIn("21/03/2008", card)
        self.assertIn("+84384872105", card)
        self.assertIn("Bạn bè", card)
        self.assertIn("Business", card)
        self.assertIn("https://example.com/avatar.jpg", card)

    def test_generate_bot_response_info_command(self):
        """Kiểm thử routing lệnh .profile / .info trong generate_bot_response."""
        bot_uid = 463450795
        api = ZaloUserInfoAPI()
        # Mock pre-populated cache
        now = time.time()
        api._cache[277635559] = (now, {
            "userId": 277635559,
            "displayName": "Đỗ Tùng",
            "gender": 2,
            "isFr": 1,
            "isBlock": 0
        })
        api._cache[432577723] = (now, {
            "userId": 432577723,
            "displayName": "Qbn",
            "gender": 0,
            "isFr": 1,
            "isBlock": 0
        })

        # 1. .profile không tham số -> hướng dẫn lệnh
        resp_guide = generate_bot_response(".profile", prefix=".", bot_uid=bot_uid, user_info_api=api)
        self.assertIn("HƯỚNG DẪN LỆNH .profile", resp_guide)

        # 2. .profile <uid>
        resp_user = generate_bot_response(".profile 277635559", prefix=".", bot_uid=bot_uid, user_info_api=api)
        self.assertIn("THÔNG TIN NGƯỜI DÙNG", resp_user)
        self.assertIn("277635559", resp_user)
        self.assertIn("Đỗ Tùng", resp_user)

        # 3. .profile kèm tag
        resp_tag = generate_bot_response(".profile @Qbn", prefix=".", bot_uid=bot_uid, mentioned_uids=[432577723], user_info_api=api)
        self.assertIn("THÔNG TIN NGƯỜI DÙNG", resp_tag)
        self.assertIn("432577723", resp_tag)

        # 4. .profile reply quote
        resp_quote = generate_bot_response(".profile", prefix=".", bot_uid=bot_uid, quote_owner_id=432577723, user_info_api=api)
        self.assertIn("THÔNG TIN NGƯỜI DÙNG", resp_quote)
        self.assertIn("432577723", resp_quote)

    def test_cache_ttl(self):
        """Kiểm thử bộ nhớ đệm cache."""
        api = ZaloUserInfoAPI()
        now = time.time()
        api._cache[277635559] = (now, {
            "userId": 277635559,
            "displayName": "Đỗ Tùng",
            "gender": 2,
            "isFr": 1,
            "isBlock": 0
        })
        user = api.get_user_info(277635559)
        self.assertIsNotNone(user)
        self.assertEqual(user["displayName"], "Đỗ Tùng")


if __name__ == "__main__":
    unittest.main()
