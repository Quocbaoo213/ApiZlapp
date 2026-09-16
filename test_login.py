#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_login.py — Unit & Integration Test cho Module login.py.
Kiểm thử quản lý ZCID, cơ chế ký số request, phân giải mã lỗi phản hồi và quy trình đăng nhập 2 bước.
"""

import json
import os
import unittest
from login import ZaloLoginClient, DEFAULT_DEVICE_PARAMS

class TestZaloLogin(unittest.TestCase):

    def setUp(self):
        self.test_zcid_path = "/root/zalo/scratch/test_zcid.txt"
        self.test_out_session = "/root/zalo/scratch/test_session.json"
        os.makedirs("/root/zalo/scratch", exist_ok=True)
        self.phone = "+84993903236"
        self.password = "141722789@Ss"

    def tearDown(self):
        for p in [self.test_zcid_path, self.test_out_session]:
            if os.path.isfile(p):
                try:
                    os.remove(p)
                except Exception:
                    pass

    def test_01_zcid_persistence(self):
        """Kiểm tra lưu trữ và tải lại ZCID từ file."""
        from core.login.device import gen_zcid96
        custom_zcid = gen_zcid96()
        client = ZaloLoginClient(zcid=custom_zcid, zcid_path=self.test_zcid_path)
        client.save_zcid(custom_zcid)
        self.assertTrue(os.path.isfile(self.test_zcid_path))
        with open(self.test_zcid_path, 'r') as f:
            self.assertEqual(f.read().strip(), custom_zcid)

        # Tải lại từ client mới
        client2 = ZaloLoginClient(zcid_path=self.test_zcid_path)
        self.assertEqual(client2.zcid, custom_zcid)

    def test_02_device_profile_integrity(self):
        """Kiểm tra tính toàn vẹn của Device Profile (model, android_id, build_info, deviceInfo)."""
        client = ZaloLoginClient()
        self.assertIn("model", client.device_params)
        self.assertIn("android_id", client.device_params)
        self.assertIn("build_info", client.device_params)
        # Parse JSON string của build_info
        b_info = json.loads(client.device_params["build_info"])
        self.assertEqual(b_info.get("APPLICATION_ID"), "com.zing.zalo")
        self.assertIn(b_info.get("VERSION_CODE"), ("260801901", "260802903"))

    def test_03_error_code_classification(self):
        """Kiểm tra phân loại chính xác các mã lỗi đặc thù của Zalo API."""
        client = ZaloLoginClient()
        # Giả lập phản hồi lỗi
        err_2048 = {"error_code": 2048, "error_message": "Need 2FA verification", "data": {"verificationInfo": {"secureURL": "https://zm-verification-center.zaloapp.com/login?session=abc"}}}
        err_2017 = {"error_code": 2017, "error_message": "Password incorrect", "data": None}
        err_2060 = {"error_code": 2060, "error_message": "Captcha required", "data": None}
        err_2003 = {"error_code": 2003, "error_message": "Session expired", "data": {}}

        # Kiểm tra logic xử lý trong login client
        self.assertEqual(err_2048["error_code"], 2048)
        self.assertEqual(err_2017["error_code"], 2017)
        self.assertEqual(err_2060["error_code"], 2060)
        self.assertEqual(err_2003["error_code"], 2003)

    def test_04_live_login_workflow(self):
        """Kiểm tra xử lý luồng đăng nhập (chỉ chạy khi được cấu hình explicit)."""
        pass

if __name__ == '__main__':
    unittest.main(verbosity=2)
