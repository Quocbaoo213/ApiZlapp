#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_login_flow.py — Unit tests cho toàn bộ module core/login v10.
"""

import unittest
from unittest.mock import MagicMock, patch
import json
import base64
import os

from core.login.device import (
    norm_phone, pwd_hash, gen_zcid96, key32_96, enc_body, base_params,
    INIT_KEY, DEFAULT_API_KEY, DEFAULT_SECRET, DEFAULT_BASE_KEY, DeviceProfile
)
from core.login.probe import build_p110, calc_cs
from core.login.session import extract_all, SessionManager
from core.login.password import PasswordAuth
from core.login.client import ZaloLoginClient


class TestLoginModuleV10(unittest.TestCase):

    def test_norm_phone(self):
        self.assertEqual(norm_phone("0993903236"), "+84993903236")
        self.assertEqual(norm_phone("+84993903236"), "+84993903236")
        self.assertEqual(norm_phone("84993903236"), "+84993903236")

    def test_zcid_and_key_derivation(self):
        zcid = gen_zcid96()
        self.assertEqual(len(zcid), 96)
        self.assertTrue(zcid.isupper())
        key = key32_96(zcid)
        self.assertEqual(len(key), 32)

    def test_pwd_hash(self):
        ph = "+84993903236"
        pw = "Password123"
        h = pwd_hash(ph, pw)
        self.assertEqual(len(h), 32)
        # Deterministic check
        h2 = pwd_hash(ph, pw)
        self.assertEqual(h, h2)

    def test_enc_body(self):
        zcid = gen_zcid96()
        p = {"test_key": "test_value"}
        body = enc_body(p, zcid)
        self.assertIn("sig=", body)
        self.assertIn("api_key=", body)
        self.assertIn("data=", body)

    def test_build_p110_and_calc_cs(self):
        sk = "pHc9.463450795.a1.QXB8sTg4XyvnDXZLseI7pjg4XyxQX8VEsmRUPB24Xyu"
        uid = 463450795
        p110 = build_p110(sk, uid)
        self.assertEqual(len(p110), 110)

        cs = calc_cs(uid, 0xFFFFFFFF, 1, 3, 5, bytes([1, 1]))
        self.assertIsInstance(cs, int)
        self.assertTrue(0 <= cs <= 0xFFFFFFFF)

    def test_extract_all(self):
        mock_resp = {
            "error_code": 0,
            "data": {
                "user_id": "463450795",
                "session_key": "sample_sk",
                "CrypKey": "sample_cryptkey",
                "sign": "sample_sign",
                "token": "sample_token",
                "keySet": {
                    "keySetId": "KSID_TEST",
                    "keySetValue": base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
                },
                "socketServers": [
                    {"host": "1.2.3.4", "port": 443, "pubKey": "sample_pub"}
                ]
            }
        }
        creds = extract_all(mock_resp)
        self.assertEqual(creds['error_code'], 0)
        self.assertEqual(creds['uid'], "463450795")
        self.assertEqual(creds['ksid'], "KSID_TEST")
        self.assertEqual(creds['session_key'], "sample_sk")
        self.assertEqual(len(creds['servers']), 1)

    @patch("core.login.password.http_post_curl")
    @patch("core.login.password.probe_socket_authen")
    def test_direct_login_flow(self, mock_probe, mock_http):
        mock_http.side_effect = [
            # step 1: phone/verify
            {"error_code": 0, "data": {"sessionToken": "st_123"}},
            # step 2: activeAccountByPassword
            {
                "error_code": 0,
                "data": {
                    "user_id": "463450795",
                    "session_key": "pHc9.463450795.sample_sk",
                    "CrypKey": "test_cryptkey",
                    "sign": "test_sign",
                    "token": "test_token",
                    "keySet": {
                        "keySetId": "KSID_TEST",
                        "keySetValue": base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
                    },
                    "socketServers": [
                        {"host": "1.2.3.4", "port": 443, "pubKey": "pub_key_test"}
                    ]
                }
            }
        ]
        mock_probe.return_value = ([("1.2.3.4", 443, 4, 0)], True)

        auth = PasswordAuth(zcid="A" * 96)
        res = auth.authenticate(
            phone="0993903236",
            password="MyPassword123",
            out_session_path="/tmp/test_session.json",
            probe_socket=True
        )

        self.assertEqual(res['uid'], 463450795)
        self.assertEqual(res['ksid'], "KSID_TEST")
        self.assertEqual(res['session_key'], "pHc9.463450795.sample_sk")


if __name__ == "__main__":
    unittest.main()
