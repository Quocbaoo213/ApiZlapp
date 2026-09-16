import os
import sys
import time
import json
import base64
import secrets
import logging
from typing import Dict, Any, Optional, List, Tuple
from .device import REG_URL, DEFAULT_CLIENT_VERSION, DEFAULT_API_KEY, DEFAULT_SECRET, DEFAULT_BASE_KEY, norm_phone, pwd_hash, gen_zcid96, is_valid_zcid, base_params, enc_body, http_post_curl
from .captcha import captcha_flow
from .two_factor import TwoFactorAuth, FriendAuth
from .probe import probe_socket_authen
from .session import extract_all, read_from_zaloprefs, save_session_file
logger = logging.getLogger('core.login.password')

class PasswordAuth:

    def __init__(self, zcid: Optional[str]=None, zcid_path: Optional[str]=None, api_key: str=DEFAULT_API_KEY, secret: str=DEFAULT_SECRET, client_version: str=DEFAULT_CLIENT_VERSION, renew_zcid: bool=False):
        self.zcid_path = zcid_path or 'zcid_trusted.txt'
        self.api_key = api_key
        self.secret = secret
        self.client_version = client_version
        self.zcid = self._init_zcid(zcid, renew_zcid)

    def _init_zcid(self, zcid: Optional[str], renew_zcid: bool) -> str:
        if zcid and is_valid_zcid(zcid):
            val = zcid.strip()
            self._save_zcid_to_file(val)
            return val
        if os.path.exists(self.zcid_path) and (not renew_zcid):
            try:
                with open(self.zcid_path, 'r', encoding='utf-8') as f:
                    cached = f.read().strip()
                if is_valid_zcid(cached):
                    logger.info(f'Su dung ZCID tu file: {cached[:24]}...')
                    return cached
                else:
                    logger.warning('ZCID trong file khong hop le, sinh moi.')
            except Exception as e:
                logger.warning(f'Loi doc ZCID file ({e}), sinh moi.')
        new_zcid = gen_zcid96()
        self._save_zcid_to_file(new_zcid)
        logger.info(f'Da sinh ZCID moi: {new_zcid[:24]}...')
        return new_zcid

    def _save_zcid_to_file(self, val: str):
        try:
            with open(self.zcid_path, 'w', encoding='utf-8') as f:
                f.write(val.strip())
        except Exception:
            pass

    def authenticate(self, phone: str, password: str, real_friends: Optional[List[str]]=None, out_session_path: str='fresh_session.json', zaloprefs_path: Optional[str]=None, target_uid: Optional[str | int]=None, probe_socket: bool=True) -> Dict[str, Any]:
        ph = norm_phone(phone)
        t_start = time.time()
        logger.info('Xac thuc so dien thoai (phone/verify)...')
        p1 = base_params(self.zcid, ph, password)
        p1.update({'password': '', 'imei': f'{secrets.randbelow(9 * 10 ** 14) + 10 ** 14}', 'android_id': secrets.token_hex(8), 'device_spec_id': f'samsung-{secrets.token_hex(8)}', 'serial_number': f'R58M{secrets.token_hex(6).upper()}', 'device_identifier': '', 'zcid': '1_' + self.zcid})
        r1 = http_post_curl(f'{REG_URL}/api/v1/login/phone/verify', enc_body(p1, self.zcid, self.api_key, self.secret), self.zcid)
        ec1 = r1.get('error_code')
        st = (r1.get('data') or {}).get('sessionToken', '')
        if ec1 == 2060:
            logger.info('Phat hien Captcha truot, dang giai tu dong...')
            cap_session = (r1.get('data') or {}).get('sessionToken', '')
            token = captcha_flow(cap_session, zcid=self.zcid)
            if not token:
                raise ValueError('Giai Captcha truot that bai hoac bi tu choi.')
            p1b = dict(p1)
            p1b['captcha_token'] = token
            r1 = http_post_curl(f'{REG_URL}/api/v1/login/phone/verify', enc_body(p1b, self.zcid, self.api_key, self.secret), self.zcid)
            ec1 = r1.get('error_code')
            st = (r1.get('data') or {}).get('sessionToken', '')
        if ec1 not in (0, None) and (not st):
            raise ValueError(f"Xac thuc so dien thoai that bai: {r1.get('error_message', json.dumps(r1))}")
        logger.info('Gui thong tin dang nhap (activeAccountByPassword)...')
        p2 = dict(p1)
        p2['password'] = pwd_hash(ph, password)
        if st:
            p2['session_token'] = st
        r2 = http_post_curl(f'{REG_URL}/api/register/activeAccountByPassword', enc_body(p2, self.zcid, self.api_key, self.secret), self.zcid)
        ec2 = r2.get('error_code')
        d2 = r2.get('data') or {}
        if ec2 == 0 and (d2.get('keySet') or d2.get('session_key')):
            logger.info('Dang nhap thanh cong (thiet bi tin cay)')
            return self._process_login_success(d2, t_start, out_session_path, zaloprefs_path, target_uid, probe_socket)
        if ec2 != 2048:
            if ec2 == 2017:
                raise ValueError('Mat khau khong chinh xac (Ma 2017).')
            raise ValueError(f"Dang nhap that bai voi ma loi {ec2}: {r2.get('error_message', json.dumps(r2))}")
        secure_url = d2.get('secureUrl', '')
        session_token_2fa = secure_url.split('session=')[-1].split('&')[0] if 'session=' in secure_url else ''
        if not session_token_2fa:
            raise ValueError(f'Khong tim thay session 2FA: {secure_url}')
        cookie_2fa = f'accounts.zalo.me_zacc_session={session_token_2fa}'
        ok2fa = False
        try:
            vt = TwoFactorAuth.execute_2fa_flow(session_token_2fa)
            if vt:
                logger.info('Xac thuc 2FA (verifyAccount)...')
                pb = base_params(self.zcid, ph, password)
                pb.update({'imei': p1['imei'], 'android_id': p1['android_id'], 'device_spec_id': p1['device_spec_id'], 'serial_number': p1['serial_number'], 'device_identifier': '', 'zcid': '1_' + self.zcid, 'verificationToken': vt, 'ckeyset': 'AAAVH3sm6OE', 'ts': '0', 'local_time': str(int(time.time() * 1000))})
                rb = http_post_curl(f'{REG_URL}/api/register/verifyAccount', enc_body(pb, self.zcid, self.api_key, self.secret), self.zcid)
                ecb = rb.get('error_code')
                d5 = rb.get('data') or {}
                if ecb == 0 and (d5.get('keySet') or d5.get('session_key')):
                    return self._process_login_success(d5, t_start, out_session_path, zaloprefs_path, target_uid, probe_socket)
                ok2fa = True
        except (EOFError, KeyboardInterrupt):
            raise
        except Exception as ex_2fa:
            logger.warning(f'Loi khi thuc hien luong 2FA: {ex_2fa}')
        if not ok2fa:
            at = FriendAuth.execute_friend_flow(session=session_token_2fa, zcid=self.zcid, cookie=cookie_2fa, real_friends=real_friends)
            if not at:
                raise PermissionError('Khong the hoan tat xac thuc 2 buoc.')
            logger.info('Xac thuc qua danh sach ban be...')
            pb = base_params(self.zcid, ph, password)
            pb.update({'imei': p1['imei'], 'android_id': p1['android_id'], 'device_spec_id': p1['device_spec_id'], 'serial_number': p1['serial_number'], 'device_identifier': '', 'zcid': '1_' + self.zcid, 'verificationToken': at, 'ckeyset': 'AAAVH3sm6OE', 'ts': '0', 'local_time': str(int(time.time() * 1000))})
            rb = http_post_curl(f'{REG_URL}/api/register/verifyAccount', enc_body(pb, self.zcid, self.api_key, self.secret), self.zcid)
            ecb = rb.get('error_code')
            d5 = rb.get('data') or {}
            if ecb != 0 or not (d5.get('keySet') or d5.get('session_key')):
                raise ValueError(f"Xac thuc tai khoan that bai: {rb.get('error_message', json.dumps(rb))}")
            return self._process_login_success(d5, t_start, out_session_path, zaloprefs_path, target_uid, probe_socket)

    def _process_login_success(self, data: dict, t_start: float, out_session_path: str, zaloprefs_path: Optional[str]=None, target_uid: Optional[str | int]=None, probe_socket: bool=True) -> Dict[str, Any]:
        ks = data.get('keySet') or {}
        ksid = ks.get('keySetId', '')
        dk_raw = ks.get('keySetValue', '')
        sk = data.get('session_key', '')
        uid = str(data.get('user_id', ''))
        servers = [s for s in data.get('socketServers') or data.get('uploadServers') or [] if ':' not in s.get('host', '')]
        if zaloprefs_path and (not dk_raw or not ksid):
            uid_lookup = target_uid or uid
            if uid_lookup:
                try:
                    dk_pref, ksid_pref = read_from_zaloprefs(zaloprefs_path, uid_lookup)
                    if dk_pref:
                        dk_raw = dk_pref
                        ksid = ksid_pref or ksid
                except Exception as ex:
                    logger.warning(f'Loi doc zaloprefs: {ex}')
        if not dk_raw or not sk:
            raise ValueError('Khong nhan duoc du bo khoa tu server.')
        dk_bytes = base64.b64decode(dk_raw) if isinstance(dk_raw, str) and dk_raw.endswith('=') else bytes.fromhex(dk_raw) if isinstance(dk_raw, str) and len(dk_raw) == 64 else dk_raw if isinstance(dk_raw, bytes) else b''
        session_dict = {'uid': int(uid) if uid.isdigit() else 0, 'dk_hex': dk_bytes.hex(), 'dk_b64': base64.b64encode(dk_bytes).decode('utf-8'), 'ksid': ksid, 'session_key': sk, 'cryptkey': data.get('CrypKey', ''), 'sign': data.get('sign', ''), 'token': data.get('token', ''), 'ssPubKey': data.get('ssPubKey', ''), 'socketServers': servers, 'zcid': self.zcid, 'login_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
        save_session_file(session_dict, out_session_path)
        logger.info(f'Da luu session vao: {out_session_path}')
        if probe_socket:
            logger.info('Kiem tra ket noi Socket PROV...')
            uid_int = int(uid) if uid.isdigit() else 0
            results, ok = probe_socket_authen(sk=sk, dk=dk_bytes, ksid=ksid, servers=servers[:8], uid_int=uid_int)
            if ok:
                logger.info('Ket noi Socket PROV thanh cong!')
        return session_dict

def login(phone: str, password: str, real_friends: Optional[List[str]]=None, out_session_path: str='fresh_session.json', zcid: Optional[str]=None, renew_zcid: bool=False, zaloprefs_path: Optional[str]=None, target_uid: Optional[str | int]=None, probe_socket: bool=True) -> Dict[str, Any]:
    auth = PasswordAuth(zcid=zcid, renew_zcid=renew_zcid)
    return auth.authenticate(phone=phone, password=password, real_friends=real_friends, out_session_path=out_session_path, zaloprefs_path=zaloprefs_path, target_uid=target_uid, probe_socket=probe_socket)
