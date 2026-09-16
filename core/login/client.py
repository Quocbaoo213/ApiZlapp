from typing import Dict, Any, Optional, List
from core.login.device import INIT_KEY, DEFAULT_API_KEY, DEFAULT_SECRET, DEFAULT_BASE_KEY, DEFAULT_CLIENT_VERSION, DEFAULT_USER_AGENT, HAR_DEVICE, HAR_LONG, gen_zcid96, pwd_hash, enc_body, norm_phone, base_params, key32_96, DeviceProfile
from core.login.captcha import solve_captcha_img, captcha_flow
from core.login.two_factor import TwoFactorAuth, FriendAuth
from core.login.probe import probe_socket_authen, probe_now, build_p110, calc_cs
from core.login.session import extract_all, read_from_zaloprefs, save_session_file, SessionManager
from core.login.password import PasswordAuth, login

class ZaloLoginClient:

    def __init__(self, zcid: Optional[str]=None, zcid_path: Optional[str]=None, api_key: str=DEFAULT_API_KEY, secret: str=DEFAULT_SECRET, client_version: str=DEFAULT_CLIENT_VERSION, renew_zcid: bool=False):
        self.auth = PasswordAuth(zcid=zcid, zcid_path=zcid_path, api_key=api_key, secret=secret, client_version=client_version, renew_zcid=renew_zcid)
        self.zcid = self.auth.zcid
        self.device_params = HAR_LONG

    def save_zcid(self, zcid: str):
        self.auth._save_zcid_to_file(zcid)
        self.zcid = zcid

    def login(self, phone: str, password: str, out_session_path: str='fresh_session.json', real_friends: Optional[List[str]]=None, zaloprefs_path: Optional[str]=None, target_uid: Optional[str | int]=None, probe_socket: bool=True) -> Dict[str, Any]:
        return self.auth.authenticate(phone=phone, password=password, real_friends=real_friends, out_session_path=out_session_path, zaloprefs_path=zaloprefs_path, target_uid=target_uid, probe_socket=probe_socket)
__all__ = ['ZaloLoginClient', 'PasswordAuth', 'login', 'solve_captcha_img', 'captcha_flow', 'TwoFactorAuth', 'FriendAuth', 'probe_socket_authen', 'probe_now', 'build_p110', 'calc_cs', 'extract_all', 'read_from_zaloprefs', 'save_session_file', 'gen_zcid96', 'pwd_hash', 'enc_body', 'norm_phone', 'base_params', 'key32_96', 'DEFAULT_API_KEY', 'DEFAULT_SECRET', 'DEFAULT_CLIENT_VERSION', 'DEFAULT_USER_AGENT', 'HAR_DEVICE', 'HAR_LONG']
