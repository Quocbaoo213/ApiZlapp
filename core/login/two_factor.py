import sys
import re
import json
import logging
import subprocess
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple, Set
from .device import ZMVC_URL, ACC_URL, http_post_json_curl
logger = logging.getLogger('core.login.two_factor')
METHOD_NAMES = {1: 'SMS', 2: 'Email', 3: 'Số điện thoại / Cuộc gọi', 6: 'Tổng đài OTP'}

class TwoFactorAuth:

    @staticmethod
    def get_webview_html(session: str) -> str:
        url = f'{ZMVC_URL}/2fa?session={session}&lang=vi'
        cmd = ['curl', '--compressed', '-sS', '-m', '30', url, '-H', 'user-agent: Mozilla/5.0 (Linux; Android 11; SM-J610F) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/83.0.4103.120 Mobile Safari/537.36 Zalo android/260801901', '-H', 'x-requested-with: com.zing.zalo']
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
        return r.stdout

    @staticmethod
    def post_vc_json(url: str, session: str, data: dict) -> dict:
        cmd = ['curl', '--compressed', '-sS', '-m', '30', '-X', 'POST', url, '-H', 'content-type: application/json', '-H', 'accept: application/json, text/plain, */*', '-H', f'origin: {ZMVC_URL}', '-H', f'referer: {ZMVC_URL}/2fa?session={session}&lang=vi', '-H', 'user-agent: Mozilla/5.0 (Linux; Android 11; SM-J610F) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/83.0.4103.120 Mobile Safari/537.36 Zalo android/260801901', '--data', json.dumps(data, separators=(',', ':'))]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
        try:
            return json.loads(r.stdout)
        except Exception:
            return {'raw': r.stdout[:300], 'error_code': -1}

    @classmethod
    def extract_available_methods(cls, session: str) -> Tuple[List[int], Dict[int, str], Set[int]]:
        methods: List[int] = []
        dests: Dict[int, str] = {}
        blocked: Set[int] = set()
        try:
            rhtml = cls.get_webview_html(session)
            # Tách các khối login-option không phụ thuộc vào thẻ phân cách <hr class="divider">
            blocks = re.findall(r'(<div class="login-option"[^>]*>.*?)(?=(?:<div class="login-option"|$))', rhtml, re.S)
            for blk_all in blocks:
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

            # Dự phòng nếu HTML có cấu trúc khác nhưng vẫn chứa thuộc tính method
            if not methods:
                all_m = re.findall(r'method="(\d+)"', rhtml)
                for mid_str in all_m:
                    mid = int(mid_str)
                    if mid not in methods:
                        methods.append(mid)

            methods = sorted(set(methods))
        except Exception as ex:
            logger.warning(f'Lỗi phân tích HTML 2FA: {ex}')
        return (methods, dests, blocked)

    @classmethod
    def execute_2fa_flow(cls, session: str, interactive: bool=True) -> Optional[str]:
        names = {1: 'SMS', 2: 'Email', 3: 'Số điện thoại / Cuộc gọi', 6: 'Tổng đài OTP'}
        methods, dests, blocked = cls.extract_available_methods(session)
        avail = [m for m in methods if m not in blocked]
        logger.info('2FA webview verify...')

        if not methods and not avail:
            # Fallback nếu không parse được methods từ webview nhưng Zalo yêu cầu 2FA
            avail = [6, 1, 3]

        print('\n[2FA] Danh sách phương thức xác thực:')
        display_list = methods if methods else avail
        for mm in display_list:
            mark = ' ⛔ [Đã hết lượt / Tạm khóa]' if mm in blocked else ''
            desc = f' → {dests[mm]}' if dests.get(mm) else ''
            print(f'  [{mm}] {names.get(mm, f"Phương thức {mm}")}{desc}{mark}')

        if blocked:
            print(f'  ⛔ Phương thức bị giới hạn: {[names.get(b, str(b)) for b in sorted(blocked)]}')

        if not avail:
            if methods and interactive:
                try:
                    ch = input(f'  ⚠️ Tất cả phương thức bị đánh dấu tạm khóa. Thử chọn {methods} (hoặc Enter để bỏ qua): ').strip()
                    if ch.isdigit() and int(ch) in methods:
                        avail = [int(ch)]
                except (EOFError, KeyboardInterrupt):
                    raise
                except Exception:
                    pass
            if not avail:
                print('  [!] Không có phương thức 2FA khả dụng.')
                return None

        pick = avail[0]
        if len(avail) > 1 and interactive:
            try:
                ch = input(f'  👉 Chọn phương thức xác thực {avail} (mặc định = {avail[0]}): ').strip()
                if ch.isdigit() and int(ch) in avail:
                    pick = int(ch)
            except (EOFError, KeyboardInterrupt):
                raise
            except Exception:
                pick = avail[0]
        else:
            print(f'  👉 Sử dụng phương thức: [{pick}] {names.get(pick, str(pick))}')

        nm = names.get(pick, str(pick))
        q2fa = urllib.parse.urlencode({'session': session, 'lang': 'vi'})
        r3m = cls.post_vc_json(f'{ZMVC_URL}/api/v1/2fa/methods?{q2fa}', session, {'method': pick})
        ec3m = r3m.get('error_code')
        if ec3m != 0:
            logger.warning(f'Gửi mã qua method {pick} thất bại: {r3m.get("error_message") or ec3m}')
            return None
        vt = ''
        for attempt in range(3):
            try:
                otp = input(f'  ✉️ Nhập mã ({nm}) [lần {attempt + 1}/3]: ').strip()
            except (EOFError, KeyboardInterrupt):
                raise
            except Exception:
                break
            if not otp:
                continue
            r3v = cls.post_vc_json(f'{ZMVC_URL}/api/v1/2fa/verify?{q2fa}&method={pick}', session, {'method': pick, 'code': otp})
            ecv = r3v.get('error_code')
            vt = (r3v.get('data') or {}).get('verificationToken', '')
            if vt:
                return vt
            if attempt < 2:
                print('  ⚠️ Mã không đúng hoặc đã hết hạn, vui lòng nhập lại...')
        return None

class FriendAuth:

    @staticmethod
    def execute_friend_flow(session: str, zcid: str, cookie: str, real_friends: Optional[List[str]]=None, interactive: bool=True) -> Optional[str]:
        logger.info('Friend verify...')
        http_post_json_curl(f'{ACC_URL}/verify/v3/api/check-session', body=f'session={session}', zcid=zcid, cookie=cookie)
        r3b = http_post_json_curl(f'{ACC_URL}/verify/v3/api/seq/get-question', body=f'session={session}', zcid=zcid, cookie=cookie)
        d3 = r3b.get('data') or {}
        choices = d3.get('choices', [])
        q_type = d3.get('question_type', 2)
        if not choices:
            return None
        real_friends = real_friends or []
        mapping: Dict[str, int] = {}
        for name in real_friends:
            hits = [i for i, c in enumerate(choices) if name.lower() in c.get('title', '').lower()]
            if hits:
                mapping[name] = hits[0]
        picked: List[int] = []
        if mapping:
            picked = [mapping[n] for n in real_friends if n in mapping][:3]
        if len(picked) < 2 and interactive:
            for i, c in enumerate(choices):
                print(f"  {i}: {c.get('title')}")
            while True:
                try:
                    raw = input('Chon it nhat 2 ten (cach nhau bang dau phay): ').strip()
                    selected = [int(x.strip()) for x in raw.split(',') if x.strip()]
                except (EOFError, KeyboardInterrupt):
                    raise
                except ValueError:
                    continue
                selected = list(dict.fromkeys(selected))
                if len(selected) < 2 or len(selected) > 3:
                    continue
                if any((i < 0 or i >= len(choices) for i in selected)):
                    continue
                picked = selected
                break
        if not picked:
            return None
        answers = ','.join((choices[i]['value'] for i in picked))
        body = urllib.parse.urlencode({'session': session, 'question_type': str(q_type), 'answers': answers})
        r4 = http_post_json_curl(f'{ACC_URL}/verify/v3/api/seq/answer', body=body, zcid=zcid, cookie=cookie)
        at = (r4.get('data') or {}).get('access_token', '')
        return at if at else None
