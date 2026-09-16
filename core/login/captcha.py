import io
import json
import time
import base64
import logging
import subprocess
import urllib.parse
from typing import Optional, Tuple
from PIL import Image
from .device import ZMCAP_URL, http_post_json_curl
logger = logging.getLogger('core.login.captcha')

def solve_captcha_img(bg_png: bytes, slice_png: bytes, top: int) -> Tuple[int, float]:
    bg = Image.open(io.BytesIO(bg_png)).convert('RGB')
    sl = Image.open(io.BytesIO(slice_png)).convert('RGBA')
    px, sp = (bg.load(), sl.load())
    W, H = bg.size
    samples = [(i, j) for i in range(0, sl.size[0], 3) for j in range(0, sl.size[1], 3) if sp[i, j][3] > 200]
    if not samples:
        return (0, 0.0)
    sl_vals = [sum(sp[i, j][:3]) / 3 for i, j in samples]
    m = sum(sl_vals) / len(sl_vals)
    var = (sum(((x - m) ** 2 for x in sl_vals)) / len(sl_vals)) ** 0.5 or 1.0
    sl_n = [(x - m) / var for x in sl_vals]
    best, bx = (-2.0, 0)
    max_x = max(1, W - sl.size[0])
    for x0 in range(0, max_x):
        bgv = [sum(px[x0 + i, min(top + j, H - 1)][:3]) / 3 for i, j in samples]
        m2 = sum(bgv) / len(bgv)
        v2 = (sum(((x - m2) ** 2 for x in bgv)) / len(bgv)) ** 0.5 or 1.0
        bg_n = [(x - m2) / v2 for x in bgv]
        corr = sum((a * b for a, b in zip(sl_n, bg_n))) / len(bg_n)
        if corr > best:
            best, bx = (corr, x0)
    return (bx, best)

def captcha_flow(captcha_session: str, zcid: str='') -> Optional[str]:
    if not captcha_session:
        logger.warning('captcha_session rỗng, không thể tải challenge.')
        return None
    gen_url = f'{ZMCAP_URL}/api/slide-captcha-gen?session={captcha_session}'
    cmd = ['curl', '-sS', '-m', '15', gen_url]
    rr = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    try:
        r = json.loads(rr.stdout)
    except Exception:
        r = {'raw': rr.stdout[:200], 'error_code': -1}
    if r.get('error_code') != 0:
        logger.error(f'Captcha Gen thất bại: {json.dumps(r)[:150]}')
        return None
    d = r.get('data') or {}
    bg_b64 = d.get('bg', '').split(',', 1)[-1]
    slice_b64 = d.get('slice', '').split(',', 1)[-1]
    top = int(d.get('top', 0))
    if not bg_b64 or not slice_b64:
        logger.error('Không nhận được dữ liệu ảnh captcha.')
        return None
    bg_png = base64.b64decode(bg_b64)
    slice_png = base64.b64decode(slice_b64)
    left, conf = solve_captcha_img(bg_png, slice_png, top)
    logger.info(f'Slide Captcha: top={top}, left={left}, correlation={conf:.3f}')
    start = int(time.time() * 1000)
    body = urllib.parse.urlencode({'left': left, 'startTime': start, 'stopTime': start + 2200 + left % 700})
    verify_url = f'{ZMCAP_URL}/api/slide-captcha-verify?session={captcha_session}'
    r2 = http_post_json_curl(verify_url, body=body, zcid=zcid)
    if r2.get('error_code') != 0:
        logger.error(f'Captcha Verify thất bại: {json.dumps(r2)[:150]}')
        return None
    token = (r2.get('data') or {}).get('captchaToken', '')
    if token:
        logger.info(f'Đã nhận captchaToken thành công: {token[:36]}...')
        return token
    return None
