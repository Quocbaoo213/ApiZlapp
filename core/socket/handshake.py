import base64
import os
import struct
import time
from typing import Optional, Tuple, List, Dict, Any
from .crypto import DEFAULT_XK
from .protocol import CKSUM_MAGIC, INNER_HEADER_FORMAT, compute_checksum, build_outer_frame, xor_enc, XK

def build_p110(sk_str: str, uid: int, vercode: int=260801901) -> bytes:
    s = sk_str.encode('utf-8')
    inner = b'\x01' + b'\xff' * 4 + b'\x00\x00' + struct.pack('<I', vercode) + b'\x02' + struct.pack('<H', 19) + b'samsung_SM-J610F_11' + struct.pack('<H', 6) + b'000000' + b'\x00' * 6 + struct.pack('<H', len(s)) + s
    le_t = struct.pack('<I', 133)
    le_m = struct.pack('<I', uid & 4294967295)
    key = bytes((XK[i % 32] ^ le_t[i % 4] ^ le_m[i % 4] for i in range(32)))
    return bytes((inner[i] ^ key[i % 32] for i in range(110)))

def build_authen_body(sk_str: str, uid: int, ctr: int=4294967295) -> bytes:
    s = uid + ctr + 1 + 3 + 5 + 1 + 1 & 4294967295
    cs = s ^ CKSUM_MAGIC
    return struct.pack('<I', cs) + b'\x01\x01' + struct.pack('<I', ctr) + struct.pack('<I', uid)[::-1][:0] + b'' + struct.pack('<I', uid) + b'\x03' + b'\x01\x00\x05' + build_p110(sk_str, uid)

def build_prov_frame(session_key: str, dk: bytes, ksid: str, server_pubkey_b64: Any, uid: int) -> bytes:
    if isinstance(server_pubkey_b64, str):
        srv_pub = base64.b64decode(server_pubkey_b64)
    else:
        srv_pub = server_pubkey_b64
    body = build_authen_body(session_key, uid)
    iv = os.urandom(12)
    from Crypto.Cipher import AES
    c = AES.new(dk, AES.MODE_GCM, nonce=iv, mac_len=16)
    ct, tag = c.encrypt_and_digest(body)
    inner = ct + tag + iv + ksid.encode('utf-8') + b'\x10'
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(srv_pub))
    eiv = os.urandom(12)
    outer = AESGCM(shared).encrypt(eiv, inner, None)
    payload = outer + eiv + eph.public_key().public_bytes_raw() + srv_pub
    return struct.pack('<I', 5 + len(payload)) + b'\x08' + payload
build_prov = build_prov_frame

def build_init_frames(uid: int, dest: int=335694418, vercode: int=260801901) -> List[Tuple[int, int, int, int, bytes]]:
    VC = struct.pack('<I', vercode)
    dest_le = struct.pack('<I', dest & 4294967295)
    uid_le = struct.pack('<I', uid & 4294967295)
    now_ms = int(time.time() * 1000)
    fr = []
    add = lambda cmd, sub, bb, pt: fr.append((cmd, sub, bb, 1, xor_enc(pt, uid)))
    add(384, 0, 0, b'\x01' + VC + struct.pack('<I', 160) + b'\x00' * 8)
    add(2061, 0, 0, b'\x01' + VC)
    add(133, 0, 0, b'')
    add(2070, 0, 0, b'\x01' + VC + b'\x00' * 4)
    add(1430, 0, 0, b'\x01' + VC)
    add(151, 4, 0, uid_le + b'\x00' * 4 + struct.pack('<I', 6) + b'\x02\x04\x00\x00' + b'\x00' * 3)
    add(390, 1, 0, b'\x01' + VC)
    bundle_path = None
    for bp in ['binhmod.bin', os.path.join(os.path.dirname(__file__), '..', '..', 'binhmod.bin'), os.path.expanduser('~/.zalo/binhmod.bin'), '/root/zalo/binhmod.bin']:
        if os.path.isfile(bp):
            bundle_path = bp
            break
    if bundle_path and os.path.exists(bundle_path):
        with open(bundle_path, 'rb') as f:
            raw = f.read()
        if len(raw) == 889 and raw[0] != 0:
            params10100 = raw
        else:
            params10100 = xor_enc(raw, uid)
        fr.append((10100, 1, 0, 1, params10100))
    sync = ('{"owner_id":"%d","data_types":[3],"src_type":3}' % uid).encode('utf-8')
    add(1814, 0, 0, b'\x01' + VC + struct.pack('<I', len(sync)) + sync)
    add(10301, 1, 0, b'\x01\x01' + b'\x00' * 4)
    add(177, 0, 0, b'\x01' + b'\x00' * 9)
    add(525, 0, 0, b'\x01' + VC)
    add(271, 0, 0, struct.pack('<I', 11))
    add(1715, 0, 0, b'')
    add(620, 0, 0, b'\x01' + VC + b'\x01\x00')
    add(1582, 0, 0, b'\x01' + VC + struct.pack('<I', 160))
    add(1963, 0, 0, b'\x01' + VC + b'\x00' * 11)
    add(601, 0, 0, b'\x00' * 48)
    add(1786, 0, 1, b'\x00' * 8)
    add(102, 3, 1, b'{"seen":0,"data":[]}')
    add(1419, 0, 0, struct.pack('<I', 6) + VC + b'\x01')
    add(1411, 0, 0, b'\x01' + VC)
    add(1484, 0, 0, b'\x01' + VC + struct.pack('<I', 1))
    add(176, 1, 0, b'')
    add(1407, 0, 0, b'')
    add(1399, 0, 0, struct.pack('<I', 6) + VC + b'\x01')
    csv = ('1,346190,0,0,0,%d,%d' % (now_ms - 300000, now_ms - 18000)).encode('utf-8')
    import zlib as _z
    co = _z.compressobj(6, _z.DEFLATED, -15)
    body = co.compress(csv) + co.flush()
    crc = _z.crc32(csv) & 4294967295
    gz = b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03' + body + struct.pack('<II', crc, len(csv) & 4294967295)
    add(1530, 0, 0, b'\x04' + struct.pack('<I', now_ms >> 8 & 4294967295) + struct.pack('<I', 1) + struct.pack('<I', len(gz)) + gz)
    add(1915, 0, 0, b'\x01' + VC + b'\x00\x00')
    add(396, 4, 0, b'\x01' + VC + struct.pack('<I', 1) + struct.pack('<I', 100) + struct.pack('<I', 160) + b'\x00' * 4 + b'\x01')
    add(376, 1, 0, b'\x01' + VC + b'\x00' * 4 + struct.pack('<I', 100) + struct.pack('<I', 160))
    add(272, 1, 0, b'\x01' + VC + b'\x01\x00\x19' + b'\x00' * 7)
    add(2085, 0, 0, b'\x01' + VC + b'\x00' * 6 + b'\x01' + b'\x00' * 7)
    add(700, 0, 0, b'\x01' + VC + b'\x00')
    add(1588, 1, 0, b'\x01' + VC + struct.pack('<I', 160) + b'\x00')
    add(2190, 0, 0, b'\x01' + VC)
    e2ee_json = b'{"devices":{"masterId":"aade588b835d3813157f91c24d3b5394","encIdentity":"BSZhp3pIB9XiGN6DxHr\\/Cf\\/egcZwhiXk67b\\/tqBgSFB","lastUpdateTs":%d,"encSignature":"0idIG9lZ8c444kPv\\/axpIi5KiaMQ2Lcb\\/54Zs+kwphSHTr9hV3H\\/StaVL4klnyNtsEwtDiyDVlqmPBVWICBg==","companions":[]}}' % now_ms
    add(3400, 0, 0, b'\x01' + VC + b'\x01\x01\x15\x01\x00\x00' + e2ee_json)
    add(1971, 0, 0, b'\x01' + dest_le)
    add(1708, 0, 0, b'\x01' + VC + b'\x00' * 6 + dest_le + b'\x00' * 8)
    add(151, 4, 0, dest_le + b'\x00' * 4 + struct.pack('<I', 6) + b'\x04\x04\x00\x00' + b'\x00' * 3)
    add(1251, 4, 0, b'\x00\x00\x01' + VC + b'\x00\x00' + dest_le + struct.pack('<I', 6) + struct.pack('<I', 240) + b'\x00' * 3)
    add(1400, 4, 0, b'\x05\x00' + b'\xff' * 13)
    return fr

def send_init_frames(sock, dk: bytes, uid: int, dest: int=335694418, vercode: int=260801901, send_lock=None):
    init_list = build_init_frames(uid, dest=dest, vercode=vercode)
    seq = -2
    for cmd, sub, bb, ty, params in init_list:
        ck = compute_checksum(cmd, sub, seq, uid, bb=bb, ty=ty)
        header = struct.pack(INNER_HEADER_FORMAT, ck, bb, ty, seq, uid, 3, cmd, sub)
        inner = header + params
        outer = build_outer_frame(inner, dk)
        if send_lock:
            with send_lock:
                sock.sendall(outer)
        else:
            sock.sendall(outer)
        seq -= 1
        time.sleep(0.02)
