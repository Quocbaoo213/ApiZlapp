import base64
import gzip
import hashlib
import json
import os
from typing import Dict, Any, Tuple, Optional
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
DEFAULT_XK = b'P1BL2G5I7NJD2H3JAUD554G7645PH54F'
DEFAULT_BASE_KEY = 'd902f34a77e3084b9034eb0caee3e019'
DEFAULT_SECRET = '8cd0fc6c58e88e78d62db52f0e093367'
_P = 2 ** 255 - 19
_A24 = 121665
_BASE_POINT_U = 9 .to_bytes(32, 'little')

def key32(zcid: str) -> bytes:
    z = zcid.strip()
    if len(z) < 96:
        raise ValueError(f'ZCID quá ngắn ({len(z)} ký tự), cần tối thiểu 96 ký tự hex.')
    part1 = ''.join((z[i] for i in range(0, 32, 2)))
    part2 = ''.join((z[len(z) - 1 - 2 * i] for i in range(16)))
    return (part1 + part2).encode('latin1')

def password_hash(phone: str, password: str, base_key: str=DEFAULT_BASE_KEY) -> str:
    key = hashlib.md5((base_key + phone).encode('utf-8')).hexdigest()[5:21].encode('utf-8')
    blk = password.encode('utf-8').ljust(16, b'\x00')[:16]
    return AES.new(key, AES.MODE_ECB).encrypt(blk).hex()

def compute_sig(data_hex: str, api_key: str, secret: str=DEFAULT_SECRET) -> str:
    payload = f'api_key={api_key}data={data_hex}{secret}'.encode('utf-8')
    return hashlib.md5(payload).hexdigest()

def encrypt_http_data(params: dict, zcid: str) -> str:
    k = key32(zcid)
    plain = json.dumps(params, separators=(',', ':')).encode('utf-8')
    pad_len = 16 - len(plain) % 16
    plain += bytes([pad_len]) * pad_len
    cipher = AES.new(k, AES.MODE_CBC, iv=bytes(16))
    return cipher.encrypt(plain).hex().upper()

def decrypt_http_data(data_hex: str, zcid: str) -> dict:
    k = key32(zcid)
    cipher = AES.new(k, AES.MODE_CBC, iv=bytes(16))
    raw = cipher.decrypt(bytes.fromhex(data_hex))
    pad_len = raw[-1]
    if 1 <= pad_len <= 16:
        raw = raw[:-pad_len]
    return json.loads(raw.decode('utf-8', errors='ignore'))

def encrypt_aes_gcm(plaintext: bytes, dk: bytes, iv: Optional[bytes]=None) -> bytes:
    if len(dk) != 32:
        raise ValueError(f'Derived Key (DK) phải đúng 32 bytes, hiện tại là {len(dk)} bytes.')
    if iv is None:
        iv = get_random_bytes(12)
    elif len(iv) != 12:
        raise ValueError(f'IV cho AES-GCM phải đúng 12 bytes, nhận {len(iv)} bytes.')
    cipher = AES.new(dk, AES.MODE_GCM, nonce=iv, mac_len=16)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return ct + tag + iv

def decrypt_aes_gcm(frame_body: bytes, dk: bytes) -> bytes:
    if len(dk) != 32:
        raise ValueError(f'Derived Key (DK) phải đúng 32 bytes, hiện tại là {len(dk)} bytes.')
    if len(frame_body) < 28:
        raise ValueError(f'Frame body quá ngắn ({len(frame_body)} bytes), cần tối thiểu 28 bytes (16B Tag + 12B IV).')
    iv = frame_body[-12:]
    tag = frame_body[-28:-12]
    ct = frame_body[:-28]
    cipher = AES.new(dk, AES.MODE_GCM, nonce=iv, mac_len=16)
    return cipher.decrypt_and_verify(ct, tag)

def encrypt_e2ee_cbc(plaintext: bytes, cryptkey: bytes, iv: Optional[bytes]=None) -> Tuple[bytes, bytes]:
    if len(cryptkey) != 16:
        raise ValueError(f'CryptKey phải đúng 16 bytes, hiện tại là {len(cryptkey)} bytes.')
    if iv is None:
        iv = get_random_bytes(16)
    elif len(iv) != 16:
        raise ValueError(f'IV cho AES-CBC phải đúng 16 bytes, nhận {len(iv)} bytes.')
    pad_len = 16 - len(plaintext) % 16
    padded = plaintext + bytes([pad_len]) * pad_len
    cipher = AES.new(cryptkey, AES.MODE_CBC, iv=iv)
    return (cipher.encrypt(padded), iv)

def decrypt_e2ee_cbc(ciphertext: bytes, cryptkey: bytes, iv: bytes) -> bytes:
    if len(cryptkey) != 16:
        raise ValueError(f'CryptKey phải đúng 16 bytes, hiện tại là {len(cryptkey)} bytes.')
    if len(iv) != 16:
        raise ValueError(f'IV cho AES-CBC phải đúng 16 bytes, nhận {len(iv)} bytes.')
    cipher = AES.new(cryptkey, AES.MODE_CBC, iv=iv)
    raw = cipher.decrypt(ciphertext)
    pad_len = raw[-1]
    if 1 <= pad_len <= 16:
        raw = raw[:-pad_len]
    return raw

def xor_d3(data: bytes, key: bytes=DEFAULT_XK) -> bytes:
    k_len = len(key)
    out = bytearray(len(data))
    for i in range(len(data)):
        out[i] = data[i] ^ key[i % k_len]
    return bytes(out)

def _clamp(k_bytes: bytes) -> int:
    a = bytearray(k_bytes)
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(a, 'little')

def _cswap(swap: int, x_2: int, x_3: int) -> Tuple[int, int]:
    dummy = swap * ((x_2 ^ x_3) % _P)
    return ((x_2 ^ dummy) % _P, (x_3 ^ dummy) % _P)

def x25519(scalar_bytes: bytes, u_bytes: bytes) -> bytes:
    k = _clamp(scalar_bytes)
    u = int.from_bytes(u_bytes, 'little') % _P
    x_1 = u
    x_2, z_2 = (1, 0)
    x_3, z_3 = (u, 1)
    swap = 0
    for t in reversed(range(255)):
        k_t = k >> t & 1
        swap ^= k_t
        x_2, x_3 = _cswap(swap, x_2, x_3)
        z_2, z_3 = _cswap(swap, z_2, z_3)
        swap = k_t
        A = (x_2 + z_2) % _P
        AA = A * A % _P
        B = (x_2 - z_2) % _P
        BB = B * B % _P
        E = (AA - BB) % _P
        C = (x_3 + z_3) % _P
        D = (x_3 - z_3) % _P
        DA = D * A % _P
        CB = C * B % _P
        x_3 = (DA + CB) ** 2 % _P
        z_3 = x_1 * (DA - CB) ** 2 % _P
        x_2 = AA * BB % _P
        z_2 = E * (AA + _A24 * E) % _P
    x_2, x_3 = _cswap(swap, x_2, x_3)
    z_2, z_3 = _cswap(swap, z_2, z_3)
    res = x_2 * pow(z_2, _P - 2, _P) % _P
    return res.to_bytes(32, 'little')

def x25519_keypair() -> Tuple[bytes, bytes]:
    priv = get_random_bytes(32)
    pub = x25519(priv, _BASE_POINT_U)
    return (priv, pub)

def x25519_shared_secret(private_key: bytes, peer_public_key: bytes) -> bytes:
    return x25519(private_key, peer_public_key)

def gzip_decompress(data: bytes) -> bytes:
    return gzip.decompress(data)

def gzip_compress(data: bytes) -> bytes:
    return gzip.compress(data)
