import os
import time
import socket
import struct
import base64
import logging
from typing import List, Tuple, Dict, Any, Optional
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
logger = logging.getLogger('core.login.probe')

def build_p110(sk_str: str, uid_int: int, vercode: int=260801901) -> bytes:
    s = sk_str.encode()
    inner = b'\x01' + b'\xff' * 4 + b'\x00\x00' + struct.pack('<I', vercode) + b'\x02' + struct.pack('<H', 19) + b'samsung_SM-J610F_11' + struct.pack('<H', 6) + b'000000' + b'\x00' * 6 + struct.pack('<H', len(s)) + s
    total_len = len(inner)
    XK = b'P1BL2G5I7NJD2H3JAUD554G7645PH54F'
    le_t = struct.pack('<I', 133)
    le_m = struct.pack('<I', uid_int)
    key = bytes((XK[i % 32] ^ le_t[i % 4] ^ le_m[i % 4] for i in range(32)))
    return bytes((inner[i] ^ key[i % 32] for i in range(total_len)))

def calc_cs(uid_int: int, ctr: int, cmd: int, dirn: int, sub: int, seq_b: bytes) -> int:
    s = uid_int + ctr + cmd + dirn + sub + seq_b[0] + seq_b[1] & 4294967295
    return s ^ 1827134112

def probe_socket_authen(sk: str, dk: bytes, ksid: str, servers: List[Dict[str, Any]], uid_int: int, ctr: int=4294967295, timeout: float=6.0) -> Tuple[List[Tuple[str, int, str, Any]], bool]:
    if not servers:
        return ([], False)
    cs = calc_cs(uid_int, ctr, 1, 3, 5, bytes([1, 1]))
    body = struct.pack('<I', cs) + b'\x01\x01' + struct.pack('<I', ctr) + struct.pack('<I', uid_int) + b'\x03' + b'\x01\x00\x05' + build_p110(sk, uid_int)
    results = []
    for s in servers:
        host = s.get('host', '')
        port = int(s.get('port', 443))
        pub_key_b64 = s.get('pubKey', '')
        if not host or not pub_key_b64 or ':' in host:
            continue
        try:
            srv_pub = base64.b64decode(pub_key_b64)
            iv1 = os.urandom(12)
            c = AES.new(dk, AES.MODE_GCM, nonce=iv1, mac_len=16)
            ct, tag = c.encrypt_and_digest(body)
            inner = ct + tag + iv1 + ksid.encode() + b'\x10'
            eph = X25519PrivateKey.generate()
            shared = eph.exchange(X25519PublicKey.from_public_bytes(srv_pub))
            eiv = os.urandom(12)
            outer = AESGCM(shared).encrypt(eiv, inner, None)
            payload = outer + eiv + eph.public_key().public_bytes_raw() + srv_pub
            wire = struct.pack('<I', 5 + len(payload)) + b'\x08' + payload
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.sendall(f'GET/HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n'.encode())
            time.sleep(0.05)
            sock.settimeout(3.0)
            try:
                got = b''
                while b'\r\n\r\n' not in got:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    got += chunk
            except Exception:
                pass
            sock.sendall(wire)
            sock.settimeout(4.0)
            buf = b''
            try:
                while len(buf) < 8192:
                    x = sock.recv(4096)
                    if not x:
                        break
                    buf += x
            except Exception:
                pass
            sock.close()
            off = 0
            st = None
            typ = None
            while off + 5 <= len(buf):
                tot = int.from_bytes(buf[off:off + 4], 'little')
                if tot < 5 or off + tot > len(buf):
                    break
                t = buf[off + 4]
                p = buf[off + 5:off + tot]
                off += tot
                typ = t
                if t == 6:
                    try:
                        in2 = AESGCM(shared).decrypt(p[38:50], p[:38] + p[50:], None)
                        st = int.from_bytes(in2[-4:], 'little', signed=True)
                    except Exception:
                        st = 'DECFAIL'
                elif t == 4:
                    try:
                        pt = AES.new(dk, AES.MODE_GCM, nonce=p[-12:]).decrypt_and_verify(p[:-28], p[-28:-12])
                        st = int.from_bytes(pt[18:22], 'little', signed=True)
                        typ = '4-DECRYPTED'
                        results.append((host, port, typ, st))
                        if st == 0:
                            logger.info(f'[{host}:{port}] -> PROV AUTHEN SUCCESS (status=0)!')
                            return (results, True)
                    except Exception:
                        st = '4-gcmfail'
            results.append((host, port, typ, st))
            if st == 0:
                logger.info(f'[{host}:{port}] -> AUTHEN SUCCESS!')
                return (results, True)
        except Exception as e:
            results.append((host, port, 'ERR', str(e)))
    return (results, False)
probe_now = probe_socket_authen
