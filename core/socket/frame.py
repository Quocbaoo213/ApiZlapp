import struct
from dataclasses import dataclass
from typing import Optional, Tuple
from core.socket.constants import FRAME_TYPE_DATA, XK, MAGIC_CHECKSUM_XOR
from core.socket.crypto import encrypt_aes_gcm, decrypt_aes_gcm

INNER_HEADER_FORMAT = '<IBBiIBHB'
INNER_HEADER_SIZE = 18

@dataclass
class InnerPacketHeader:
    ck: int
    bb: int
    ty: int
    seq: int
    uid: int
    ver: int
    cmd: int
    sub: int

    def pack(self) -> bytes:
        return struct.pack(
            INNER_HEADER_FORMAT,
            self.ck & 4294967295,
            self.bb & 255,
            self.ty & 255,
            self.seq,
            self.uid & 4294967295,
            self.ver & 255,
            self.cmd & 65535,
            self.sub & 255
        )

    @classmethod
    def unpack(cls, data: bytes) -> 'InnerPacketHeader':
        if len(data) < INNER_HEADER_SIZE:
            raise ValueError(f'Dữ liệu không đủ {INNER_HEADER_SIZE} bytes để đọc Header (nhận {len(data)} bytes).')
        ck, bb, ty, seq, uid, ver, cmd, sub = struct.unpack_from(INNER_HEADER_FORMAT, data, 0)
        return cls(ck=ck, bb=bb, ty=ty, seq=seq, uid=uid, ver=ver, cmd=cmd, sub=sub)

@dataclass
class OuterFrame:
    total_len: int
    ftype: int
    body: bytes

    def pack(self) -> bytes:
        return struct.pack('<IB', len(self.body) + 5, self.ftype) + self.body

    @classmethod
    def unpack_from_buffer(cls, buf: bytes) -> Optional[Tuple['OuterFrame', int]]:
        if len(buf) < 5:
            return None
        total_len = struct.unpack_from('<I', buf, 0)[0]
        if total_len < 5:
            raise ValueError(f'Outer frame total_len không hợp lệ: {total_len}')
        if len(buf) < total_len:
            return None
        ftype = buf[4]
        body = buf[5:total_len]
        return (cls(total_len=total_len, ftype=ftype, body=body), total_len)

def compute_checksum(cmd: int, sub: int, seq: int, uid: int, target: int = 0, target_type: int = 0, cmsg: int = 0, bb: int = 1, ty: int = 2, ver: int = 3) -> int:
    total = bb + ty + seq + uid + ver + cmd + sub + target + target_type + cmsg & 4294967295
    return total ^ MAGIC_CHECKSUM_XOR

def xor_encode_d3(plain: bytes, uid: int, xk: bytes = XK) -> bytes:
    a4 = len(plain) + 36
    le4 = struct.pack('<I', a4)
    ule = struct.pack('<I', uid & 4294967295)
    k = bytes((xk[i % 32] ^ le4[i % 4] ^ ule[i % 4] for i in range(32)))
    return bytes((plain[i] ^ k[i % 32] for i in range(len(plain))))

def xor_decode_d3(cipher: bytes, uid: int, xk: bytes = XK) -> bytes:
    return xor_encode_d3(cipher, uid, xk)

def dekey(a4: int, uid: int) -> bytes:
    ule = struct.pack('<I', uid & 4294967295)
    k1 = bytes((XK[i % 32] ^ struct.pack('<I', a4)[i % 4] for i in range(32)))
    return bytes((k1[i % 32] ^ ule[i % 4] for i in range(32)))

def xor_enc(pt: bytes, uid: int) -> bytes:
    key = dekey(len(pt) + 23, uid)
    return bytes((pt[i] ^ key[i % 32] for i in range(len(pt))))

def build_outer_frame(inner_packet: bytes, dk: bytes) -> bytes:
    encrypted_body = encrypt_aes_gcm(inner_packet, dk)
    frame = OuterFrame(total_len=len(encrypted_body) + 5, ftype=FRAME_TYPE_DATA, body=encrypted_body)
    return frame.pack()

