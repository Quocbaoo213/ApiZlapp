import json
import struct
from typing import Optional, Dict, Any, Union
from core.socket.protocol import (
    InnerPacketHeader,
    compute_checksum,
    xor_encode_d3,
    SUB_FILE_MSG,
    CMD_GROUP_MSG,
    CMD_1TO1_MSG,
    build_file_attach,
    build_d3_payload_group,
    build_d3_payload_1to1
)

def build_file_binary_payload(file_url: str, file_name: str, file_size: Union[int, str] = 0, checksum: str = '', file_ext: str = '', duration: int = 0, f_type: int = 1, thumb: str = '', is_group: bool = True, text: str = '', ttl_ms: int = 0, quote_data: Optional[dict] = None, cryptkey: Optional[bytes] = None, sub_type: int = SUB_FILE_MSG) -> bytes:
    attach_obj = build_file_attach(file_url=file_url, file_name=file_name, file_size=file_size, checksum=checksum, file_ext=file_ext, duration=duration, f_type=f_type, thumb=thumb)
    if is_group:
        return build_d3_payload_group(text=text, ttl_ms=ttl_ms, quote_data=quote_data, attach=attach_obj, sub_id=sub_type)
    return build_d3_payload_1to1(text=text, cryptkey=cryptkey, ttl_ms=ttl_ms, quote_data=quote_data, attach=attach_obj, sub_id=sub_type)

def build_file_message_packet(uid: int, target_id: int, file_url: str, file_name: str, seq: int, ck_val: Optional[int] = None, cmsg_id: int = 0, file_size: Union[int, str] = 0, checksum: str = '', file_ext: str = '', duration: int = 0, f_type: int = 1, thumb: str = '', is_group: bool = True, text: str = '', ttl_ms: int = 0, quote_data: Optional[dict] = None, cryptkey: Optional[bytes] = None, sub_type: int = SUB_FILE_MSG) -> bytes:
    cmd = CMD_GROUP_MSG if is_group else CMD_1TO1_MSG
    sub = int(sub_type)
    target_type = 4 if is_group else 3
    if ck_val is None or ck_val == 0:
        ck_val = compute_checksum(cmd=cmd, sub=sub, seq=seq, uid=uid, target=target_id, target_type=target_type, cmsg=cmsg_id, bb=1, ty=2, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=1, ty=2, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    plain_payload = build_file_binary_payload(file_url=file_url, file_name=file_name, file_size=file_size, checksum=checksum, file_ext=file_ext, duration=duration, f_type=f_type, thumb=thumb, is_group=is_group, text=text, ttl_ms=ttl_ms, quote_data=quote_data, cryptkey=cryptkey, sub_type=sub)
    xor_payload = xor_encode_d3(plain_payload, uid)
    params_prefix = struct.pack('<IBII', target_id & 4294967295, target_type, cmsg_id & 4294967295, 416)
    return hdr.pack() + params_prefix + xor_payload
