import json
import struct
from typing import Optional, Dict, Any
from core.socket.crypto import DEFAULT_XK
from core.socket.protocol import InnerPacketHeader, compute_checksum, xor_encode_d3, SUB_PHOTO_MSG, CMD_GROUP_MSG, CMD_1TO1_MSG, INNER_HEADER_FORMAT

def build_photo_attach(url: str, width: int=0, height: int=0, total_size: int=0, title: str='', description: str='', thumb_url: Optional[str]=None, hd_url: Optional[str]=None) -> Dict[str, Any]:
    return {'title': title, 'description': description or url, 'href': url, 'thumb': thumb_url or url, 'url': url, 'hdUrl': hd_url or url, 'tType': 3, 'width': width or 0, 'height': height or 0, 'totalSize': total_size or 0, 'hdSize': total_size or 0}

def build_photo_binary_payload(url: str, title: str='', description: str='', thumb_url: Optional[str]=None, hd_url: Optional[str]=None, caption: str='', width: int=0, height: int=0, total_size: int=0, sub_type: int=SUB_PHOTO_MSG, is_original: bool=False) -> bytes:
    thumb = str(thumb_url or url)
    hd = str(hd_url or url)
    u = str(url)
    t = str(title or caption or '')
    d = str(description or u)
    meta_dict = {}
    if width > 0:
        meta_dict['width'] = int(width)
    if height > 0:
        meta_dict['height'] = int(height)
    if total_size > 0:
        meta_dict['totalSize'] = int(total_size)
        meta_dict['fileSize'] = int(total_size)
    if hd:
        meta_dict['hd'] = hd
    if is_original:
        meta_dict['is_original'] = 1
        if total_size > 0:
            meta_dict['hdSize'] = int(total_size)
    meta_json = json.dumps(meta_dict, separators=(',', ':')) if meta_dict else ''
    extra = ''
    hdr = struct.pack('<HB', int(sub_type), 0)
    a_bytes = t.encode('utf-8')
    e_bytes = d.encode('utf-8')
    d_bytes = hd.encode('utf-8')
    c_bytes = thumb.encode('utf-8')
    f_bytes = extra.encode('utf-8')
    g_bytes = meta_json.encode('utf-8')
    body = struct.pack('<H', len(a_bytes)) + a_bytes + struct.pack('<H', len(e_bytes)) + e_bytes + struct.pack('<H', len(d_bytes)) + d_bytes + struct.pack('<H', len(c_bytes)) + c_bytes + struct.pack('<H', 0) + struct.pack('<H', len(f_bytes)) + f_bytes + struct.pack('<H', len(g_bytes)) + g_bytes
    return hdr + body

def build_photo_message_packet(uid: int, target_id: int, photo_url: str, seq: int, ck_val: Optional[int]=None, cmsg_id: int=0, is_group: bool=True, caption: str='', title: Optional[str]=None, description: Optional[str]=None, width: int=0, height: int=0, total_size: int=0, thumb_url: Optional[str]=None, hd_url: Optional[str]=None, ttl_ms: int=0, quote_data: Optional[dict]=None, cryptkey: Optional[bytes]=None, native: bool=True, sub_type: int=SUB_PHOTO_MSG, is_original: bool=False) -> bytes:
    from core.socket.protocol import build_group_message_packet, build_1to1_message_packet
    t_val = str(title or caption or '')
    d_val = str(description or photo_url)
    if not native:
        attach_obj = build_photo_attach(url=photo_url, width=width, height=height, total_size=total_size, title=t_val, description=d_val, thumb_url=thumb_url, hd_url=hd_url)
        msg_text = f'{t_val}\n{photo_url}' if t_val and t_val.strip() != photo_url.strip() else photo_url
        if is_group:
            return build_group_message_packet(uid=uid, group_id=target_id, text=msg_text, seq=seq, cmsg_id=cmsg_id, ttl_ms=ttl_ms, quote_data=quote_data, attach_override=attach_obj)
        else:
            return build_1to1_message_packet(uid=uid, to_uid=target_id, text=msg_text, seq=seq, cmsg_id=cmsg_id, ttl_ms=ttl_ms, quote_data=quote_data, cryptkey=cryptkey, attach_override=attach_obj)
    cmd = CMD_GROUP_MSG if is_group else CMD_1TO1_MSG
    sub = int(sub_type)
    target_type = 4 if is_group else 3
    if ck_val is None or ck_val == 0:
        ck_val = compute_checksum(cmd=cmd, sub=sub, seq=seq, uid=uid, target=target_id, target_type=target_type, cmsg=cmsg_id, bb=1, ty=2, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=1, ty=2, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    plain_payload = build_photo_binary_payload(url=photo_url, title=t_val, description=d_val, thumb_url=thumb_url, hd_url=hd_url, caption=t_val, width=width, height=height, total_size=total_size, sub_type=sub, is_original=is_original)
    xor_payload = xor_encode_d3(plain_payload, uid)
    params_prefix = struct.pack('<IBII', target_id & 4294967295, target_type, cmsg_id & 4294967295, 416)
    return hdr.pack() + params_prefix + xor_payload
