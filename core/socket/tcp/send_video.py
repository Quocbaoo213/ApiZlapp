import json
import struct
from typing import Optional, Dict, Any
from core.socket.protocol import InnerPacketHeader, compute_checksum, xor_encode_d3, SUB_VIDEO_MSG, CMD_GROUP_MSG, CMD_1TO1_MSG, INNER_HEADER_FORMAT

def build_video_attach(url: str, width: int=1280, height: int=720, duration: int=0, total_size: int=0, title: str='', description: str='', thumb_url: Optional[str]=None) -> Dict[str, Any]:
    return {'title': title, 'description': description or url, 'href': url, 'thumb': thumb_url or url, 'url': url, 'tType': 4, 'width': width or 1280, 'height': height or 720, 'duration': duration or 0, 'totalSize': total_size or 0, 'fileSize': total_size or 0}

def build_video_binary_payload(url: str, title: str='', description: str='', thumb_url: Optional[str]=None, width: int=1280, height: int=720, duration_ms: int=0, total_size: int=0, sub_type: int=SUB_VIDEO_MSG) -> bytes:
    thumb = str(thumb_url or url)
    u = str(url)
    t = str(title or '')
    d = str(description or u)
    meta_dict = {'duration': int(duration_ms or 0), 'video_original_width': int(width or 1280), 'video_original_height': int(height or 720), 'video_width': int(width or 1280), 'video_height': int(height or 720), 'video_rotation': 0, 'isHD': 1}
    if thumb_url:
        meta_dict['thumb'] = thumb
        meta_dict['thumbUrl'] = thumb
    if total_size > 0:
        meta_dict['fileSize'] = int(total_size)
        meta_dict['totalSize'] = int(total_size)
    meta_json = json.dumps(meta_dict, separators=(',', ':'))
    extra = ''
    hdr = struct.pack('<HB', int(sub_type), 0)
    a_bytes = t.encode('utf-8')
    e_bytes = d.encode('utf-8')
    d_bytes = u.encode('utf-8')
    c_bytes = thumb.encode('utf-8')
    dur_sec = int(duration_ms) // 1000 if duration_ms > 1000 else int(duration_ms)
    f_bytes = extra.encode('utf-8')
    g_bytes = meta_json.encode('utf-8')
    body = struct.pack('<H', len(a_bytes)) + a_bytes + struct.pack('<H', len(e_bytes)) + e_bytes + struct.pack('<H', len(d_bytes)) + d_bytes + struct.pack('<H', len(c_bytes)) + c_bytes + struct.pack('<H', dur_sec & 65535) + struct.pack('<H', len(f_bytes)) + f_bytes + struct.pack('<H', len(g_bytes)) + g_bytes
    return hdr + body

def build_video_message_packet(uid: int, target_id: int, video_url: str, seq: int, ck_val: Optional[int]=None, cmsg_id: int=0, is_group: bool=True, caption: str='', title: Optional[str]=None, description: Optional[str]=None, thumb_url: Optional[str]=None, width: int=1280, height: int=720, duration_ms: int=0, total_size: int=0, ttl_ms: int=0, quote_data: Optional[dict]=None, cryptkey: Optional[bytes]=None, native: bool=True, sub_type: int=SUB_VIDEO_MSG) -> bytes:
    from core.socket.protocol import build_group_message_packet, build_1to1_message_packet
    t_val = str(title or caption or '')
    d_val = str(description or video_url)
    if not native:
        dur_sec = int(duration_ms) // 1000 if duration_ms > 1000 else int(duration_ms)
        attach_obj = build_video_attach(url=video_url, width=width, height=height, duration=dur_sec, total_size=total_size, title=t_val, description=d_val, thumb_url=thumb_url)
        msg_text = f'{t_val}\n{video_url}' if t_val and t_val.strip() != video_url.strip() else video_url
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
    plain_payload = build_video_binary_payload(url=video_url, title=t_val, description=d_val, thumb_url=thumb_url, width=width, height=height, duration_ms=duration_ms, total_size=total_size, sub_type=sub)
    xor_payload = xor_encode_d3(plain_payload, uid)
    params_prefix = struct.pack('<IBII', target_id & 4294967295, target_type, cmsg_id & 4294967295, 416)
    return hdr.pack() + params_prefix + xor_payload
