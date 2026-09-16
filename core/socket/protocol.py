import base64
import gzip
import json
import logging
import os
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, Any, List
try:
    from .crypto import encrypt_aes_gcm, decrypt_aes_gcm, encrypt_e2ee_cbc, decrypt_e2ee_cbc, DEFAULT_XK
except (ImportError, ValueError):
    from crypto import encrypt_aes_gcm, decrypt_aes_gcm, encrypt_e2ee_cbc, decrypt_e2ee_cbc, DEFAULT_XK
logger = logging.getLogger('core.socket.protocol')
CKSUM_MAGIC = 1827134112
MAGIC_CHECKSUM_XOR = 1827134112
XK = DEFAULT_XK
FRAME_TYPE_CONTROL = 3
FRAME_TYPE_DATA = 4
FRAME_TYPE_KEY_EXCHANGE = 6
FRAME_TYPE_HANDSHAKE = 8
CMD_PING = 1971
SUB_PING = 0
CMD_GROUP_MSG = 207
SUB_GROUP_MSG = 1
CMD_1TO1_MSG = 113
SUB_1TO1_MSG = 41
SUB_PHOTO_MSG = 32
SUB_DOODLE_MSG = 37
SUB_PHOTO_ATTACH_MSG = 37
SUB_ATTACH_MSG = 37
SUB_VIDEO_MSG = 44
CMD_GROUP_TYPING = 206
SUB_GROUP_TYPING = 1
CMD_1TO1_TYPING = 106
SUB_1TO1_TYPING = 1
CMD_GROUP_PREPARE = 203
SUB_GROUP_PREPARE = 4
CMD_GROUP_SYNC_BROADCAST = 1867
SUB_GROUP_SYNC = 0
CMD_DELIVERY_RECEIPT = 202
SUB_DELIVERY_RECEIPT = 3
CMD_1TO1_INCOMING = 101
CMD_REMOVE_MEMBER = 228
SUB_REMOVE_MEMBER = 0
CMD_KICK_MEMBER = 234
SUB_KICK_MEMBER = 0
CMD_DISBAND_GROUP = 242
SUB_DISBAND_GROUP = 0
CMD_BLOCK_GROUP_MEMBER = 238
SUB_BLOCK_GROUP_MEMBER = 4
CMD_BLOCK_USER = 821
SUB_BLOCK_USER = 3
CMD_ADD_MEMBER = 235
SUB_ADD_MEMBER = 0
CMD_LEAVE_GROUP = 239
SUB_LEAVE_GROUP = 1
CMD_LEAVE_GROUP_225 = 225
SUB_LEAVE_GROUP_225 = 3
CMD_LEAVE_GROUP_239 = 239
SUB_LEAVE_GROUP_239 = 1
CMD_JOIN_GROUP = 246
SUB_JOIN_GROUP = 3
CMD_JOIN_GROUP_INVITE = 250
SUB_JOIN_GROUP_INVITE = 1
CMD_REQUEST_JOIN_GROUP = 244
SUB_REQUEST_JOIN_GROUP = 4
CMD_GROUP_LINK_INFO = 244
SUB_GROUP_LINK_INFO = 4
CMD_JOIN_GROUP_BY_LINK = 2000
SUB_JOIN_GROUP_BY_LINK = 3
CMD_PIN_TOPIC = 1752
SUB_PIN_TOPIC = 2
CMD_UNPIN_TOPIC = 1708
SUB_UNPIN_TOPIC = 0
CMD_CREATE_POLL = 1640
SUB_CREATE_POLL = 3
CMD_RECALL_MSG_GROUP = 204
SUB_RECALL_MSG_GROUP = 2
CMD_RECALL_MSG_1TO1 = 114
SUB_RECALL_MSG_1TO1 = 2
CMD_DELETE_MSG = 205
SUB_DELETE_MSG = 3
CMD_BLOCK_USER_1TO1 = 382
SUB_BLOCK_USER_1TO1 = 0
CMD_UNBLOCK_USER_1TO1 = 383
SUB_UNBLOCK_USER_1TO1 = 0
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
        return struct.pack(INNER_HEADER_FORMAT, self.ck & 4294967295, self.bb & 255, self.ty & 255, self.seq, self.uid & 4294967295, self.ver & 255, self.cmd & 65535, self.sub & 255)

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

def compute_checksum(cmd: int, sub: int, seq: int, uid: int, target: int=0, target_type: int=0, cmsg: int=0, bb: int=1, ty: int=2, ver: int=3) -> int:
    total = bb + ty + seq + uid + ver + cmd + sub + target + target_type + cmsg & 4294967295
    return total ^ MAGIC_CHECKSUM_XOR

def xor_encode_d3(plain: bytes, uid: int, xk: bytes=XK) -> bytes:
    a4 = len(plain) + 36
    le4 = struct.pack('<I', a4)
    ule = struct.pack('<I', uid & 4294967295)
    k = bytes((xk[i % 32] ^ le4[i % 4] ^ ule[i % 4] for i in range(32)))
    return bytes((plain[i] ^ k[i % 32] for i in range(len(plain))))

def xor_decode_d3(cipher: bytes, uid: int, xk: bytes=XK) -> bytes:
    return xor_encode_d3(cipher, uid, xk)

def dekey(a4: int, uid: int) -> bytes:
    ule = struct.pack('<I', uid & 4294967295)
    k1 = bytes((XK[i % 32] ^ struct.pack('<I', a4)[i % 4] for i in range(32)))
    return bytes((k1[i % 32] ^ ule[i % 4] for i in range(32)))

def xor_enc(pt: bytes, uid: int) -> bytes:
    key = dekey(len(pt) + 23, uid)
    return bytes((pt[i] ^ key[i % 32] for i in range(len(pt))))

def build_photo_attach(url: str, width: int=0, height: int=0, total_size: int=0, title: str='', description: str='', thumb_url: Optional[str]=None, hd_url: Optional[str]=None, is_original: bool=False) -> Dict[str, Any]:
    thumb = str(thumb_url or url)
    hd = str(hd_url or url)
    u = str(url)
    res = {'title': str(title or ''), 'description': str(description or ''), 'href': u, 'thumb': thumb, 'hdUrl': hd, 'normalUrl': u, 'url': u, 'thumbs': [thumb], 'media': {'url': u, 'thumb': thumb, 'hdUrl': hd, 'width': int(width or 0), 'height': int(height or 0), 'totalSize': int(total_size or 0)}, 'tType': 2, 'tWidth': int(width or 0), 'tHeight': int(height or 0), 'width': int(width or 0), 'height': int(height or 0), 'totalSize': int(total_size or 0), 'actionId': 0}
    if is_original:
        res['is_original'] = 1
        res['isOriginal'] = True
        res['media']['is_original'] = 1
    return res

def build_video_attach(url: str, width: int=1280, height: int=720, duration: int=0, total_size: int=0, title: str='', description: str='', thumb_url: Optional[str]=None) -> Dict[str, Any]:
    thumb = str(thumb_url or url)
    u = str(url)
    return {'title': str(title or ''), 'description': str(description or ''), 'href': u, 'thumb': thumb, 'normalUrl': u, 'url': u, 'thumbs': [thumb], 'media': {'url': u, 'thumb': thumb, 'width': int(width or 1280), 'height': int(height or 720), 'duration': int(duration or 0), 'totalSize': int(total_size or 0)}, 'tType': 4, 'tWidth': int(width or 1280), 'tHeight': int(height or 720), 'width': int(width or 1280), 'height': int(height or 720), 'duration': int(duration or 0), 'totalSize': int(total_size or 0), 'actionId': 0}

def build_d3_payload_group(text: str, ttl_ms: int=0, quote_data: Optional[Dict[str, Any]]=None, mentions: Optional[List[Dict[str, Any]]]=None, style_id: Optional[int]=None, size: Optional[int]=None, color: Optional[str]=None, bold: bool=False, italic: bool=False, underline: bool=False, strike: bool=False, fontsize: Optional[int]=None, list_type: Optional[int]=None, rtf_mode: str='fwd', attach: Optional[Union[Dict[str, Any], str]]=None) -> bytes:
    ttl_ms = int(ttl_ms or 0)
    prop_obj = {'sSrcType': -1, 'sSrcStr': '', 'msg_warning_type': 0, 'emoji': {'content': 0, 'num': 0, 'uniq': 0, 'first': '', 'last': '', 'most': '', 'text': 1}}
    if style_id is not None:
        prop_obj['decorInfo'] = {'decorType': 4, 'typoId': int(style_id)}
    if mentions:
        prop_obj['mentions'] = mentions
    if ttl_ms > 0:
        prop_obj['ttl'] = ttl_ms
    if attach:
        if isinstance(attach, dict):
            prop_obj['attach'] = json.dumps(attach, separators=(',', ':'), ensure_ascii=False)
        else:
            prop_obj['attach'] = str(attach)
    style_tags = []
    if bold:
        style_tags.append('b')
    if italic:
        style_tags.append('i')
    if underline:
        style_tags.append('u')
    if strike:
        style_tags.append('s')
    if fontsize is not None:
        style_tags.append(f'f_{int(fontsize)}')
    if color:
        c_clean = str(color).lstrip('#').lower()
        style_tags.append(f'c_{c_clean}')
    if list_type:
        style_tags.append(f'lst_{int(list_type)}')
    if style_tags:
        u16_len = len(text.encode('utf-16-le')) // 2
        prop_obj['styles'] = [{'start': 0, 'len': u16_len, 'st': ','.join(style_tags)}]
        prop_obj['ver'] = 0
    prop_bytes = json.dumps(prop_obj, separators=(',', ':')).encode('utf-8')
    text_bytes = text.encode('utf-8')
    size_val = struct.pack('<i', size if size is not None else -1)
    if color:
        color_int = int(str(color).lstrip('#'), 16)
        color_val = struct.pack('<i', color_int if color_int < 2 ** 31 else color_int - 2 ** 32)
    else:
        color_val = struct.pack('<i', -1)
    type_v = -1
    if bold and italic:
        type_v = 3
    elif bold:
        type_v = 1
    elif italic:
        type_v = 2
    type_val = struct.pack('<i', type_v)
    style_hdr = size_val + color_val + type_val
    if quote_data:
        q_uid = int(quote_data.get('ownerId') or quote_data.get('uid') or 0)
        q_ts = int(quote_data.get('ts') or int(time.time() * 1000))
        q_gmi = int(quote_data.get('globalMsgId') or 0)
        q_cmi = int(quote_data.get('cliMsgId') or int(time.time() * 1000))
        q_typ = int(quote_data.get('cliMsgType') or 1)
        q_text_bytes = str(quote_data.get('msg') or '').encode('utf-8')
        q_attach_bytes = str(quote_data.get('attach') or '').encode('utf-8')
        q_ttl_ms = int(quote_data.get('ttl') or 0)
        mention_len = 0
        if quote_data.get('fromD'):
            tag = f"@{quote_data['fromD']}"
            if text.startswith(tag):
                mention_len = len(tag.encode('utf-16-le')) // 2
        if mention_len == 0 and quote_data.get('ownerId'):
            tag_uid = f"@{quote_data['ownerId']}"
            if text.startswith(tag_uid):
                mention_len = len(tag_uid.encode('utf-16-le')) // 2
        if mention_len == 0 and text.startswith('@'):
            parts = text.split(' ', 1)
            mention_len = len(parts[0].encode('utf-16-le')) // 2
        count_byte = 4 if ttl_ms > 0 else 3
        buf = bytearray()
        buf += bytes([1, 0, count_byte, 11, 1])
        buf += struct.pack('<I', 0)
        buf += struct.pack('<H', mention_len)
        buf += struct.pack('<I', q_uid)
        buf += bytes([2])
        buf += struct.pack('<I', q_uid)
        buf += struct.pack('<Q', q_ts)
        buf += struct.pack('<Q', q_gmi)
        buf += struct.pack('<Q', q_cmi)
        buf += struct.pack('<H', q_typ)
        buf += struct.pack('<H', len(q_text_bytes)) + q_text_bytes
        buf += struct.pack('<H', len(q_attach_bytes)) + q_attach_bytes
        buf += struct.pack('<Q', q_ttl_ms)
        buf += struct.pack('<H', 7)
        buf += style_hdr
        buf += struct.pack('<I', len(prop_bytes)) + prop_bytes
        if ttl_ms > 0:
            buf += bytes([8]) + struct.pack('<I', ttl_ms) + bytes(4)
        buf += text_bytes
        return bytes(buf)
    if ttl_ms > 0:
        header = bytearray([1, 0, 2, 7, 0]) + style_hdr + struct.pack('<I', len(prop_bytes)) + prop_bytes
        ttl_block = bytes([8]) + struct.pack('<I', ttl_ms) + bytes(4)
        return header + ttl_block + text_bytes
    header = bytearray([1, 0, 1, 7, 0]) + style_hdr + struct.pack('<I', len(prop_bytes)) + prop_bytes
    return bytes(header + text_bytes)

def build_d3_json(style_id: Optional[int]=None) -> bytes:
    if style_id:
        obj = {'sSrcType': -1, 'sSrcStr': '', 'decorInfo': {'decorType': 4, 'typoId': style_id}, 'msg_warning_type': 0, 'emoji': {'content': 0, 'num': 0, 'uniq': 0, 'first': '', 'last': '', 'most': '', 'text': 1}}
        return json.dumps(obj, separators=(',', ':')).encode('utf-8')
    return b'{"sSrcType":-1,"sSrcStr":"","msg_warning_type":0,"emoji":{"content":0,"num":0,"uniq":0,"first":"","last":"","most":"","text":1}}'

def build_d3_payload_1to1(text: str, cryptkey: bytes, ttl_ms: int=0, quote_data: Optional[Dict[str, Any]]=None, attach: Optional[Union[Dict[str, Any], str]]=None) -> bytes:
    ttl_ms = int(ttl_ms or 0)
    ct, iv = encrypt_e2ee_cbc(text.encode('utf-8'), cryptkey)
    text_block = bytes([1]) + iv + struct.pack('<H', len(ct)) + ct
    prop_obj = {'sSrcType': -1, 'sSrcStr': '', 'msg_warning_type': 0, 'emoji': {'content': 0, 'num': 0, 'uniq': 0, 'first': '', 'last': '', 'most': '', 'text': 1}}
    if ttl_ms > 0:
        prop_obj['ttl'] = ttl_ms
    if attach:
        if isinstance(attach, dict):
            prop_obj['attach'] = json.dumps(attach, separators=(',', ':'), ensure_ascii=False)
        else:
            prop_obj['attach'] = str(attach)
    prop_bytes = json.dumps(prop_obj, separators=(',', ':')).encode('utf-8')
    if not quote_data:
        if ttl_ms > 0:
            ttl_block = bytes([8]) + struct.pack('<I', ttl_ms) + bytes(4)
            prop_header = bytes([41, 0, 2, 7, 0]) + b'\xff' * 12 + struct.pack('<I', len(prop_bytes)) + prop_bytes
            return prop_header + ttl_block + text_block
        prop_header = bytes([41, 0, 1, 7, 0]) + b'\xff' * 12 + struct.pack('<I', len(prop_bytes)) + prop_bytes
        return prop_header + text_block
    q_uid = int(quote_data.get('ownerId') or quote_data.get('uid') or 0)
    q_ts = int(quote_data.get('ts') or int(time.time() * 1000))
    q_gmi = int(quote_data.get('globalMsgId') or 0)
    q_cmi = int(quote_data.get('cliMsgId') or int(time.time() * 1000))
    q_typ = int(quote_data.get('cliMsgType') or 1)
    q_text_bytes = str(quote_data.get('msg') or '').encode('utf-8')
    q_attach_bytes = str(quote_data.get('attach') or '').encode('utf-8')
    q_ttl_ms = int(quote_data.get('ttl') or 0)
    mention_len = 0
    if quote_data.get('fromD'):
        tag = f"@{quote_data['fromD']}"
        if text.startswith(tag):
            mention_len = len(tag.encode('utf-16-le')) // 2
    if mention_len == 0 and quote_data.get('ownerId'):
        tag_uid = f"@{quote_data['ownerId']}"
        if text.startswith(tag_uid):
            mention_len = len(tag_uid.encode('utf-16-le')) // 2
    if mention_len == 0 and text.startswith('@'):
        parts = text.split(' ', 1)
        mention_len = len(parts[0].encode('utf-16-le')) // 2
    count_byte = 4 if ttl_ms > 0 else 3
    buf = bytearray()
    buf += bytes([41, 0, count_byte, 11, 1])
    buf += struct.pack('<I', 0)
    buf += struct.pack('<H', mention_len)
    buf += struct.pack('<I', q_uid)
    buf += bytes([2])
    buf += struct.pack('<I', q_uid)
    buf += struct.pack('<Q', q_ts)
    buf += struct.pack('<Q', q_gmi)
    buf += struct.pack('<Q', q_cmi)
    buf += struct.pack('<H', q_typ)
    buf += struct.pack('<H', len(q_text_bytes)) + q_text_bytes
    buf += struct.pack('<H', len(q_attach_bytes)) + q_attach_bytes
    buf += struct.pack('<Q', q_ttl_ms)
    buf += struct.pack('<H', 7)
    buf += b'\xff' * 12
    buf += struct.pack('<I', len(prop_bytes)) + prop_bytes
    if ttl_ms > 0:
        buf += bytes([8]) + struct.pack('<I', ttl_ms) + bytes(4)
    buf += text_block
    return bytes(buf)

def build_d3_payload_1to1_styled(text: str, cryptkey: bytes, style_id: Optional[int]=None, size: Optional[int]=None, color: Optional[str]=None, bold: bool=False, italic: bool=False, ttl_ms: int=0) -> bytes:
    ct, iv = encrypt_e2ee_cbc(text.encode('utf-8'), cryptkey)
    js = build_d3_json(style_id)
    size_val = struct.pack('<i', size if size is not None else -1)
    if color:
        color_int = int(color.lstrip('#'), 16)
        color_val = struct.pack('<i', color_int if color_int < 2 ** 31 else color_int - 2 ** 32)
    else:
        color_val = struct.pack('<i', -1)
    type_v = -1
    if bold and italic:
        type_v = 3
    elif bold:
        type_v = 1
    elif italic:
        type_v = 2
    type_val = struct.pack('<i', type_v)
    if ttl_ms > 0:
        ttl_field = bytes([8]) + struct.pack('<I', ttl_ms) + b'\x00\x00\x00\x00'
        head_ttl = bytes([41, 0, 2, 7, 0]) + size_val + color_val + type_val + struct.pack('<I', len(js)) + js
        return head_ttl + ttl_field + bytes([1]) + iv + struct.pack('<H', len(ct)) + ct
    head = bytes([41, 0, 1, 7, 0]) + size_val + color_val + type_val + struct.pack('<I', len(js)) + js
    return head + bytes([1]) + iv + struct.pack('<H', len(ct)) + ct

def build_d3_payload_1to1_rtf(text: str, cryptkey: bytes, styles: List[Dict[str, Any]], rtf_mode: str='fwd', list_type: Optional[int]=None) -> bytes:
    import gzip, secrets
    ct, iv = encrypt_e2ee_cbc(text.encode('utf-8'), cryptkey)
    applied_styles = list(styles)
    if list_type:
        lines = text.split('\n')
        off = 0
        for ln in lines:
            applied_styles.append({'start': off, 'len': len(ln) or 1, 'st': f'lst_{list_type}'})
            off += len(ln) + 1
    styles_js = json.dumps({'styles': applied_styles, 'ver': 0}, separators=(',', ':')).encode('utf-8')
    prop_js = b'{"sSrcType":-1,"sSrcStr":"","msg_warning_type":0}'
    if rtf_mode == 'fwd':
        ts = int(time.time() * 1000)
        mid = secrets.token_hex(16)
        root_ts = ts - 30000
        root_id = secrets.token_hex(16)
        fw_meta = json.dumps({'ts': ts, 'id': mid, 'cl': -1, 'logSrcType': 1, 'rootMsgRef': {'ts': root_ts, 'id': root_id, 'logSrcType': 1}, 'fwLvl': 2}, separators=(',', ':')).encode('utf-8')
        fw_info = json.dumps({'s': 0, 'ds': -1, 'ld': {'lat': 0, 'lon': 0}, 'v': {'ic': 0}, 'ph': {'st': 0}, 'fw': {'pmsg': {'st': 1, 'ts': ts, 'id': mid}, 'rmsg': {'st': 1, 'ts': root_ts, 'id': root_id}}}, separators=(',', ':')).encode('utf-8')
        fw_gz = gzip.compress(fw_info)
        return bytes([41, 0, 4, 5, 3, 0, 0, 0]) + struct.pack('<I', len(fw_meta)) + fw_meta + bytes([6]) + struct.pack('<I', len(fw_gz)) + fw_gz + bytes([7, 0]) + struct.pack('<i', -1) + struct.pack('<I', 2147483648) + struct.pack('<i', -1) + struct.pack('<I', len(prop_js)) + prop_js + bytes([15]) + struct.pack('<I', len(styles_js)) + styles_js + bytes([1]) + iv + struct.pack('<H', len(ct)) + ct
    elif rtf_mode == 'nofwd':
        js = build_d3_json(None)
        return bytes([41, 0, 2, 7, 0]) + struct.pack('<i', -1) + struct.pack('<i', -1) + struct.pack('<i', -1) + struct.pack('<I', len(js)) + js + bytes([15]) + struct.pack('<I', len(styles_js)) + styles_js + bytes([1]) + iv + struct.pack('<H', len(ct)) + ct
    else:
        return bytes([41, 0, 2, 5, 3, 0, 0, 0]) + bytes([7, 0]) + struct.pack('<i', -1) + struct.pack('<I', 2147483648) + struct.pack('<i', -1) + struct.pack('<I', len(prop_js)) + prop_js + bytes([15]) + struct.pack('<I', len(styles_js)) + styles_js + bytes([1]) + iv + struct.pack('<H', len(ct)) + ct

def build_ping_packet(uid: int, seq: int, ck_val: int=0, dest: int=335694418) -> bytes:
    if ck_val == 0:
        ck_val = compute_checksum(CMD_PING, SUB_PING, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=CMD_PING, sub=SUB_PING)
    pt = b'\x01' + struct.pack('<I', dest & 4294967295)
    params = xor_enc(pt, uid)
    return hdr.pack() + params

def build_typing_packet(uid: int, target_id: int, is_group: bool, seq: int, ck_val: int, cmsg_id: int) -> bytes:
    cmd = CMD_GROUP_TYPING if is_group else CMD_1TO1_TYPING
    hdr = InnerPacketHeader(ck=ck_val, bb=1, ty=2, seq=seq, uid=uid, ver=3, cmd=cmd, sub=SUB_GROUP_TYPING)
    params = struct.pack('<IBII', target_id & 4294967295, 3, cmsg_id & 4294967295, 416)
    return hdr.pack() + params

def build_group_message_packet(uid: int, group_id: int, text: str, seq: int, ck_val: int, cmsg_id: int, ttl_ms: int=0, quote_data: Optional[dict]=None, mentions: Optional[list]=None, style_id: Optional[int]=None, size: Optional[int]=None, color: Optional[str]=None, bold: bool=False, italic: bool=False, underline: bool=False, strike: bool=False, fontsize: Optional[int]=None, list_type: Optional[int]=None, rtf_mode: str='fwd', attach: Optional[Union[Dict[str, Any], str]]=None) -> bytes:
    hdr = InnerPacketHeader(ck=ck_val, bb=1, ty=2, seq=seq, uid=uid, ver=3, cmd=CMD_GROUP_MSG, sub=SUB_GROUP_MSG)
    d3_plain = build_d3_payload_group(text, ttl_ms=ttl_ms, quote_data=quote_data, mentions=mentions, style_id=style_id, size=size, color=color, bold=bold, italic=italic, underline=underline, strike=strike, fontsize=fontsize, list_type=list_type, rtf_mode=rtf_mode, attach=attach)
    d3_xor = xor_encode_d3(d3_plain, uid)
    params_prefix = struct.pack('<IBII', group_id & 4294967295, 4, cmsg_id & 4294967295, 416)
    return hdr.pack() + params_prefix + d3_xor

def build_1to1_message_packet(uid: int, target_uid: int, text: str, cryptkey: bytes, seq: int, ck_val: int, cmsg_id: int, ttl_ms: int=0, quote_data: Optional[dict]=None, style_id: Optional[int]=None, size: Optional[int]=None, color: Optional[str]=None, bold: bool=False, italic: bool=False, underline: bool=False, strike: bool=False, fontsize: Optional[int]=None, list_type: Optional[int]=None, rtf_mode: str='fwd', attach: Optional[Union[Dict[str, Any], str]]=None) -> bytes:
    hdr = InnerPacketHeader(ck=ck_val, bb=1, ty=2, seq=seq, uid=uid, ver=3, cmd=CMD_1TO1_MSG, sub=SUB_1TO1_MSG)
    if color or bold or italic or fontsize or underline or strike or list_type:
        styles = []
        if fontsize:
            styles.append({'start': 0, 'len': len(text), 'st': f'f_{fontsize}'})
        if color:
            styles.append({'start': 0, 'len': len(text), 'st': f"c_{color.lstrip('#')}"})
        if bold:
            styles.append({'start': 0, 'len': len(text), 'st': 'b'})
        if italic:
            styles.append({'start': 0, 'len': len(text), 'st': 'i'})
        if underline:
            styles.append({'start': 0, 'len': len(text), 'st': 'u'})
        if strike:
            styles.append({'start': 0, 'len': len(text), 'st': 's'})
        d3_plain = build_d3_payload_1to1_rtf(text, cryptkey=cryptkey, styles=styles, rtf_mode=rtf_mode, list_type=list_type)
    elif style_id or size is not None or (ttl_ms > 0 and (not quote_data) and (not attach)):
        d3_plain = build_d3_payload_1to1_styled(text, cryptkey=cryptkey, style_id=style_id, size=size, color=color, bold=bold, italic=italic, ttl_ms=ttl_ms)
    else:
        d3_plain = build_d3_payload_1to1(text, cryptkey=cryptkey, ttl_ms=ttl_ms, quote_data=quote_data, attach=attach)
    d3_xor = xor_encode_d3(d3_plain, uid)
    params_prefix = struct.pack('<IBII', target_uid & 4294967295, 3, cmsg_id & 4294967295, 416)
    return hdr.pack() + params_prefix + d3_xor

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
    t_val = str(title or caption or '')
    d_val = str(description or photo_url)
    if not native:
        attach_obj = build_photo_attach(url=photo_url, width=width, height=height, total_size=total_size, title=t_val, description=d_val, thumb_url=thumb_url, hd_url=hd_url, is_original=is_original)
        msg_text = f'{t_val}\n{photo_url}' if t_val and t_val.strip() != photo_url.strip() else photo_url
        if is_group:
            return build_group_message_packet(uid=uid, group_id=target_id, text=msg_text, seq=seq, ck_val=ck_val if ck_val is not None else 0, cmsg_id=cmsg_id, ttl_ms=ttl_ms, quote_data=quote_data, attach=attach_obj)
        else:
            if not cryptkey:
                raise ValueError('cryptkey là bắt buộc khi gửi tin nhắn ảnh 1-1')
            return build_1to1_message_packet(uid=uid, target_uid=target_id, text=msg_text, cryptkey=cryptkey, seq=seq, ck_val=ck_val if ck_val is not None else 0, cmsg_id=cmsg_id, ttl_ms=ttl_ms, quote_data=quote_data, attach=attach_obj)
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

def build_video_binary_payload(url: str, title: str='', description: str='', thumb_url: Optional[str]=None, width: int=1280, height: int=720, duration_ms: int=0, total_size: int=0, sub_type: int=SUB_VIDEO_MSG) -> bytes:
    thumb = str(thumb_url or url)
    u = str(url)
    t = str(title or '')
    d = str(description or u)
    meta_dict = {'duration': int(duration_ms or 0), 'video_original_width': int(width or 1280), 'video_original_height': int(height or 720), 'video_width': int(width or 1280), 'video_height': int(height or 720), 'video_rotation': 0, 'isHD': 1}
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
    t_val = str(title or caption or '')
    d_val = str(description or video_url)
    if not native:
        dur_sec = int(duration_ms) // 1000 if duration_ms > 1000 else int(duration_ms)
        attach_obj = build_video_attach(url=video_url, width=width, height=height, duration=dur_sec, total_size=total_size, title=t_val, description=d_val, thumb_url=thumb_url)
        msg_text = f'{t_val}\n{video_url}' if t_val and t_val.strip() != video_url.strip() else video_url
        if is_group:
            return build_group_message_packet(uid=uid, group_id=target_id, text=msg_text, seq=seq, ck_val=ck_val if ck_val is not None else 0, cmsg_id=cmsg_id, ttl_ms=ttl_ms, quote_data=quote_data, attach=attach_obj)
        else:
            if not cryptkey:
                raise ValueError('cryptkey là bắt buộc khi gửi tin nhắn video 1-1')
            return build_1to1_message_packet(uid=uid, target_uid=target_id, text=msg_text, cryptkey=cryptkey, seq=seq, ck_val=ck_val if ck_val is not None else 0, cmsg_id=cmsg_id, ttl_ms=ttl_ms, quote_data=quote_data, attach=attach_obj)
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

def build_reaction_packet(uid: int, target_id: int, cli_msg_id: int, global_msg_id: int=0, icon: str='❤️', is_group: bool=True, seq: int=-100, ck_val: int=0, cmsg_id: Optional[int]=None) -> bytes:
    cmd = 1785 if is_group else 1780
    sub = 0
    now_ms = int(time.time() * 1000)
    cmsg = cmsg_id if cmsg_id is not None else now_ms & 4294967295
    try:
        from core.models.enums import ReactionIcon
        r_type, r_icon, _ = ReactionIcon.resolve(icon)
    except Exception:
        r_type, r_icon = (5, '/-heart') if icon in ('❤️', 'heart') else (75, icon)
    r_data = {'rType': r_type, 'rIcon': r_icon, 'msgSender': str(uid), 'rMsg': [{'cMsgID': int(cli_msg_id or now_ms), 'gMsgID': int(global_msg_id or 0), 'msgType': 1}], 'source': 0}
    json_bytes = json.dumps(r_data, separators=(',', ':')).encode('utf-8')
    d3_plain = b'7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' + struct.pack('<H', len(json_bytes)) + json_bytes
    d3_xor = xor_encode_d3(d3_plain, uid)
    target_type = 4 if is_group else 3
    params_prefix = struct.pack('<IBII', target_id & 4294967295, target_type, cmsg & 4294967295, 416)
    params = params_prefix + d3_xor
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, target=target_id, target_type=target_type, cmsg=cmsg, bb=1, ty=2, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=1, ty=2, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + params

def build_pin_topic_packet(uid: int, group_id: int, title: str='', cli_msg_id: int=0, global_msg_id: int=0, sender_name: str='Member', seq: int=-100, ck_val: int=0, vercode: int=260802903) -> bytes:
    cmd = CMD_PIN_TOPIC
    sub = SUB_PIN_TOPIC
    buf = bytearray()
    buf.append(1)
    buf.extend(struct.pack('<I', vercode))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<H', 0))
    buf.extend(struct.pack('<I', int(group_id) & 4294967295))
    buf.extend(b'\x04\x05')
    s1 = b'{"needPin":1}'
    buf.extend(struct.pack('<I', len(s1)) + s1)
    buf.extend(b'\x04\x10\x00\x00\x00')
    s2 = '{"emoji":"📌"}'.encode('utf-8')
    buf.extend(s2)
    buf.append(0)
    topic_dict = {'title': str(title or 'Bài ghim nhóm'), 'msg_type': 1, 'client_msg_id': str(cli_msg_id or int(time.time() * 1000)), 'global_msg_id': str(global_msg_id or 0), 'extra': json.dumps({'mentions': []}), 'senderName': str(sender_name or 'Member'), 'senderUid': str(uid)}
    s3 = json.dumps(topic_dict, separators=(',', ':')).encode('utf-8')
    buf.extend(struct.pack('<I', len(s3)) + s3)
    buf.append(6)
    s4 = b'{"topicType":2}'
    buf.extend(struct.pack('<I', len(s4)) + s4)
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_unpin_topic_packet(uid: int, group_id: int, topic_id: int=0, global_msg_id: int=0, cli_msg_id: int=0, seq: int=-100, ck_val: int=0, vercode: int=260802903) -> bytes:
    cmd = CMD_UNPIN_TOPIC
    sub = SUB_UNPIN_TOPIC
    tid = topic_id or global_msg_id or 0
    buf = bytearray()
    buf.append(1)
    buf.extend(struct.pack('<I', vercode))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<H', 0))
    buf.extend(struct.pack('<I', int(group_id) & 4294967295))
    buf.extend(struct.pack('<q', int(tid)))
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_fetch_pinned_topics_packet(uid: int, group_id: int, from_time: int=0, seq: int=-100, ck_val: int=0, vercode: int=260802903) -> bytes:
    cmd = 1703
    sub = 0
    prefix = bytes([1]) + struct.pack('<I', vercode) + struct.pack('<I', 0) + struct.pack('<H', 0)
    pt_params = prefix + struct.pack('<Iq', int(group_id) & 4294967295, int(from_time or 0))
    enc_params = xor_enc(pt_params, uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_cmd_1705_packet(uid: int, group_id: int, field_8byte: int=0, prefix_data: bytes=b'\x01\x0f\x8b\x89W\x00\x00\x00\x00\x00\x00', seq: int=-100, ck_val: int=0) -> bytes:
    cmd = 1705
    sub = 0
    prefix = prefix_data if prefix_data else bytes([1]) + struct.pack('<I', 260802903) + struct.pack('<I', 0) + struct.pack('<H', 0)

    def _l3(s: str) -> bytes:
        b = s.encode('utf-8')
        return struct.pack('<I', len(b)) + b
    extra_list = bytes([4]) + _l3('{"needPin":0}') + bytes([4]) + _l3('{"emoji":""}') + bytes([0]) + _l3('{}') + bytes([6]) + _l3('{"topicType":0}')
    pt_params = prefix + struct.pack('<IQ', int(group_id) & 4294967295, int(field_8byte or 0)) + extra_list
    enc_params = xor_enc(pt_params, uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_disband_242_packet(uid: int, group_id: int, seq: int=-100, ck_val: int=0, vercode: int=260802903) -> bytes:
    cmd = CMD_DISBAND_GROUP
    sub = SUB_DISBAND_GROUP
    buf = bytes([1]) + struct.pack('<I', vercode) + struct.pack('<I', int(group_id) & 4294967295)
    enc_params = xor_enc(buf, uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params
build_disband_group_packet = build_disband_242_packet
build_disband_test_frame = build_cmd_1705_packet

def build_remove_member_packet(uid: int, group_id: int, member_uids: List[int], seq: int=-100, ck_val: int=0) -> bytes:
    cmd = CMD_REMOVE_MEMBER
    sub = SUB_REMOVE_MEMBER
    buf = bytearray()
    buf.extend(struct.pack('<I', int(group_id) & 4294967295))
    for m_uid in member_uids:
        buf.extend(struct.pack('<I', int(m_uid) & 4294967295))
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_kick_member_packet(uid: int, group_id: int, member_uids: List[int], is_block: bool=False, seq: int=-100, ck_val: int=0) -> bytes:
    cmd = CMD_KICK_MEMBER
    sub = SUB_KICK_MEMBER
    buf = bytearray()
    buf.extend(struct.pack('<I', int(group_id) & 4294967295))
    buf.append(1 if is_block else 0)
    buf.extend(struct.pack('<I', len(member_uids)))
    for m_uid in member_uids:
        buf.extend(struct.pack('<I', int(m_uid) & 4294967295))
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_block_group_member_packet(uid: int, group_id: int, member_uids: List[int], seq: int=-100, ck_val: int=0, vercode: int=260802903) -> bytes:
    return build_kick_member_packet(uid=uid, group_id=group_id, member_uids=member_uids, is_block=True, seq=seq, ck_val=ck_val)

def build_block_user_packet(uid: int, target_uid: int, is_block: bool=True, seq: int=-100, ck_val: int=0, vercode: int=260802903) -> bytes:
    cmd = CMD_BLOCK_USER_1TO1 if is_block else CMD_UNBLOCK_USER_1TO1
    sub = 0
    buf = bytearray()
    buf.append(1)
    buf.extend(struct.pack('<I', vercode))
    if is_block:
        buf.extend(struct.pack('<H', 1))
        buf.extend(struct.pack('<I', int(target_uid) & 4294967295))
        buf.extend(struct.pack('<H', 0))
    else:
        buf.extend(struct.pack('<I', int(target_uid) & 4294967295))
        buf.extend(struct.pack('<H', 0))
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_unblock_user_packet(uid: int, target_uid: int, seq: int=-100, ck_val: int=0, vercode: int=260802903) -> bytes:
    return build_block_user_packet(uid, target_uid, is_block=False, seq=seq, ck_val=ck_val, vercode=vercode)

def build_leave_group_packet(uid: int, group_id: int, new_owner_id: int=0, is_silent: bool=False, is_block_readd: bool=False, seq: int=-100, ck_val: int=0, vercode: int=260802903, lang: int=0) -> bytes:
    cmd = CMD_LEAVE_GROUP
    sub = SUB_LEAVE_GROUP
    buf = bytearray()
    buf.append(1)
    buf.extend(struct.pack('<I', vercode))
    src_type = 2 if new_owner_id else 3
    json_bytes = json.dumps({'srcType': src_type}, separators=(',', ':')).encode('utf-8')
    buf.extend(struct.pack('<I', len(json_bytes)))
    buf.extend(json_bytes)
    buf.extend(struct.pack('<H', lang))
    buf.extend(struct.pack('<I', int(group_id) & 4294967295))
    buf.extend(struct.pack('<I', int(new_owner_id) & 4294967295 if new_owner_id else 0))
    buf.append(1 if is_silent else 0)
    buf.append(1 if is_block_readd else 0)
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_leave_group_225_packet(uid: int, group_id: int, seq: int=-100, ck_val: int=0, vercode: int=260802903, lang: int=0) -> bytes:
    cmd = CMD_LEAVE_GROUP_225
    sub = SUB_LEAVE_GROUP_225
    buf = bytearray()
    buf.append(1)
    buf.extend(struct.pack('<I', vercode))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<H', lang))
    buf.extend(struct.pack('<I', int(group_id) & 4294967295))
    buf.extend(struct.pack('<I', 160))
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params
build_leave_group_239_packet = build_leave_group_packet

def build_create_poll_packet(uid: int, group_id: int, question: str, options: List[str], seq: int=-100, ck_val: int=0, vercode: int=260802903) -> bytes:
    cmd = CMD_CREATE_POLL
    sub = SUB_CREATE_POLL
    buf = bytearray()
    buf.append(1)
    buf.extend(struct.pack('<I', vercode))
    src_str = b'{"srcType":3}'
    buf.extend(struct.pack('<I', len(src_str)) + src_str)
    buf.extend(b'\x00\x00')
    buf.extend(struct.pack('<I', int(group_id) & 4294967295))
    q_bytes = question.encode('utf-8')
    buf.extend(struct.pack('<I', len(q_bytes)) + q_bytes)
    buf.extend(b'\x01\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    buf.extend(struct.pack('<I', len(options)))
    for opt in options:
        opt_b = opt.encode('utf-8')
        buf.extend(struct.pack('<I', len(opt_b)) + opt_b)
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_join_group_by_link_901_packet(uid: int, link_url: str, seq: int=-100, ck_val: int=0) -> bytes:
    cmd = 901
    sub = 3
    url_b = link_url.strip().encode('utf-8') if isinstance(link_url, str) else bytes(link_url)
    url_len = len(url_b)
    url_enc = bytearray(url_b)
    for i in range(len(url_enc)):
        if i % 4 == 3:
            url_enc[i] ^= 51
    plain = b'\x00' * 8 + bytes([url_len]) + bytes(url_enc)
    enc_params = xor_encode_d3(plain, uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_preview_link_901_packet(uid: int, link_url: str, seq: int=-100, ck_val: int=0, vercode: int=260802903, source: int=6, sub_type: int=1001) -> bytes:
    return build_join_group_by_link_901_packet(uid=uid, link_url=link_url, seq=seq, ck_val=ck_val)

def build_query_group_906_packet(uid: int, group_id: int, seq: int=-100, ck_val: int=0) -> bytes:
    cmd = 906
    sub = 0
    buf = struct.pack('<I', 0) + struct.pack('<I', 50) + struct.pack('<I', int(group_id) & 4294967295)
    enc_params = xor_enc(buf, uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def parse_d3_compressed_json(body: bytes, uid: int) -> Optional[Dict[str, Any]]:
    if not body or len(body) < 10:
        return None
    import zlib, re, json
    ule = (uid & 4294967295).to_bytes(4, 'little')
    candidates = [body]
    if len(body) > 4:
        candidates.append(body[4:])
    for b in candidates:
        for offset in range(-50, 50):
            a4 = len(b) + offset
            le4 = a4.to_bytes(4, 'little', signed=True)
            k = bytes((XK[i % 32] ^ le4[i % 4] ^ ule[i % 4] for i in range(32)))
            dec = bytes([b[i] ^ k[i % 32] for i in range(len(b))])
            if dec.startswith(b'\x1f\x8b'):
                for w in (16 + zlib.MAX_WBITS, 31, 15, -15):
                    try:
                        d_out = zlib.decompress(dec if w != -15 else dec[10:], w)
                        txt = d_out.decode('utf-8', errors='ignore')
                        res: Dict[str, Any] = {}
                        try:
                            js = json.loads(txt)
                            if isinstance(js, dict):
                                res.update(js)
                        except Exception:
                            pass
                        m_err = re.search('code[^\\d]*(\\d+)', txt)
                        if m_err and 'error_code' not in res:
                            ec = int(m_err.group(1))
                            if ec == 7002:
                                ec = 17002
                            res['error_code'] = ec
                        m_gid = re.search('(?:groupId|grid|id)[^\\d]*(\\d{6,15})', txt)
                        if m_gid and 'group_id' not in res:
                            res['group_id'] = int(m_gid.group(1))
                        res['raw_text'] = txt
                        return res
                    except Exception:
                        pass
            for w in (-15, 15, 0):
                try:
                    d_out = zlib.decompress(dec, w)
                    txt = d_out.decode('utf-8', errors='ignore')
                    res = {}
                    try:
                        js = json.loads(txt)
                        if isinstance(js, dict):
                            res.update(js)
                    except Exception:
                        pass
                    m_err = re.search('code[^\\d]*(\\d+)', txt)
                    if m_err and 'error_code' not in res:
                        ec = int(m_err.group(1))
                        if ec == 7002:
                            ec = 17002
                        res['error_code'] = ec
                    m_gid = re.search('(?:groupId|grid|id)[^\\d]*(\\d{6,15})', txt)
                    if m_gid and 'group_id' not in res:
                        res['group_id'] = int(m_gid.group(1))
                    res['raw_text'] = txt
                    return res
                except Exception:
                    pass
    return None

def build_recall_message_packet(uid: int, target_id: int, cli_msg_id: Union[int, str], global_msg_id: Union[int, str]=0, msg_type: int=1, owner_id: Optional[Union[int, str]]=None, is_group: bool=True, cmsg_counter: int=0, seq: int=-100, ck_val: int=0) -> bytes:
    cmd = CMD_RECALL_MSG_GROUP if is_group else CMD_RECALL_MSG_1TO1
    sub = SUB_RECALL_MSG_GROUP if is_group else SUB_RECALL_MSG_1TO1
    t_type = 4 if is_group else 3
    owner = int(owner_id) if owner_id else int(uid)
    g_id = int(global_msg_id) if global_msg_id else 0
    c_id = int(cli_msg_id) if cli_msg_id else int(time.time() * 1000)
    c_counter = int(cmsg_counter) if cmsg_counter else c_id & 4294967295
    d3_plain = struct.pack('<I', int(target_id) & 4294967295) + struct.pack('<q', c_id) + struct.pack('<q', g_id) + struct.pack('<I', int(msg_type) & 4294967295) + struct.pack('<I', int(owner) & 4294967295)
    d3_enc = xor_encode_d3(d3_plain, uid)
    prefix = struct.pack('<I', int(target_id) & 4294967295) + bytes([t_type]) + struct.pack('<I', c_counter & 4294967295) + struct.pack('<I', 416)
    plain_payload = prefix + d3_enc
    enc_params = xor_enc(plain_payload, uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, target=int(target_id), target_type=t_type, cmsg=c_counter, bb=0, ty=2, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=2, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_delete_message_packet(uid: int, group_id: int, cli_msg_id: Union[int, str], global_msg_id: Union[int, str]='', is_group: bool=True, only_me: bool=False, seq: int=-100, ck_val: int=0) -> bytes:
    cmd = CMD_DELETE_MSG
    sub = SUB_DELETE_MSG
    now_cmi = int(time.time() * 1000)
    t_type = 3 if is_group else 1
    il_val = 1 if only_me else 2
    data_json = json.dumps({'cmi': now_cmi, 'il': il_val, 'data': [{'t': t_type, 'ti': int(group_id), 'si': int(uid), 'di': int(group_id), 'cmi': str(cli_msg_id), 'gmi': str(global_msg_id or ''), 'mt': 1}]}, separators=(',', ':')).encode('utf-8')
    enc_params = xor_enc(data_json, uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_add_member_packet(uid: int, group_id: int, member_uids: List[int], is_invite: bool=False, seq: int=-100, ck_val: int=0) -> bytes:
    cmd = CMD_ADD_MEMBER
    sub = SUB_ADD_MEMBER
    buf = bytearray()
    buf.extend(struct.pack('<I', int(group_id) & 4294967295))
    buf.append(1 if is_invite else 0)
    buf.extend(struct.pack('<I', len(member_uids)))
    for m_uid in member_uids:
        buf.extend(struct.pack('<I', int(m_uid) & 4294967295))
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_join_group_packet(uid: int, group_id: int, source: int=0, seq: int=-100, ck_val: int=0, vercode: int=260802903, ts_ms: Optional[int]=None) -> bytes:
    cmd = CMD_JOIN_GROUP
    sub = SUB_JOIN_GROUP
    if ts_ms is None:
        ts_ms = int(time.time() * 1000)
    prefix = bytes([1]) + struct.pack('<I', vercode) + struct.pack('<I', 0) + struct.pack('<H', 0)
    pt_params = prefix + struct.pack('<IIq', int(group_id) & 4294967295, int(source) & 4294967295, int(ts_ms))
    enc_params = xor_enc(pt_params, uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_join_group_invite_packet(uid: int, group_id: int, inviter_uid: int=0, seq: int=-100, ck_val: int=0, vercode: int=260802903) -> bytes:
    cmd = CMD_JOIN_GROUP_INVITE
    sub = SUB_JOIN_GROUP_INVITE
    prefix = bytes([1]) + struct.pack('<I', vercode) + struct.pack('<I', 0) + struct.pack('<H', 0)
    pt_params = prefix + struct.pack('<Iq', int(group_id) & 4294967295, int(inviter_uid))
    enc_params = xor_enc(pt_params, uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_request_join_group_packet(uid: int, group_id: int=0, msg: str='', link_url: str='', source: int=1, sub_source: int=0, seq: int=-100, ck_val: int=0, vercode: int=260802903) -> bytes:
    cmd = CMD_REQUEST_JOIN_GROUP
    sub = SUB_REQUEST_JOIN_GROUP
    buf = bytearray()
    buf.append(1)
    buf.extend(struct.pack('<I', vercode))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<H', 0))
    buf.extend(struct.pack('<I', int(group_id) & 4294967295))
    if msg:
        msg_bytes = msg.encode('utf-8')
        buf.extend(struct.pack('<I', len(msg_bytes)))
        buf.extend(msg_bytes)
    else:
        buf.extend(struct.pack('<I', 0))
    src_val = int(source) if source is not None else 1
    buf.extend(struct.pack('<I', src_val & 4294967295))
    buf.append(int(sub_source) & 255)
    if link_url:
        link_clean = link_url.strip()
        link_bytes = link_clean.encode('utf-8')
        buf.extend(struct.pack('<I', len(link_bytes)))
        buf.extend(link_bytes)
    else:
        buf.extend(struct.pack('<I', 0))
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_group_link_info_packet(uid: int, link_url: str, source: int=1, sub_source: int=0, seq: int=-100, ck_val: int=0, vercode: int=260802903) -> bytes:
    return build_request_join_group_packet(uid=uid, group_id=0, msg='', link_url=link_url, source=source, sub_source=sub_source, seq=seq, ck_val=ck_val, vercode=vercode)

def build_join_group_by_link_packet(uid: int, link_code: str, group_id: int=0, flag_byte: int=0, seq: int=-100, ck_val: int=0, vercode: int=260802903) -> bytes:
    cmd = CMD_JOIN_GROUP_BY_LINK
    sub = SUB_JOIN_GROUP_BY_LINK
    buf = bytearray()
    buf.append(1)
    buf.extend(struct.pack('<I', vercode))
    link_bytes = link_code.encode('utf-8') if link_code else b''
    buf.extend(struct.pack('<I', len(link_bytes)))
    buf.extend(link_bytes)
    buf.extend(struct.pack('<H', 0))
    buf.extend(struct.pack('<I', int(group_id) & 4294967295))
    buf.append(int(flag_byte) & 255)
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_join_group_2000_packet(uid: int, group_id: int, flag_byte: int=0, seq: int=-100, ck_val: int=0, vercode: int=260802903) -> bytes:
    cmd = CMD_JOIN_GROUP_BY_LINK
    sub = SUB_JOIN_GROUP_BY_LINK
    buf = bytearray()
    buf.append(1)
    buf.extend(struct.pack('<I', vercode))
    buf.extend(struct.pack('<I', 0))
    buf.extend(struct.pack('<H', 0))
    buf.extend(struct.pack('<I', int(group_id) & 4294967295))
    buf.append(int(flag_byte) & 255)
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_outer_frame(inner_packet: bytes, dk: bytes) -> bytes:
    encrypted_body = encrypt_aes_gcm(inner_packet, dk)
    frame = OuterFrame(total_len=len(encrypted_body) + 5, ftype=FRAME_TYPE_DATA, body=encrypted_body)
    return frame.pack()

def parse_incoming_frame(frame: OuterFrame, dk: bytes, cryptkey: Optional[bytes]=None, my_uid: Optional[int]=None) -> dict:
    res = {'ftype': frame.ftype, 'total_len': frame.total_len, 'is_error': False, 'error_code': None, 'cmd': None, 'sub': None, 'cmsg_id': 0, 'parsed_data': None}
    if frame.ftype not in (3, 4):
        return res
    try:
        dec_inner = decrypt_aes_gcm(frame.body, dk)
    except Exception as ex:
        if frame.ftype == 3 and len(frame.body) >= 6:
            try:
                cmd, sub, code = struct.unpack_from('<HHi', frame.body, 0)[:3]
                res.update({'is_error': True, 'cmd': cmd, 'sub': sub, 'error_code': code})
                return res
            except Exception:
                pass
        res['decrypt_error'] = str(ex)
        return res
    if len(dec_inner) < INNER_HEADER_SIZE:
        res['error'] = 'Inner packet quá ngắn'
        return res
    hdr = InnerPacketHeader.unpack(dec_inner)
    params_body = dec_inner[INNER_HEADER_SIZE:]
    res.update({'ck': hdr.ck, 'bb': hdr.bb, 'ty': hdr.ty, 'seq': hdr.seq, 'uid': hdr.uid, 'ver': hdr.ver, 'cmd': hdr.cmd, 'sub': hdr.sub, 'raw_params': params_body})
    if hdr.cmd in (101, 201, 1865, 1867):
        parsed_msgs, cmsg_id = parse_incoming_messages_payload(hdr.cmd, hdr.sub, hdr.uid, params_body, cryptkey=cryptkey, my_uid=my_uid)
        res['cmsg_id'] = cmsg_id
        res['parsed_data'] = {'messages': parsed_msgs}
    elif hdr.cmd == CMD_DELIVERY_RECEIPT and hdr.sub == SUB_DELIVERY_RECEIPT:
        res['parsed_data'] = parse_delivery_receipt_202(params_body)
    elif hdr.cmd == CMD_GROUP_MSG and hdr.sub == SUB_GROUP_MSG:
        if len(params_body) >= 4:
            res['ack_code'] = struct.unpack_from('<i', params_body, 0)[0]
    return res

def parse_incoming_messages_payload(cmd: int, sub: int, uid: int, params_bytes: bytes, cryptkey: Optional[bytes]=None, my_uid: Optional[int]=None) -> Tuple[List[Dict[str, Any]], int]:
    cmsg_id = 0
    if len(params_bytes) >= 13:
        try:
            p_uid, p_type, cmsg_id, flags = struct.unpack('<IBII', params_bytes[:13])
        except Exception:
            pass
    decomp_json = None
    gz_idx = params_bytes.find(b'\x1f\x8b\x08')
    if gz_idx != -1:
        try:
            decomp = gzip.decompress(params_bytes[gz_idx:])
            decomp_json = json.loads(decomp.decode('utf-8', errors='ignore'))
        except Exception:
            pass
    if not decomp_json and cmd in (101, 201):
        payload_bytes = params_bytes[13:] if len(params_bytes) >= 13 else params_bytes
        for try_u in (uid, my_uid):
            if not try_u:
                continue
            try:
                d3_dec = xor_decode_d3(payload_bytes, try_u)
                gz_idx2 = d3_dec.find(b'\x1f\x8b\x08')
                if gz_idx2 != -1:
                    decomp = gzip.decompress(d3_dec[gz_idx2:])
                else:
                    decomp = gzip.decompress(d3_dec)
                decomp_json = json.loads(decomp.decode('utf-8', errors='ignore'))
                if decomp_json:
                    break
            except Exception:
                pass
    if not decomp_json:
        try:
            decomp_json = json.loads(params_bytes.decode('utf-8', errors='ignore'))
        except Exception:
            pass
    messages = []
    if decomp_json and isinstance(decomp_json, dict):
        msg_list = decomp_json.get('msg', [])
        if not isinstance(msg_list, list):
            msg_list = [msg_list] if msg_list else []
        for item in msg_list:
            if not isinstance(item, dict):
                continue
            txt_obj = item.get('text', {})
            ttype = txt_obj.get('type') or 'webchat'
            d = txt_obj.get('data', {})
            if not d and 'data' in item:
                d = item.get('data', {})
            raw_from_u = d.get('fromU')
            msg_id = d.get('id') or item.get('id')
            cmi_id = d.get('cliMsgId') or cmsg_id
            to_dest = d.get('to')
            is_group = cmd in (201, 1867)
            if cmd == 1865:
                is_self = True
                from_u = my_uid or uid
                from_d = 'Tôi'
            elif cmd == 101:
                is_self = False
                from_u = raw_from_u or uid
                from_d = d.get('fromD') or str(from_u)
            elif cmd in (201, 1867):
                is_self = raw_from_u == my_uid if my_uid and raw_from_u is not None else raw_from_u == 0
                from_u = raw_from_u or uid
                from_d = d.get('fromD') or str(from_u)
            else:
                is_self = raw_from_u == my_uid if my_uid else False
                from_u = raw_from_u or uid
                from_d = d.get('fromD') or str(from_u)
            msg_txt = d.get('msg', '')
            if d.get('mcrypt') == 1 and d.get('iv') and cryptkey:
                try:
                    iv_raw = base64.b64decode(d['iv'])
                    ct_raw = base64.b64decode(msg_txt)
                    pt_raw = decrypt_e2ee_cbc(ct_raw, cryptkey, iv_raw)
                    msg_txt = pt_raw.decode('utf-8', errors='replace')
                except Exception:
                    pass
            quote_data = d.get('quote') or d.get('q') or item.get('quote') or txt_obj.get('quote')
            if isinstance(quote_data, str) and quote_data.strip().startswith('{'):
                try:
                    quote_data = json.loads(quote_data)
                except Exception:
                    pass
            mentions_data = d.get('mentions')
            if isinstance(mentions_data, str) and mentions_data.startswith('['):
                try:
                    mentions_data = json.loads(mentions_data)
                except Exception:
                    mentions_data = []
            elif not isinstance(mentions_data, list):
                mentions_data = []
            messages.append({'cmd': cmd, 'is_group': is_group, 'is_self': is_self, 'to_group': to_dest if is_group else None, 'to_id': to_dest, 'from_uid': from_u, 'from_display': from_d, 'from_name': from_d, 'msg_id': msg_id, 'cli_msg_id': cmi_id, 'content': msg_txt, 'text': msg_txt, 'ttl': d.get('ttl', 0), 'ts': d.get('ts') or int(time.time() * 1000), 'attach': d.get('attach', ''), 'mentions': mentions_data, 'quote': quote_data, 'type': ttype, 'raw': d})
    return (messages, cmsg_id)

def parse_group_sync_1867(params_bytes: bytes) -> dict:
    messages, _ = parse_incoming_messages_payload(1867, 0, 0, params_bytes)
    return {'raw_json': None, 'messages': messages}

def parse_delivery_receipt_202(params_bytes: bytes) -> dict:
    out = {}
    if len(params_bytes) >= 16:
        try:
            gmi = struct.unpack_from('<Q', params_bytes, 0)[0]
            out['globalMsgId'] = gmi
        except Exception:
            pass
    return out
