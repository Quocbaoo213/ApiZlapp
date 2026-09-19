import json
import os
import re
import struct
import time
import zlib
from typing import Optional, Tuple, Dict, Any, List, Union

from core.socket.constants import (
    XK,
    FRAME_TYPE_DATA,
    FRAME_TYPE_CONTROL,
    CMD_PING,
    SUB_PING,
    CMD_GROUP_MSG,
    SUB_GROUP_MSG,
    CMD_1TO1_MSG,
    SUB_1TO1_MSG,
    SUB_PHOTO_MSG,
    SUB_DOODLE_MSG,
    SUB_PHOTO_ATTACH_MSG,
    SUB_ATTACH_MSG,
    SUB_VIDEO_MSG,
    SUB_STICKER_MSG,
    SUB_LOCATION_MSG,
    SUB_FILE_MSG,
    SUB_CONTACT_MSG,
    CMD_REACTION_ACTION,
    SUB_REACTION_ACTION,
    CMD_GROUP_TYPING,
    SUB_GROUP_TYPING,
    CMD_1TO1_TYPING,
    SUB_1TO1_TYPING,
    CMD_PIN_TOPIC,
    SUB_PIN_TOPIC,
    CMD_UNPIN_TOPIC,
    SUB_UNPIN_TOPIC,
    CMD_DISBAND_GROUP,
    SUB_DISBAND_GROUP,
    CMD_REMOVE_MEMBER,
    SUB_REMOVE_MEMBER,
    CMD_KICK_MEMBER,
    SUB_KICK_MEMBER,
    CMD_BLOCK_GROUP_MEMBER,
    SUB_BLOCK_GROUP_MEMBER,
    CMD_BLOCK_USER,
    SUB_BLOCK_USER,
    CMD_BLOCK_USER_1TO1,
    SUB_BLOCK_USER_1TO1,
    CMD_UNBLOCK_USER_1TO1,
    SUB_UNBLOCK_USER_1TO1,
    CMD_ADD_MEMBER,
    SUB_ADD_MEMBER,
    CMD_LEAVE_GROUP,
    SUB_LEAVE_GROUP,
    CMD_LEAVE_GROUP_225,
    SUB_LEAVE_GROUP_225,
    CMD_JOIN_GROUP,
    SUB_JOIN_GROUP,
    CMD_JOIN_GROUP_INVITE,
    SUB_JOIN_GROUP_INVITE,
    CMD_REQUEST_JOIN_GROUP,
    SUB_REQUEST_JOIN_GROUP,
    CMD_JOIN_GROUP_BY_LINK,
    SUB_JOIN_GROUP_BY_LINK,
    CMD_CREATE_POLL,
    SUB_CREATE_POLL,
    CMD_RECALL_MSG_GROUP,
    SUB_RECALL_MSG_GROUP,
    CMD_RECALL_MSG_1TO1,
    SUB_RECALL_MSG_1TO1,
    CMD_DELETE_MSG,
    SUB_DELETE_MSG,
)
from core.socket.frame import InnerPacketHeader, compute_checksum, xor_encode_d3, dekey, xor_enc
from core.socket.crypto import encrypt_e2ee_cbc
from core.socket.attach import (
    build_photo_attach,
    build_video_attach,
    build_sticker_attach,
    build_location_attach,
    build_file_attach,
    build_contact_attach,
)

def u16_len(s: str) -> int:
    return len(s.encode('utf-16-le')) // 2


def merge_styles(styles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not styles:
        return []
    merged_map = {}
    order = []
    for s in styles:
        if not isinstance(s, dict) or 'start' not in s or 'len' not in s:
            continue
        key = (int(s['start']), int(s['len']))
        st_val = str(s.get('st', '')).strip()
        if not st_val:
            continue
        tokens = [t.strip() for t in st_val.split(',') if t.strip()]
        if key not in merged_map:
            merged_map[key] = []
            order.append(key)
        for tok in tokens:
            if tok not in merged_map[key]:
                merged_map[key].append(tok)
    res = []
    for k in order:
        res.append({
            'start': k[0],
            'len': k[1],
            'st': ','.join(merged_map[k])
        })
    return res


def parse_formatted_text(text: str) -> Tuple[str, List[Dict[str, Any]]]:
    if not text:
        return text, []

    tag_re = re.compile(
        r'</?(?:b|i|u|s|red|green|yellow|blue|(?:color|c)=#?([0-9a-fA-F]{3,8})|(?:size|fontsize|f)=(\d+))>',
        re.IGNORECASE
    )
    if tag_re.search(text):
        tag_stack: Dict[str, List[int]] = {}
        color_stack: List[Tuple[int, str]] = []
        size_stack: List[Tuple[int, int]] = []
        out_parts = []
        styles = []
        current_u16_pos = 0

        last_idx = 0
        for m in tag_re.finditer(text):
            plain_chunk = text[last_idx:m.start()]
            if plain_chunk:
                out_parts.append(plain_chunk)
                current_u16_pos += u16_len(plain_chunk)

            raw_tag = m.group(0).lower()
            is_close = raw_tag.startswith('</')
            tag_name = m.group(0)[2 if is_close else 1:-1].strip().lower()

            if '=' in tag_name:
                key, val = tag_name.split('=', 1)
                key = key.strip()
                val = val.strip().lstrip('#')
            else:
                key = tag_name
                val = None

            if key in ('b', 'i', 'u', 's'):
                if is_close:
                    if tag_stack.get(key):
                        start_pos = tag_stack[key].pop()
                        styles.append({'start': start_pos, 'len': current_u16_pos - start_pos, 'st': key})
                else:
                    tag_stack.setdefault(key, []).append(current_u16_pos)

            elif key in ('red', 'green', 'yellow', 'blue'):
                c_map = {'red': 'db342e', 'green': '15a85f', 'yellow': 'f7b503', 'blue': '1877f2'}
                hex_c = c_map[key]
                if is_close:
                    if color_stack:
                        start_pos, _ = color_stack.pop()
                        styles.append({'start': start_pos, 'len': current_u16_pos - start_pos, 'st': f'c_{hex_c}'})
                else:
                    color_stack.append((current_u16_pos, hex_c))

            elif key in ('color', 'c'):
                if is_close:
                    if color_stack:
                        start_pos, hex_c = color_stack.pop()
                        styles.append({'start': start_pos, 'len': current_u16_pos - start_pos, 'st': f'c_{hex_c}'})
                else:
                    if val:
                        color_stack.append((current_u16_pos, val.lower()))

            elif key in ('size', 'fontsize', 'f'):
                if is_close:
                    if size_stack:
                        start_pos, sz = size_stack.pop()
                        styles.append({'start': start_pos, 'len': current_u16_pos - start_pos, 'st': f'f_{sz}'})
                else:
                    if val and val.isdigit():
                        size_stack.append((current_u16_pos, int(val)))

            last_idx = m.end()

        tail = text[last_idx:]
        if tail:
            out_parts.append(tail)
            current_u16_pos += u16_len(tail)

        return ''.join(out_parts), merge_styles(styles)

    token_to_st = {
        '**': 'b',
        '__': 'u',
        '~~': 's',
        '!!': 'c_db342e',
        '++': 'c_15a85f',
        '==': 'c_f7b503',
        '*': 'i',
        '_': 'i'
    }

    out_chars = []
    styles = []
    current_u16 = 0
    i = 0
    n = len(text)
    stack: Dict[str, List[int]] = {k: [] for k in token_to_st}
    tokens = sorted(token_to_st.keys(), key=len, reverse=True)

    while i < n:
        matched_tok = None
        for tok in tokens:
            if text.startswith(tok, i):
                matched_tok = tok
                break

        if not matched_tok:
            ch = text[i]
            out_chars.append(ch)
            current_u16 += u16_len(ch)
            i += 1
            continue

        lt = len(matched_tok)
        next_ch = text[i + lt] if i + lt < n else None

        if stack[matched_tok]:
            start_pos = stack[matched_tok].pop()
            length = current_u16 - start_pos
            if length > 0:
                styles.append({'start': start_pos, 'len': length, 'st': token_to_st[matched_tok]})
            i += lt
            continue

        if next_ch is not None and not next_ch.isspace():
            close_idx = text.find(matched_tok, i + lt)
            if close_idx != -1:
                stack[matched_tok].append(current_u16)
                i += lt
                continue

        ch = text[i]
        out_chars.append(ch)
        current_u16 += u16_len(ch)
        i += 1

    return ''.join(out_chars), merge_styles(styles)


def build_d3_payload_group(
    text: str,
    ttl_ms: int = 0,
    quote_data: Optional[Dict[str, Any]] = None,
    mentions: Optional[List[Dict[str, Any]]] = None,
    style_id: Optional[int] = None,
    size: Optional[int] = None,
    color: Optional[str] = None,
    bold: bool = False,
    italic: bool = False,
    underline: bool = False,
    strike: bool = False,
    fontsize: Optional[int] = None,
    list_type: Optional[int] = None,
    rtf_mode: str = 'fwd',
    attach: Optional[Union[Dict[str, Any], str]] = None,
    styles: Optional[List[Dict[str, Any]]] = None,
    sub_id: int = 1
) -> bytes:
    ttl_ms = int(ttl_ms or 0)
    prop_obj: Dict[str, Any] = {
        'sSrcType': -1,
        'sSrcStr': '',
        'msg_warning_type': 0,
        'emoji': {'content': 0, 'num': 0, 'uniq': 0, 'first': '', 'last': '', 'most': '', 'text': 1}
    }
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

    mention_len = 0
    if quote_data:
        if quote_data.get('fromD'):
            tag = f"@{quote_data['fromD']}"
            if text.startswith(tag):
                mention_len = u16_len(tag)
        if mention_len == 0 and quote_data.get('ownerId'):
            tag_uid = f"@{quote_data['ownerId']}"
            if text.startswith(tag_uid):
                mention_len = u16_len(tag_uid)
    if mention_len == 0 and text.startswith('@'):
        parts = text.split(' ', 1)
        mention_len = u16_len(parts[0])

    tot_u16 = u16_len(text)

    valid_styles = []
    if styles:
        raw_styles = []
        for s in styles:
            if isinstance(s, dict) and 'start' in s and 'len' in s and 'st' in s:
                raw_styles.append({
                    'start': int(s['start']),
                    'len': int(s['len']),
                    'st': str(s['st'])
                })
        valid_styles = merge_styles(raw_styles)
    else:
        start_idx = 0
        if mention_len > 0 and mention_len < tot_u16:
            if text.startswith('@'):
                m_parts = text.split(' ', 1)
                tag_sp = m_parts[0] + ' '
                if text.startswith(tag_sp):
                    start_idx = u16_len(tag_sp)
                else:
                    start_idx = mention_len
            else:
                start_idx = mention_len
        target_len = max(1, tot_u16 - start_idx) if tot_u16 > start_idx else tot_u16
        if start_idx >= tot_u16:
            start_idx = 0
            target_len = tot_u16

        tokens = []
        if bold:
            tokens.append('b')
        if italic:
            tokens.append('i')
        if underline:
            tokens.append('u')
        if strike:
            tokens.append('s')
        if fontsize is not None:
            tokens.append(f'f_{int(fontsize)}')
        if color:
            c_clean = str(color).lstrip('#').lower()
            tokens.append(f'c_{c_clean}')
        if list_type:
            tokens.append(f'lst_{int(list_type)}')

        if tokens:
            valid_styles.append({
                'start': start_idx,
                'len': target_len,
                'st': ','.join(tokens)
            })

    if valid_styles:
        prop_obj['styles'] = valid_styles
        prop_obj['ver'] = 1
        if not prop_obj.get('attach'):
            rtf_attach = {
                "title": "",
                "description": "",
                "href": "",
                "thumb": "",
                "childnumber": 0,
                "action": "rtf",
                "params": json.dumps({"ver": 1, "styles": valid_styles}, separators=(',', ':')),
                "type": ""
            }
            prop_obj['attach'] = json.dumps(rtf_attach, separators=(',', ':'), ensure_ascii=False)

    prop_bytes = json.dumps(prop_obj, separators=(',', ':')).encode('utf-8')
    text_bytes = text.encode('utf-8')

    sz_val = size
    if sz_val is None and fontsize is not None:
        sz_val = int(fontsize)
    size_val = struct.pack('<i', sz_val if sz_val is not None else -1)

    col_str = color
    if not col_str:
        for s in prop_obj.get('styles', []):
            st_val = str(s.get('st', ''))
            for part in st_val.split(','):
                if part.startswith('c_'):
                    col_str = part[2:]
                    break
    if col_str:
        try:
            color_int = int(str(col_str).lstrip('#'), 16)
            color_val = struct.pack('<i', color_int if color_int < 2 ** 31 else color_int - 2 ** 32)
        except Exception:
            color_val = struct.pack('<i', -1)
    else:
        color_val = struct.pack('<i', -1)

    has_bold = bold or any('b' in s.get('st', '').split(',') for s in prop_obj.get('styles', []))
    has_italic = italic or any('i' in s.get('st', '').split(',') for s in prop_obj.get('styles', []))
    type_v = -1
    if has_bold and has_italic:
        type_v = 3
    elif has_bold:
        type_v = 1
    elif has_italic:
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
        sub_hdr = struct.pack('<H', int(sub_id))
        count_byte = 4 if ttl_ms > 0 else 3
        buf = bytearray()
        buf += sub_hdr + bytes([count_byte, 11, 1])
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
    sub_hdr = struct.pack('<H', int(sub_id))
    if ttl_ms > 0:
        header = bytearray(sub_hdr + bytes([2, 7, 0])) + style_hdr + struct.pack('<I', len(prop_bytes)) + prop_bytes
        ttl_block = bytes([8]) + struct.pack('<I', ttl_ms) + bytes(4)
        return header + ttl_block + text_bytes
    header = bytearray(sub_hdr + bytes([1, 7, 0])) + style_hdr + struct.pack('<I', len(prop_bytes)) + prop_bytes
    return bytes(header + text_bytes)

def build_d3_json(style_id: Optional[int]=None) -> bytes:
    if style_id:
        obj = {'sSrcType': -1, 'sSrcStr': '', 'decorInfo': {'decorType': 4, 'typoId': style_id}, 'msg_warning_type': 0, 'emoji': {'content': 0, 'num': 0, 'uniq': 0, 'first': '', 'last': '', 'most': '', 'text': 1}}
        return json.dumps(obj, separators=(',', ':')).encode('utf-8')
    return b'{"sSrcType":-1,"sSrcStr":"","msg_warning_type":0,"emoji":{"content":0,"num":0,"uniq":0,"first":"","last":"","most":"","text":1}}'

def build_d3_payload_1to1(text: str, cryptkey: Optional[bytes]=None, ttl_ms: int=0, quote_data: Optional[Dict[str, Any]]=None, attach: Optional[Union[Dict[str, Any], str]]=None, sub_id: int=41) -> bytes:
    ttl_ms = int(ttl_ms or 0)
    if cryptkey:
        ct, iv = encrypt_e2ee_cbc(text.encode('utf-8'), cryptkey)
    else:
        ct = text.encode('utf-8')
        iv = bytes(16)
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
    sub_hdr = struct.pack('<H', int(sub_id))
    if not quote_data:
        if ttl_ms > 0:
            ttl_block = bytes([8]) + struct.pack('<I', ttl_ms) + bytes(4)
            prop_header = sub_hdr + bytes([2, 7, 0]) + b'\xff' * 12 + struct.pack('<I', len(prop_bytes)) + prop_bytes
            return prop_header + ttl_block + text_block
        prop_header = sub_hdr + bytes([1, 7, 0]) + b'\xff' * 12 + struct.pack('<I', len(prop_bytes)) + prop_bytes
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
    buf += sub_hdr + bytes([count_byte, 11, 1])
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

def build_group_message_packet(
    uid: int,
    group_id: int,
    text: str,
    seq: int,
    ck_val: int,
    cmsg_id: int,
    ttl_ms: int = 0,
    quote_data: Optional[dict] = None,
    mentions: Optional[list] = None,
    style_id: Optional[int] = None,
    size: Optional[int] = None,
    color: Optional[str] = None,
    bold: bool = False,
    italic: bool = False,
    underline: bool = False,
    strike: bool = False,
    fontsize: Optional[int] = None,
    list_type: Optional[int] = None,
    rtf_mode: str = 'fwd',
    attach: Optional[Union[Dict[str, Any], str]] = None,
    styles: Optional[List[Dict[str, Any]]] = None
) -> bytes:
    hdr = InnerPacketHeader(ck=ck_val, bb=1, ty=2, seq=seq, uid=uid, ver=3, cmd=CMD_GROUP_MSG, sub=SUB_GROUP_MSG)
    d3_plain = build_d3_payload_group(
        text,
        ttl_ms=ttl_ms,
        quote_data=quote_data,
        mentions=mentions,
        style_id=style_id,
        size=size,
        color=color,
        bold=bold,
        italic=italic,
        underline=underline,
        strike=strike,
        fontsize=fontsize,
        list_type=list_type,
        rtf_mode=rtf_mode,
        attach=attach,
        styles=styles
    )
    d3_xor = xor_encode_d3(d3_plain, uid)
    params_prefix = struct.pack('<IBII', group_id & 4294967295, 4, cmsg_id & 4294967295, 416)
    return hdr.pack() + params_prefix + d3_xor

def build_1to1_message_packet(
    uid: int,
    target_uid: int,
    text: str,
    cryptkey: bytes,
    seq: int,
    ck_val: int,
    cmsg_id: int,
    ttl_ms: int = 0,
    quote_data: Optional[dict] = None,
    style_id: Optional[int] = None,
    size: Optional[int] = None,
    color: Optional[str] = None,
    bold: bool = False,
    italic: bool = False,
    underline: bool = False,
    strike: bool = False,
    fontsize: Optional[int] = None,
    list_type: Optional[int] = None,
    rtf_mode: str = 'fwd',
    attach: Optional[Union[Dict[str, Any], str]] = None,
    styles: Optional[List[Dict[str, Any]]] = None
) -> bytes:
    hdr = InnerPacketHeader(ck=ck_val, bb=1, ty=2, seq=seq, uid=uid, ver=3, cmd=CMD_1TO1_MSG, sub=SUB_1TO1_MSG)
    u16_l = u16_len(text)
    if styles or color or bold or italic or fontsize or underline or strike or list_type:
        raw_styles = []
        if styles:
            for s in styles:
                if isinstance(s, dict) and 'start' in s and 'len' in s and 'st' in s:
                    raw_styles.append({
                        'start': int(s['start']),
                        'len': int(s['len']),
                        'st': str(s['st'])
                    })
        else:
            tokens = []
            if bold:
                tokens.append('b')
            if italic:
                tokens.append('i')
            if underline:
                tokens.append('u')
            if strike:
                tokens.append('s')
            if fontsize:
                tokens.append(f'f_{fontsize}')
            if color:
                tokens.append(f"c_{str(color).lstrip('#').lower()}")
            if tokens:
                raw_styles.append({'start': 0, 'len': u16_l, 'st': ','.join(tokens)})
        applied_styles = merge_styles(raw_styles)
        d3_plain = build_d3_payload_1to1_rtf(text, cryptkey=cryptkey, styles=applied_styles, rtf_mode=rtf_mode, list_type=list_type)
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

def build_pin_topic_packet(uid: int, group_id: int, title: str='', cli_msg_id: int=0, global_msg_id: int=0, sender_name: str='Member', sender_uid: int=0, seq: int=-100, ck_val: int=0, vercode: int=260802903) -> bytes:
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
    s_uid = str(sender_uid if sender_uid else uid)
    topic_dict = {'title': str(title or 'Bài ghim nhóm'), 'msg_type': 1, 'client_msg_id': str(cli_msg_id or int(time.time() * 1000)), 'global_msg_id': str(global_msg_id or 0), 'extra': json.dumps({'mentions': []}), 'senderName': str(sender_name or 'Member'), 'senderUid': s_uid}
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

def build_join_group_by_link_901_packet(uid: int, link_url: str, seq: int=-100, ck_val: int=0, vercode: int=260802903, source: int=1, sub_type: int=0) -> bytes:
    cmd = 901
    sub = 3
    url_clean = str(link_url).strip()
    if not url_clean.startswith('http://') and not url_clean.startswith('https://'):
        url_clean = f'https://zalo.me/g/{url_clean}'
    url_b = url_clean.encode('utf-8')
    buf = bytearray()
    buf.append(1)
    buf.extend(struct.pack('<I', int(vercode)))
    buf.extend(struct.pack('<I', len(url_b)))
    buf.extend(url_b)
    buf.extend(struct.pack('<I', int(source)))
    buf.extend(struct.pack('<I', int(sub_type)))
    buf.append(0)
    buf.extend(struct.pack('<i', -1))
    enc_params = xor_enc(bytes(buf), uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_preview_link_901_packet(uid: int, link_url: str, seq: int=-100, ck_val: int=0, vercode: int=260802903, source: int=1, sub_type: int=0) -> bytes:
    return build_join_group_by_link_901_packet(uid=uid, link_url=link_url, seq=seq, ck_val=ck_val, vercode=vercode, source=source, sub_type=sub_type)


def build_query_group_906_packet(uid: int, group_id: int, seq: int=-100, ck_val: int=0) -> bytes:
    cmd = 906
    sub = 0
    buf = struct.pack('<I', 0) + struct.pack('<I', 50) + struct.pack('<I', int(group_id) & 4294967295)
    enc_params = xor_enc(buf, uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

def build_query_user_profile_151_packet(uid: int, target_uid: int, seq: int = -100, ck_val: int = 0, vercode: int = 260802903, version: int = 0) -> bytes:
    cmd = 151
    sub = 4
    buf = struct.pack('<I', int(target_uid) & 4294967295) + struct.pack('<I', version) + struct.pack('<I', vercode) + b'\x00'
    enc_params = xor_enc(buf, uid)
    if ck_val == 0:
        ck_val = compute_checksum(cmd, sub, seq, uid, bb=0, ty=1, ver=3)
    hdr = InnerPacketHeader(ck=ck_val, bb=0, ty=1, seq=seq, uid=uid, ver=3, cmd=cmd, sub=sub)
    return hdr.pack() + enc_params

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

