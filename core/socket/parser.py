import base64
import gzip
import json
import logging
import re
import struct
import time
import zlib
from typing import Optional, Tuple, Dict, Any, List

from core.socket.constants import (
    XK,
    FRAME_TYPE_DATA,
    FRAME_TYPE_CONTROL,
    CMD_GROUP_MSG,
    SUB_GROUP_MSG,
    CMD_DELIVERY_RECEIPT,
    SUB_DELIVERY_RECEIPT,
    CMD_REACTION_PUSH
)
from core.socket.frame import InnerPacketHeader, OuterFrame, INNER_HEADER_SIZE
from core.socket.crypto import decrypt_aes_gcm, decrypt_e2ee_cbc

logger = logging.getLogger('core.socket.parser')

def dekey(a4: int, uid: int) -> bytes:
    ule = struct.pack('<I', uid & 4294967295)
    k1 = bytes((XK[i % 32] ^ struct.pack('<I', a4)[i % 4] for i in range(32)))
    return bytes((k1[i % 32] ^ ule[i % 4] for i in range(32)))

def xor_decode_d3(ct: bytes, uid: int) -> bytes:
    key = dekey(len(ct) + 27, uid)
    return bytes((ct[i] ^ key[i % 32] for i in range(len(ct))))

def parse_d3_compressed_json(body: bytes, uid: int) -> Optional[Dict[str, Any]]:
    if not body or len(body) < 10:
        return None
    ule = (uid & 4294967295).to_bytes(4, 'little')
    candidates = [body]
    if len(body) > 4:
        candidates.append(body[4:])
    priority_offsets = [27, 0, 18, -18, 36, -36]
    all_offsets = priority_offsets + [o for o in range(-50, 50) if o not in priority_offsets]
    for b in candidates:
        for offset in all_offsets:
            a4 = len(b) + offset
            le4 = a4.to_bytes(4, 'little', signed=True)
            k = bytes((XK[i % 32] ^ le4[i % 4] ^ ule[i % 4] for i in range(32)))
            dec = bytes([b[i] ^ k[i % 32] for i in range(len(b))])
            for w in (31, 16 + zlib.MAX_WBITS, 15, -15):
                try:
                    d_out = zlib.decompress(dec if (w != -15 or not dec.startswith(b'\x1f\x8b')) else dec[10:], w)
                    txt = d_out.decode('utf-8', errors='ignore')
                    js = None
                    try:
                        js = json.loads(txt)
                    except Exception:
                        pass
                    if js is not None and isinstance(js, dict):
                        res: Dict[str, Any] = dict(js)
                        item = js.get('data', {}).get('item', {}) if isinstance(js.get('data'), dict) else (js.get('item', {}) if isinstance(js.get('item'), dict) else {})
                        if isinstance(item, dict) and 'gid' in item and 'group_id' not in res:
                            try:
                                res['group_id'] = int(item['gid'])
                            except Exception:
                                pass
                        m_err = re.search(r'code[^\d]*(\d+)', txt)
                        if m_err and 'error_code' not in res:
                            ec = int(m_err.group(1))
                            if ec == 7002:
                                ec = 17002
                            res['error_code'] = ec
                        m_gid = re.search(r'(?:groupId|grid|id)[^\d]*(\d{6,15})', txt)
                        if m_gid and 'group_id' not in res:
                            res['group_id'] = int(m_gid.group(1))
                        res['raw_text'] = txt
                        return res
                except Exception:
                    pass
    return None

def parse_incoming_typing(cmd: int, sub: int, params_bytes: bytes) -> List[Dict[str, Any]]:
    if len(params_bytes) < 8:
        return []
    try:
        target_id, target_type = struct.unpack_from('<II', params_bytes, 0)
        idx = params_bytes.find(b'\x1f\x8b')
        if idx == -1:
            return []
        dec = gzip.decompress(params_bytes[idx:])
        info = json.loads(dec.decode('utf-8', errors='ignore'))
        u_id = info.get('uid') or 0
        e_val = info.get('e', 0)
        is_pc = bool(info.get('isPC', 0))
        is_typing = (e_val == 0)
        is_group = (cmd == 206) or (target_type == 4)
        return [{
            'cmd': cmd,
            'sub': sub,
            'type': 'chat.typing',
            'msg_type': 'chat.typing',
            'from_uid': u_id,
            'from_display': str(u_id),
            'from_name': str(u_id),
            'to_id': target_id,
            'to_group': target_id if is_group else None,
            'is_group': is_group,
            'is_typing': is_typing,
            'is_pc': is_pc,
            'content': '[Đang soạn tin...]' if is_typing else '[Đã dừng soạn tin]',
            'text': '[Đang soạn tin...]' if is_typing else '[Đã dừng soạn tin]',
            'raw': info
        }]
    except Exception as ex:
        logger.debug(f'parse_incoming_typing error: {ex}')
        return []

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
    if hdr.cmd in (101, 201, 224, 1865, 1867):
        parsed_msgs, cmsg_id = parse_incoming_messages_payload(hdr.cmd, hdr.sub, hdr.uid, params_body, cryptkey=cryptkey, my_uid=my_uid)
        res['cmsg_id'] = cmsg_id
        res['parsed_data'] = {'messages': parsed_msgs}
    elif hdr.cmd in (106, 206):
        parsed_typing = parse_incoming_typing(hdr.cmd, hdr.sub, params_body)
        res['parsed_data'] = {'messages': parsed_typing, 'typing': parsed_typing}
    elif hdr.cmd == CMD_REACTION_PUSH:
        parsed_reactions = parse_incoming_reactions_1785(params_body, my_uid=my_uid)
        res['parsed_data'] = {'messages': parsed_reactions, 'reactions': parsed_reactions}
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
            mem_name = None
            if not raw_from_u and 'members' in d and isinstance(d['members'], list) and d['members']:
                first_mem = d['members'][0]
                if isinstance(first_mem, dict):
                    raw_from_u = first_mem.get('id') or first_mem.get('uid')
                    mem_name = first_mem.get('name') or first_mem.get('dName')
            if not raw_from_u:
                raw_from_u = d.get('creatorId') or d.get('ownerId')

            to_dest = d.get('to') or d.get('groupId') or d.get('grid')
            is_group = (cmd in (201, 224, 1867)) or bool(d.get('groupId')) or bool(d.get('grid'))
            if cmd == 1865:
                is_self = True
                from_u = my_uid or uid
                from_d = 'Tôi'
            elif cmd == 101:
                is_self = False
                from_u = raw_from_u or uid
                from_d = d.get('fromD') or mem_name or str(from_u)
            elif is_group:
                is_self = (raw_from_u == my_uid) if (my_uid and raw_from_u is not None) else (raw_from_u == 0)
                from_u = raw_from_u or uid
                from_d = d.get('fromD') or mem_name or str(from_u)
            else:
                is_self = (raw_from_u == my_uid) if my_uid else False
                from_u = raw_from_u or uid
                from_d = d.get('fromD') or mem_name or str(from_u)

            msg_txt = d.get('msg', '')
            if not msg_txt:
                if ttype == 'group.leave':
                    msg_txt = f"{from_d} đã rời nhóm"
                elif ttype in ('group.join', 'group.add'):
                    msg_txt = f"{from_d} đã tham gia nhóm"
                elif ttype == 'group.kick':
                    msg_txt = f"{from_d} đã bị mời ra khỏi nhóm"
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
            msg_ts = d.get('ts') or item.get('ts')
            if not msg_ts and d.get('time'):
                try:
                    t_val = int(d.get('time'))
                    msg_ts = t_val * 1000 if t_val < 10000000000 else t_val
                except Exception:
                    pass
            if not msg_ts and item.get('time'):
                try:
                    t_val = int(item.get('time'))
                    msg_ts = t_val * 1000 if t_val < 10000000000 else t_val
                except Exception:
                    pass
            if not msg_ts and cmi_id:
                try:
                    cmi_int = int(cmi_id)
                    if 1500000000000 <= cmi_int <= 3000000000000:
                        msg_ts = cmi_int
                except Exception:
                    pass
            if not msg_ts and isinstance(decomp_json, dict) and decomp_json.get('last'):
                try:
                    l_int = int(decomp_json['last'])
                    if 1500000000000 <= l_int <= 3000000000000:
                        msg_ts = l_int
                except Exception:
                    pass
            rtf_styles = None
            rtf_params = None
            att_val = d.get('attach')
            att_dict = None
            if isinstance(att_val, dict):
                att_dict = att_val
            elif isinstance(att_val, str) and att_val.strip().startswith('{'):
                try:
                    att_dict = json.loads(att_val)
                except Exception:
                    pass
            if isinstance(att_dict, dict) and att_dict.get('action') == 'rtf':
                p_raw = att_dict.get('params')
                if isinstance(p_raw, str) and p_raw.strip().startswith('{'):
                    try:
                        rtf_params = json.loads(p_raw)
                    except Exception:
                        pass
                elif isinstance(p_raw, dict):
                    rtf_params = p_raw
                if isinstance(rtf_params, dict):
                    rtf_styles = rtf_params.get('styles')

            topic_id = None
            if not topic_id and isinstance(d.get('extraInfo'), dict):
                top_obj = d['extraInfo'].get('topic')
                if isinstance(top_obj, dict) and top_obj.get('id'):
                    try:
                        topic_id = int(top_obj['id'])
                    except Exception:
                        pass

            if isinstance(att_dict, dict):
                act_name = str(att_dict.get('action', '')).lower()
                if act_name == 'msginfo.actionlist':
                    p_raw = att_dict.get('params')
                    p_data = None
                    if isinstance(p_raw, str) and p_raw.strip().startswith('{'):
                        try:
                            p_data = json.loads(p_raw)
                        except Exception:
                            pass
                    elif isinstance(p_raw, dict):
                        p_data = p_raw

                    if isinstance(p_data, dict):
                        actions = p_data.get('actions', [])
                        icon_url = str(p_data.get('iconUrl', '')).lower()
                        msg_field = p_data.get('msg', {})
                        vi_msg = str(msg_field.get('vi', '') if isinstance(msg_field, dict) else '').lower()
                        en_msg = str(msg_field.get('en', '') if isinstance(msg_field, dict) else '').lower()
                        title_str = str(att_dict.get('title', '')).lower()

                        for act in actions:
                            if isinstance(act, dict) and act.get('actionType') == 'action.open.grouptopic.detail':
                                a_data = act.get('actionData')
                                if isinstance(a_data, str) and a_data.strip().startswith('{'):
                                    try:
                                        a_data = json.loads(a_data)
                                    except Exception:
                                        a_data = {}
                                if isinstance(a_data, dict) and a_data.get('topicId'):
                                    try:
                                        topic_id = int(a_data['topicId'])
                                    except Exception:
                                        pass
                                break

                        if 'ic_unpin' in icon_url or 'bỏ ghim' in vi_msg or 'unpinned' in en_msg or 'bỏ ghim' in title_str:
                            ttype = 'group.unpin.topic'
                            if not msg_txt:
                                msg_txt = att_dict.get('title') or f"{from_d} đã bỏ ghim tin nhắn"
                        elif 'ic_pin' in icon_url or 'đã ghim' in vi_msg or 'pinned' in en_msg or 'đã ghim' in title_str:
                            ttype = 'group.update.topic'
                            if not msg_txt:
                                msg_txt = att_dict.get('title') or f"{from_d} đã ghim tin nhắn"

            if not msg_txt and isinstance(att_dict, dict):
                act_str = str(att_dict.get('action', '')).lower()
                att_title = str(att_dict.get('title') or '').strip()
                att_href = str(att_dict.get('href') or '').strip()
                if 'link' in act_str or ttype in ('chat.recommended', 'chat.link') or att_href:
                    if att_title:
                        msg_txt = att_title
                    elif att_href:
                        msg_txt = att_href

            if not msg_ts:
                msg_ts = 0

            messages.append({
                'cmd': cmd,
                'is_group': is_group,
                'is_self': is_self,
                'to_group': to_dest if is_group else None,
                'to_id': to_dest,
                'from_uid': from_u,
                'from_display': from_d,
                'from_name': from_d,
                'msg_id': msg_id,
                'cli_msg_id': cmi_id,
                'content': msg_txt,
                'text': msg_txt,
                'ttl': d.get('ttl', 0),
                'ts': int(msg_ts),
                'attach': att_dict if att_dict is not None else d.get('attach', ''),
                'mentions': mentions_data,
                'quote': quote_data,
                'styles': rtf_styles or d.get('styles') or item.get('styles') or txt_obj.get('styles'),
                'params': rtf_params or d.get('params') or item.get('params'),
                'type': ttype,
                'topic_id': topic_id,
                'raw': d,
                'raw_item': item
            })
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

def parse_incoming_reactions_1785(params_bytes: bytes, my_uid: Optional[int] = None) -> List[Dict[str, Any]]:
    idx = params_bytes.find(b'\x1f\x8b\x08')
    if idx == -1:
        idx = params_bytes.find(b'\x1f\x8b')
    if idx == -1:
        return []
    try:
        decomp = gzip.decompress(params_bytes[idx:])
        data = json.loads(decomp.decode('utf-8', errors='ignore'))
        msg_list = data.get('msg', [])
        if not isinstance(msg_list, list):
            msg_list = [msg_list] if msg_list else []
        results = []
        for m in msg_list:
            if not isinstance(m, dict):
                continue
            text_obj = m.get('text', {})
            t_data = text_obj.get('data', {}) if isinstance(text_obj, dict) else (m.get('data', {}) if isinstance(m.get('data'), dict) else {})
            from_u = t_data.get('fromU') or 0
            to_id = t_data.get('to') or 0
            attach = t_data.get('attach', {})
            p_str = attach.get('params', '{}') if isinstance(attach, dict) else '{}'
            p_obj = {}
            if isinstance(p_str, str) and p_str.startswith('{'):
                try:
                    p_obj = json.loads(p_str)
                except Exception:
                    p_obj = {}
            elif isinstance(p_str, dict):
                p_obj = p_str
            r_icon = p_obj.get('rIcon', '')
            r_msg = p_obj.get('rMsg', [])
            target_cmi = r_msg[0].get('cMsgID') if r_msg and isinstance(r_msg[0], dict) else 0
            target_gmi = r_msg[0].get('gMsgID') if r_msg and isinstance(r_msg[0], dict) else 0
            res_m = {
                'cmd': 1785,
                'is_group': bool(to_id and to_id != from_u),
                'is_self': bool(my_uid and from_u == my_uid),
                'to_group': to_id,
                'to_id': to_id,
                'from_uid': from_u,
                'from_display': t_data.get('fromD', '') or str(from_u),
                'from_name': t_data.get('fromD', '') or str(from_u),
                'msg_id': t_data.get('id', 0),
                'cli_msg_id': t_data.get('cliMsgId', 0),
                'content': f'[Reaction {r_icon}]' if r_icon else '[Reaction]',
                'text': f'[Reaction {r_icon}]' if r_icon else '[Reaction]',
                'type': 'chat.reaction',
                'r_icon': r_icon,
                'r_type': p_obj.get('rType'),
                'target_cli_msg_id': target_cmi,
                'target_global_msg_id': target_gmi,
                'ts': t_data.get('ts') or int(m.get('ts') or 0),
                'raw': t_data
            }
            results.append(res_m)
        return results
    except Exception as ex:
        logger.debug(f'parse_incoming_reactions_1785 error: {ex}')
        return []
