import json
import logging
import struct
import time
import zlib
from typing import Dict, Any, Optional

from core.socket.parser import parse_d3_compressed_json
from core.socket.events import MessageEvent, ReactionEvent

logger = logging.getLogger('core.socket.dispatcher')

ACK_CMDS = {
    1705, 1703, 1708, 1752, 113, 151, 207, 202, 228, 234, 235, 239, 242, 246,
    250, 225, 241, 244, 901, 902, 906, 2000, 1640, 382, 383
}

class PacketDispatcher:
    """
    Packet Dispatcher & Event Router (inspired by NBT Platform wss/packet.go & worker.Hub).
    Decouples packet parsing, ACK synchronization, group discovery, and typed event
    dispatching from the main network receive loop.
    """

    def __init__(self, client):
        self.client = client

    def dispatch(self, parsed: Dict[str, Any]):
        """Dispatches an unpacked incoming frame."""
        cmd = parsed.get('cmd')
        sub = parsed.get('sub')
        seq = parsed.get('seq')
        raw_params = parsed.get('raw_params', b'')
        parsed_data = parsed.get('parsed_data')

        if cmd in ACK_CMDS or (seq is not None and seq < 0):
            self._handle_ack_packet(cmd, sub, seq, raw_params, parsed)

        if cmd == 201 and len(raw_params) >= 4:
            try:
                pushed_gid = struct.unpack_from('<I', raw_params, 0)[0]
                if pushed_gid > 0:
                    gid_str = str(pushed_gid)
                    if gid_str not in self.client.known_groups:
                        self.client.known_groups[gid_str] = {'group_id': pushed_gid, 'ts': time.time()}
                        logger.debug(f'[CMD201] Discovered group_id={pushed_gid} from server push')
            except Exception:
                pass

        if hasattr(self.client, 'event_hub') and self.client.event_hub:
            self._publish_to_event_hub(parsed)

        if self.client.on_message_callback:
            try:
                self.client.on_message_callback(parsed)
            except Exception as cb_err:
                logger.error(f'Error in on_message_callback: {cb_err}')

    def _handle_ack_packet(self, cmd: int, sub: int, seq: Optional[int], raw_params: bytes, parsed: Dict[str, Any]):
        """Unpacks metadata, group info, topics, and profile info from ACK packets."""
        status = struct.unpack('<i', raw_params[:4])[0] if len(raw_params) >= 4 else 0
        ack_dict = {
            'cmd': cmd,
            'sub': sub,
            'seq': seq,
            'status_code': status,
            'raw_hex': raw_params[:8].hex() if raw_params else '',
            'raw_params': raw_params,
            'params_len': len(raw_params),
            'error_code': parsed.get('error_code') or 0
        }

        if cmd == 151:
            try:
                if len(raw_params) > 4:
                    d3_res = parse_d3_compressed_json(raw_params[4:], self.client.uid)
                    if not d3_res:
                        d3_res = parse_d3_compressed_json(raw_params, self.client.uid)
                    if d3_res:
                        ack_dict['json_data'] = d3_res
                        ack_dict['profile_json'] = d3_res
                        u_data = d3_res.get('data') if isinstance(d3_res.get('data'), dict) else d3_res
                        if isinstance(u_data, dict):
                            ack_dict['user_profile'] = u_data
                            ack_dict['user_id'] = u_data.get('uid') or u_data.get('userId')
                            ack_dict['display_name'] = u_data.get('dpn') or u_data.get('displayName')
                            ack_dict['avatar'] = u_data.get('avt') or u_data.get('avatar')
                            ack_dict['cover'] = u_data.get('cover')
                            ack_dict['status'] = u_data.get('stt')
                            ack_dict['global_id'] = u_data.get('globalId')
                            ack_dict['business_account'] = u_data.get('business_account')
                            for k in ('userId', 'uid', 'zaloId', 'displayName', 'zaloName', 'avatar', 'gender', 'dob', 'phoneNumber'):
                                if u_data.get(k) is not None and k not in ack_dict:
                                    ack_dict[k] = u_data[k]
            except Exception:
                pass

        if cmd in (901, 902):
            try:
                ack_dict['status_code'] = struct.unpack_from('<i', raw_params, 0)[0] if len(raw_params) >= 4 else 0
                if b'{' in raw_params:
                    j_idx = raw_params.find(b'{')
                    j_obj = json.loads(raw_params[j_idx:].decode('utf-8', errors='ignore'))
                    j_data = j_obj.get('data') or j_obj
                    j_gid = j_data.get('groupId') or j_data.get('grid') or j_data.get('id') or j_data.get('group_id')
                    if not j_gid and isinstance(j_data, dict) and isinstance(j_data.get('item'), dict):
                        j_gid = j_data['item'].get('gid')
                    if j_gid:
                        ack_dict['group_id'] = int(j_gid)

                for _i in range(len(raw_params) - 1):
                    if raw_params[_i:_i + 2] == b'\x1f\x8b':
                        try:
                            _dec = zlib.decompress(raw_params[_i:], 31)
                            _j = json.loads(_dec)
                            _d = _j.get('data') or _j
                            _gid = _d.get('groupId') or _d.get('grid') or _d.get('id')
                            if not _gid and isinstance(_d, dict) and isinstance(_d.get('item'), dict):
                                _gid = _d['item'].get('gid')
                            if _gid:
                                ack_dict['group_id'] = int(_gid)
                            ack_dict['json_data'] = _j
                            break
                        except Exception:
                            pass

                if cmd == 902 and ack_dict.get('status_code') == 0:
                    ack_dict['join_success'] = True
                    logger.debug(f"CMD 902 SUB {sub}: Joined group successfully! GID={ack_dict.get('group_id', '?')}")
            except Exception:
                pass

            if cmd == 902:
                with self.client.ack_lock:
                    self.client.cmd_ack_results[902] = ack_dict
                    if 902 in self.client.cmd_ack_events:
                        self.client.cmd_ack_events[902].set()
                    self.client.cmd_ack_results[901] = ack_dict
                    if 901 in self.client.cmd_ack_events:
                        self.client.cmd_ack_events[901].set()
                    self.client.general_ack_event.set()

        if cmd in (244, 901, 902):
            try:
                if len(raw_params) >= 8:
                    ack_dict['server_time'] = struct.unpack_from('<I', raw_params, 4)[0]
                if len(raw_params) > 4:
                    d3_res = parse_d3_compressed_json(raw_params[4:], self.client.uid)
                    if d3_res:
                        ack_dict['json_data'] = d3_res
                        if 'error_code' in d3_res:
                            ack_dict['group_error_code'] = d3_res['error_code']
                            try:
                                from core.models.enums import ZaloGroupErrorCode
                                ack_dict['group_error_msg'] = ZaloGroupErrorCode.get_message(d3_res['error_code'])
                            except Exception:
                                pass
                        if d3_res.get('group_id'):
                            ack_dict['group_id'] = int(d3_res['group_id'])
                        elif isinstance(d3_res.get('data'), dict) and isinstance(d3_res['data'].get('item'), dict) and d3_res['data']['item'].get('gid'):
                            ack_dict['group_id'] = int(d3_res['data']['item']['gid'])

                        item_data = d3_res.get('data', {}).get('item', {}) if isinstance(d3_res.get('data'), dict) else (d3_res.get('item', {}) if isinstance(d3_res.get('item'), dict) else {})
                        if isinstance(item_data, dict):
                            g_info = item_data.get('ginfo') or {}
                            if isinstance(g_info, dict):
                                ack_dict['ginfo'] = g_info
                                for k_f, t_f in (
                                    ('name', 'group_name'),
                                    ('creatorId', 'creator_id'),
                                    ('totalMembers', 'total_member'),
                                    ('desc', 'desc'),
                                    ('fullAvt', 'avatar'),
                                    ('avt', 'avatar'),
                                    ('currentMems', 'current_mems'),
                                    ('setting', 'setting'),
                                    ('admins', 'admins')
                                ):
                                    if g_info.get(k_f):
                                        ack_dict[t_f] = g_info[k_f]

                if b'{' in raw_params and (not ack_dict.get('group_id')):
                    j_idx = raw_params.find(b'{')
                    j_obj = json.loads(raw_params[j_idx:].decode('utf-8', errors='ignore'))
                    j_data = j_obj.get('data') or j_obj
                    j_gid = j_data.get('groupId') or j_data.get('grid') or j_data.get('id')
                    if not j_gid and isinstance(j_data, dict) and isinstance(j_data.get('item'), dict):
                        j_gid = j_data['item'].get('gid')
                    if j_gid:
                        ack_dict['group_id'] = int(j_gid)

                if ack_dict.get('group_id'):
                    gid_key = str(ack_dict['group_id'])
                    kg_entry = self.client.known_groups.get(gid_key, {})
                    kg_entry['group_id'] = ack_dict['group_id']
                    kg_entry['ts'] = time.time()
                    for k_field in ('group_name', 'creator_id', 'total_member', 'desc', 'avatar', 'current_mems', 'setting', 'admins', 'ginfo'):
                        if ack_dict.get(k_field):
                            kg_entry[k_field] = ack_dict[k_field]
                    self.client.known_groups[gid_key] = kg_entry
            except Exception:
                pass

        if cmd == 1703:
            try:
                topics_list = []
                if b'{' in raw_params:
                    j_idx = raw_params.find(b'{')
                    j_obj = json.loads(raw_params[j_idx:].decode('utf-8', errors='ignore'))
                    j_data = j_obj.get('data') or j_obj
                    topics_list = j_data.get('topics') or j_obj.get('topics') or []
                    if not topics_list and isinstance(j_data, list):
                        topics_list = j_data
                ack_dict['topics'] = topics_list
            except Exception:
                pass

        with self.client.ack_lock:
            self.client.cmd_ack_results[cmd] = ack_dict
            self.client.last_ack_result = ack_dict
            if cmd in self.client.cmd_ack_events:
                self.client.cmd_ack_events[cmd].set()
            self.client.general_ack_event.set()

    def _publish_to_event_hub(self, parsed: Dict[str, Any]):
        """Converts parsed data into typed events and publishes them to EventHub."""
        hub = self.client.event_hub
        hub.emit('frame', parsed)

        parsed_data = parsed.get('parsed_data')
        if not parsed_data or not isinstance(parsed_data, dict):
            return

        for m in parsed_data.get('messages', []):
            if m.get('type') == 'chat.reaction':
                r_evt = ReactionEvent.from_dict(m)
                hub.emit('reaction', r_evt)
            else:
                m_evt = MessageEvent.from_dict(m)
                hub.emit('message', m_evt)

        for r in parsed_data.get('reactions', []):
            r_evt = ReactionEvent.from_dict(r)
            hub.emit('reaction', r_evt)

        if parsed.get('cmd') == 202:
            hub.emit('delivery', parsed_data)
