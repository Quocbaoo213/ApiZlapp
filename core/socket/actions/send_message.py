import logging
import struct
import time
from typing import Optional, Union, Dict, Any, List
from core.socket.protocol import CMD_GROUP_MSG, SUB_GROUP_MSG, CMD_1TO1_MSG, SUB_1TO1_MSG, compute_checksum, build_group_message_packet, build_1to1_message_packet, build_outer_frame
logger = logging.getLogger('core.socket.actions.send_message')

class SendMessageActionMixin:

    def send_group_message(
        self,
        group_id: int,
        text: str,
        ttl_ms: int = 0,
        ttl: Optional[int] = None,
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
        attach: Optional[Union[dict, str]] = None,
        styles: Optional[List[Dict[str, Any]]] = None
    ) -> bool:
        if ttl is not None and ttl_ms == 0:
            ttl_ms = ttl * 1000 if ttl < 100000 else ttl
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(CMD_GROUP_MSG, SUB_GROUP_MSG, seq, self.uid, target=int(group_id), target_type=4, cmsg=cmsg, bb=1, ty=2, ver=3)
            inner = build_group_message_packet(
                uid=self.uid,
                group_id=int(group_id),
                text=text,
                seq=seq,
                ck_val=ck,
                cmsg_id=cmsg,
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
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            return True
        except Exception as e:
            logger.error(f'Lỗi gửi group message: {e}')
            return False

    def send_1to1_message(
        self,
        target_uid: int,
        text: str,
        ttl_ms: int = 0,
        ttl: Optional[int] = None,
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
        attach: Optional[Union[dict, str]] = None,
        styles: Optional[List[Dict[str, Any]]] = None
    ) -> bool:
        if ttl is not None and ttl_ms == 0:
            ttl_ms = ttl * 1000 if ttl < 100000 else ttl
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(CMD_1TO1_MSG, SUB_1TO1_MSG, seq, self.uid, target=int(target_uid), target_type=3, cmsg=cmsg, bb=1, ty=2, ver=3)
            inner = build_1to1_message_packet(
                uid=self.uid,
                target_uid=int(target_uid),
                text=text,
                cryptkey=self.cryptkey,
                seq=seq,
                ck_val=ck,
                cmsg_id=cmsg,
                ttl_ms=ttl_ms,
                quote_data=quote_data,
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
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            return True
        except Exception as e:
            logger.error(f'Lỗi gửi 1-1 message: {e}')
            return False

    def set_conversation_ttl(self, target_id: int, ttl_seconds: int, is_group: bool=True) -> bool:
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            ck = compute_checksum(2060, 0, seq, self.uid, target=0, target_type=0, cmsg=0, bb=1, ty=0, ver=3)
            target_type_byte = 2 if is_group else 1
            params = bytes([1]) + struct.pack('<I', 0) + struct.pack('<H', 0) + struct.pack('<I', 1) + bytes([target_type_byte]) + struct.pack('<I', int(target_id)) + struct.pack('<Q', int(ttl_seconds))
            inner = struct.pack('<IBBiIBHB', ck, 1, 0, seq, self.uid, 3, 2060, 0) + params
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            return True
        except Exception as e:
            logger.error(f'Lỗi cài đặt TTL: {e}')
            return False

    def send_message(
        self,
        target_id: Union[int, str, Dict[str, Any], Any] = 0,
        message: Union[str, Dict[str, Any], Any] = "",
        thread_type: Union[str, int, Any] = "group",
        quote: Optional[Union[Dict[str, Any], Any, bool]] = None,
        mention: Optional[Union[int, str, List[Union[int, str]], Dict[str, Any], List[Dict[str, Any]], bool]] = None,
        mentions: Optional[List[Dict[str, Any]]] = None,
        styles: Optional[List[Dict[str, Any]]] = None,
        ttl_seconds: int = 0,
        ttl_ms: int = 0,
        is_group: Optional[bool] = None,
        **kwargs
    ) -> bool:
        if isinstance(target_id, dict) or (hasattr(target_id, 'text') and not isinstance(target_id, (int, float))):
            target_id, message = message, target_id
        elif isinstance(target_id, str) and not target_id.isdigit():
            if isinstance(message, int) or (isinstance(message, str) and message.isdigit()):
                target_id, message = message, target_id

        text_val = ""
        if isinstance(message, dict):
            text_val = str(message.get('text') or message.get('msg') or message.get('content') or '')
            if quote is None and 'quote' in message:
                quote = message['quote']
            if mention is None and 'mention' in message:
                mention = message['mention']
            if mentions is None and 'mentions' in message:
                mentions = message['mentions']
            if styles is None and 'styles' in message:
                styles = message['styles']
            if ttl_seconds == 0 and 'ttl' in message:
                ttl_seconds = int(message['ttl'])
        elif hasattr(message, 'text'):
            text_val = str(getattr(message, 'text', '') or '')
            if quote is None and hasattr(message, 'quote'):
                quote = getattr(message, 'quote', None)
            if mentions is None and hasattr(message, 'mentions'):
                mentions = getattr(message, 'mentions', None)
            if styles is None and hasattr(message, 'styles'):
                styles = getattr(message, 'styles', None)
        else:
            text_val = str(message if message is not None else kwargs.pop('text', ''))

        if not text_val and 'text' in kwargs:
            text_val = str(kwargs.pop('text'))

        if quote is None and 'quote_data' in kwargs:
            quote = kwargs.pop('quote_data')
        if quote is None and 'reply' in kwargs:
            quote = kwargs.pop('reply')
        if mention is None and 'mention' in kwargs:
            mention = kwargs.pop('mention')

        q_dict = None
        if quote is not None and quote is not False:
            if hasattr(quote, 'to_dict'):
                q_dict = quote.to_dict()
            elif isinstance(quote, dict):
                if 'ownerId' in quote or 'cliMsgId' in quote:
                    q_dict = quote
                elif 'from_uid' in quote:
                    q_dict = {
                        'cliMsgType': 1,
                        'cliMsgId': int(quote.get('cli_msg_id') or time.time() * 1000),
                        'globalMsgId': int(quote.get('msg_id') or 0),
                        'ownerId': int(quote.get('from_uid') or 0),
                        'fromD': str(quote.get('from_display') or quote.get('from_name') or quote.get('from_uid') or ''),
                        'ts': int(quote.get('ts') or time.time() * 1000),
                        'msg': str(quote.get('content') or quote.get('text') or ''),
                        'ttl': int(quote.get('ttl') or 0)
                    }
                else:
                    q_dict = quote

        resolved_mentions = None
        if mentions is not None and isinstance(mentions, list) and mentions is not False:
            resolved_mentions = mentions
        elif mention is not None and mention is not False:
            resolved_mentions = []
            if isinstance(mention, (int, str)):
                m_uid = int(str(mention).strip())
                m_len = len(text_val.split()[0]) if text_val.startswith('@') else len(text_val)
                resolved_mentions.append({'uid': m_uid, 'pos': 0, 'len': max(1, m_len), 'type': 0})
            elif isinstance(mention, list):
                for item in mention:
                    if isinstance(item, dict) and 'uid' in item:
                        resolved_mentions.append({
                            'uid': int(item['uid']),
                            'pos': int(item.get('pos', 0)),
                            'len': int(item.get('len', 1)),
                            'type': int(item.get('type', 0))
                        })
                    elif isinstance(item, (int, str)):
                        resolved_mentions.append({
                            'uid': int(str(item).strip()),
                            'pos': 0,
                            'len': len(text_val),
                            'type': 0
                        })

        ttl_use = ttl_ms if ttl_ms > 0 else (ttl_seconds * 1000 if ttl_seconds > 0 else 0)

        group_target = is_group if is_group is not None else (str(thread_type).lower() in ('group', 'threadtype.group', '2', '4', 'true', '1'))

        if group_target:
            return self.send_group_message(
                int(target_id),
                text_val,
                ttl_ms=ttl_use,
                quote_data=q_dict,
                mentions=resolved_mentions,
                styles=styles,
                **kwargs
            )
        else:
            return self.send_1to1_message(
                int(target_id),
                text_val,
                ttl_ms=ttl_use,
                quote_data=q_dict,
                styles=styles,
                **kwargs
            )

    sendMessage = send_message
