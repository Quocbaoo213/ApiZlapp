import time
from typing import Optional, Dict, Any, Union, List
from core.models.enums import ThreadType
from core.models.message import Quote, Message

class MessageAPI:
    """
    Message API: Complete messaging factory for Zalo (inspired by zBug SendingFactory & Go plfz).
    Provides unified support for text, styled text, stickers, locations, files,
    business cards, photos, videos, reactions, message recall, and deletion.
    """

    def __init__(self, socket_client):
        self._socket = socket_client

    def _is_group_target(self, thread_type: Union[ThreadType, str, int]) -> bool:
        if isinstance(thread_type, ThreadType):
            return thread_type == ThreadType.GROUP
        s = str(thread_type).lower().strip()
        return s in ('group', 'threadtype.group', '2', '4')

    def send_message(
        self,
        target_id: Union[int, str, Dict[str, Any], Message] = 0,
        message: Union[str, Dict[str, Any], Message] = "",
        thread_type: Union[ThreadType, str, int] = ThreadType.GROUP,
        quote: Optional[Union[Quote, Dict[str, Any], bool]] = None,
        mention: Optional[Union[int, str, List[Union[int, str]], Dict[str, Any], List[Dict[str, Any]], bool]] = None,
        mentions: Optional[List[Dict[str, Any]]] = None,
        styles: Optional[List[Dict[str, Any]]] = None,
        ttl_seconds: int = 0,
        **kwargs
    ) -> bool:
        """
        Gửi tin nhắn đa năng chuẩn Go và Python (zBug SendingFactory / Go MessageObject).
        Hỗ trợ gọi theo cả 2 thứ tự tham số:
          - send_message(target_id, message, ...)
          - send_message(message, target_id, ...)
        Cho phép truyền text thuần, object Message, hoặc dict {text, quote, mention, styles}.
        Hỗ trợ truyền hoặc bỏ quote, mention tuỳ ý (quote=None/False, mention=None/False).
        """
        if not self._socket or not self._socket.is_connected:
            raise ConnectionError('Socket chưa được kết nối.')

        if isinstance(target_id, (Message, dict)):
            target_id, message = message, target_id
        elif isinstance(target_id, str) and not target_id.isdigit():
            if isinstance(message, (int, str)) and (isinstance(message, int) or str(message).isdigit()):
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
        elif isinstance(message, Message):
            text_val = str(message.text or "")
            if quote is None and message.quote:
                quote = message.quote
            if mentions is None and message.mentions:
                mentions = message.mentions
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
            if isinstance(quote, Quote):
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
                        'fromD': str(quote.get('from_name') or quote.get('from_uid') or ''),
                        'ts': int(quote.get('ts') or time.time() * 1000),
                        'msg': str(quote.get('content') or quote.get('text') or ''),
                        'ttl': int(quote.get('ttl') or 0)
                    }
                else:
                    q_dict = quote

        resolved_mentions = None
        if mentions is not None and isinstance(mentions, list):
            resolved_mentions = mentions
        elif mention is not None and mention is not False:
            resolved_mentions = []
            if isinstance(mention, (int, str)):
                m_uid = int(str(mention).strip())
                pos = 0
                m_len = len(text_val.split()[0]) if text_val.startswith('@') else len(text_val)
                resolved_mentions.append({'uid': m_uid, 'pos': pos, 'len': max(1, m_len), 'type': 0})
            elif isinstance(mention, list):
                for item in mention:
                    if isinstance(item, dict) and 'uid' in item:
                        resolved_mentions.append({
                            'uid': int(item['uid']),
                            'pos': int(item.get('pos', 0)),
                            'len': int(item.get('len', 1)),
                            'type': int(item.get('type', 0))
                        })
                    elif isinstance(item, (int, str)) and str(item).strip().isdigit():
                        resolved_mentions.append({
                            'uid': int(str(item).strip()),
                            'pos': 0,
                            'len': 1,
                            'type': 0
                        })

        ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
        t_id = int(target_id)
        is_grp = self._is_group_target(thread_type)

        if is_grp:
            return self._socket.send_group_message(
                group_id=t_id,
                text=text_val,
                ttl_ms=ttl_ms,
                quote_data=q_dict,
                mentions=resolved_mentions,
                styles=styles,
                **kwargs
            )
        else:
            return self._socket.send_1to1_message(
                target_uid=t_id,
                text=text_val,
                ttl_ms=ttl_ms,
                quote_data=q_dict,
                styles=styles,
                **kwargs
            )

    sendMessage = send_message
    send = send_message
    send_text = send_message
    sendText = send_message

    def reply_message(
        self,
        message: Union[str, Dict[str, Any], Message],
        reply_msg: Union[Quote, Dict[str, Any], Any],
        target_id: Union[int, str],
        thread_type: Union[ThreadType, str, int] = ThreadType.GROUP,
        ttl_seconds: int = 0,
        **kwargs
    ) -> bool:
        """Trả lời (Quote Reply) một tin nhắn cụ thể (chuẩn zBug / Go)."""
        return self.send_message(
            target_id=target_id,
            message=message,
            thread_type=thread_type,
            quote=reply_msg,
            ttl_seconds=ttl_seconds,
            **kwargs
        )

    replyMessage = reply_message

    def send_group(
        self,
        group_id: int,
        text: str,
        ttl_seconds: int = 0,
        quote: Optional[Union[Quote, Dict[str, Any]]] = None,
        styles: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> bool:
        if not self._socket or not self._socket.is_connected:
            raise ConnectionError('Socket chưa được kết nối.')
        ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
        q_dict = quote.to_dict() if isinstance(quote, Quote) else quote
        return self._socket.send_group_message(group_id=group_id, text=text, ttl_ms=ttl_ms, quote_data=q_dict, styles=styles, **kwargs)

    def send_1to1(
        self,
        target_uid: int,
        text: str,
        ttl_seconds: int = 0,
        quote: Optional[Union[Quote, Dict[str, Any]]] = None,
        styles: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> bool:
        if not self._socket or not self._socket.is_connected:
            raise ConnectionError('Socket chưa được kết nối.')
        ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
        q_dict = quote.to_dict() if isinstance(quote, Quote) else quote
        return self._socket.send_1to1_message(target_uid=target_uid, text=text, ttl_ms=ttl_ms, quote_data=q_dict, styles=styles, **kwargs)

    def send_styled(
        self,
        target_id: int,
        text: str,
        thread_type: Union[ThreadType, str] = ThreadType.USER,
        color: Optional[str] = None,
        bold: bool = False,
        italic: bool = False,
        underline: bool = False,
        strike: bool = False,
        fontsize: Optional[int] = None,
        style_id: Optional[int] = None,
        ttl_seconds: int = 0,
        quote: Optional[Union[Quote, Dict[str, Any]]] = None,
        styles: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> bool:
        if not self._socket or not self._socket.is_connected:
            raise ConnectionError('Socket chưa được kết nối.')
        ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
        q_dict = quote.to_dict() if isinstance(quote, Quote) else quote
        is_grp = self._is_group_target(thread_type)
        if is_grp:
            return self._socket.send_group_message(
                group_id=target_id,
                text=text,
                ttl_ms=ttl_ms,
                quote_data=q_dict,
                style_id=style_id,
                color=color,
                bold=bold,
                italic=italic,
                underline=underline,
                strike=strike,
                fontsize=fontsize,
                styles=styles,
                **kwargs
            )
        else:
            return self._socket.send_1to1_message(
                target_uid=target_id,
                text=text,
                ttl_ms=ttl_ms,
                quote_data=q_dict,
                style_id=style_id,
                color=color,
                bold=bold,
                italic=italic,
                underline=underline,
                strike=strike,
                fontsize=fontsize,
                styles=styles,
                **kwargs
            )

    sendStyled = send_styled

    def send_typing(self, target_id: int, is_group: bool = True) -> bool:
        if not self._socket:
            return False
        return self._socket.send_typing(target_id=target_id, is_group=is_group)

    sendTyping = send_typing

    def send_sticker(
        self,
        target_id: int,
        cat_id: Union[int, str],
        sticker_id: Union[int, str],
        thread_type: Union[ThreadType, str] = ThreadType.GROUP,
        sticker_type: int = 7,
        ttl_seconds: int = 0,
        quote: Optional[Union[Quote, Dict[str, Any]]] = None,
        **kwargs
    ) -> bool:
        if not self._socket or not self._socket.is_connected:
            raise ConnectionError('Socket chưa được kết nối.')
        ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
        q_dict = quote.to_dict() if isinstance(quote, Quote) else quote
        is_grp = self._is_group_target(thread_type)
        return self._socket.send_sticker(
            target_id=target_id,
            cat_id=cat_id,
            sticker_id=sticker_id,
            is_group=is_grp,
            sticker_type=sticker_type,
            ttl_ms=ttl_ms,
            quote_data=q_dict,
            **kwargs
        )

    def send_group_sticker(
        self,
        group_id: int,
        cat_id: Union[int, str],
        sticker_id: Union[int, str],
        sticker_type: int = 7,
        ttl_seconds: int = 0,
        quote: Optional[Union[Quote, Dict[str, Any]]] = None,
        **kwargs
    ) -> bool:
        return self.send_sticker(
            target_id=group_id,
            cat_id=cat_id,
            sticker_id=sticker_id,
            thread_type=ThreadType.GROUP,
            sticker_type=sticker_type,
            ttl_seconds=ttl_seconds,
            quote=quote,
            **kwargs
        )

    def send_1to1_sticker(
        self,
        user_id: int,
        cat_id: Union[int, str],
        sticker_id: Union[int, str],
        sticker_type: int = 7,
        ttl_seconds: int = 0,
        quote: Optional[Union[Quote, Dict[str, Any]]] = None,
        **kwargs
    ) -> bool:
        return self.send_sticker(
            target_id=user_id,
            cat_id=cat_id,
            sticker_id=sticker_id,
            thread_type=ThreadType.USER,
            sticker_type=sticker_type,
            ttl_seconds=ttl_seconds,
            quote=quote,
            **kwargs
        )

    sendSticker = send_sticker

    def send_location(
        self,
        target_id: int,
        lat: Union[float, int, str],
        lon: Union[float, int, str],
        address: str = '',
        place_id: str = '',
        thread_type: Union[ThreadType, str] = ThreadType.GROUP,
        ttl_seconds: int = 0,
        quote: Optional[Union[Quote, Dict[str, Any]]] = None,
        **kwargs
    ) -> bool:
        if not self._socket or not self._socket.is_connected:
            raise ConnectionError('Socket chưa được kết nối.')
        ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
        q_dict = quote.to_dict() if isinstance(quote, Quote) else quote
        is_grp = self._is_group_target(thread_type)
        return self._socket.send_location(
            target_id=target_id,
            lat=lat,
            lon=lon,
            address=address,
            place_id=place_id,
            is_group=is_grp,
            ttl_ms=ttl_ms,
            quote_data=q_dict,
            **kwargs
        )

    sendLocation = send_location

    def send_file(
        self,
        target_id: int,
        file_url: str,
        file_name: str,
        file_size: Union[int, str] = 0,
        checksum: str = '',
        file_ext: str = '',
        thread_type: Union[ThreadType, str] = ThreadType.GROUP,
        ttl_seconds: int = 0,
        quote: Optional[Union[Quote, Dict[str, Any]]] = None,
        **kwargs
    ) -> bool:
        if not self._socket or not self._socket.is_connected:
            raise ConnectionError('Socket chưa được kết nối.')
        ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
        q_dict = quote.to_dict() if isinstance(quote, Quote) else quote
        is_grp = self._is_group_target(thread_type)
        return self._socket.send_file(
            target_id=target_id,
            file_url=file_url,
            file_name=file_name,
            file_size=file_size,
            checksum=checksum,
            file_ext=file_ext,
            is_group=is_grp,
            ttl_ms=ttl_ms,
            quote_data=q_dict,
            **kwargs
        )

    sendFile = send_file

    def send_contact(
        self,
        target_id: int,
        contact_uid: Union[int, str],
        contact_name: str = '',
        avatar_url: str = '',
        qr_code_url: str = '',
        thread_type: Union[ThreadType, str] = ThreadType.GROUP,
        ttl_seconds: int = 0,
        quote: Optional[Union[Quote, Dict[str, Any]]] = None,
        **kwargs
    ) -> bool:
        if not self._socket or not self._socket.is_connected:
            raise ConnectionError('Socket chưa được kết nối.')
        ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
        q_dict = quote.to_dict() if isinstance(quote, Quote) else quote
        is_grp = self._is_group_target(thread_type)
        return self._socket.send_contact(
            target_id=target_id,
            contact_uid=contact_uid,
            contact_name=contact_name,
            avatar_url=avatar_url,
            qr_code_url=qr_code_url,
            is_group=is_grp,
            ttl_ms=ttl_ms,
            quote_data=q_dict,
            **kwargs
        )

    sendContact = send_contact
    send_business_card = send_contact
    sendBusinessCard = send_contact

    def send_photo(
        self,
        target_id: int,
        photo_url: str,
        thread_type: Union[ThreadType, str] = ThreadType.GROUP,
        caption: str = '',
        title: Optional[str] = None,
        description: Optional[str] = None,
        width: int = 0,
        height: int = 0,
        total_size: int = 0,
        thumb_url: Optional[str] = None,
        hd_url: Optional[str] = None,
        ttl_seconds: int = 0,
        quote: Optional[Union[Quote, Dict[str, Any]]] = None,
        is_original: bool = False,
        **kwargs
    ) -> bool:
        if not self._socket or not self._socket.is_connected:
            raise ConnectionError('Socket chưa được kết nối.')
        ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
        q_dict = quote.to_dict() if isinstance(quote, Quote) else quote
        is_grp = self._is_group_target(thread_type)
        return self._socket.send_photo(
            target_id=target_id,
            photo_url_or_path=photo_url,
            is_group=is_grp,
            caption=caption,
            title=title,
            description=description,
            width=width,
            height=height,
            total_size=total_size,
            thumb_url=thumb_url,
            hd_url=hd_url,
            ttl_ms=ttl_ms,
            quote_data=q_dict,
            is_original=is_original,
            **kwargs
        )

    sendPhoto = send_photo
    send_image = send_photo
    sendImage = send_photo

    def send_video(
        self,
        target_id: int,
        video_url: str,
        thread_type: Union[ThreadType, str] = ThreadType.GROUP,
        caption: str = '',
        title: Optional[str] = None,
        description: Optional[str] = None,
        thumb_url: Optional[str] = None,
        width: int = 1280,
        height: int = 720,
        duration_ms: int = 0,
        total_size: int = 0,
        ttl_seconds: int = 0,
        quote: Optional[Union[Quote, Dict[str, Any]]] = None,
        **kwargs
    ) -> bool:
        if not self._socket or not self._socket.is_connected:
            raise ConnectionError('Socket chưa được kết nối.')
        ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
        q_dict = quote.to_dict() if isinstance(quote, Quote) else quote
        is_grp = self._is_group_target(thread_type)
        return self._socket.send_video(
            target_id=target_id,
            video_url=video_url,
            is_group=is_grp,
            caption=caption,
            title=title,
            description=description,
            thumb_url=thumb_url,
            width=width,
            height=height,
            duration_ms=duration_ms,
            total_size=total_size,
            ttl_ms=ttl_ms,
            quote_data=q_dict,
            **kwargs
        )

    sendVideo = send_video

    def send_reaction(
        self,
        target_id: int,
        cli_msg_id: Union[int, str],
        global_msg_id: Union[int, str] = 0,
        icon: str = '❤️',
        thread_type: Union[ThreadType, str] = ThreadType.GROUP,
        **kwargs
    ) -> bool:
        if not self._socket or not self._socket.is_connected:
            raise ConnectionError('Socket chưa được kết nối.')
        is_grp = self._is_group_target(thread_type)
        return self._socket.send_reaction(
            target_id=int(target_id),
            cli_msg_id=int(cli_msg_id),
            global_msg_id=int(global_msg_id or 0),
            icon=icon,
            is_group=is_grp
        )

    sendReaction = send_reaction

    def recall_message(
        self,
        target_id: int,
        cli_msg_id: Union[int, str],
        global_msg_id: Union[int, str] = 0,
        msg_type: int = 1,
        thread_type: Union[ThreadType, str] = ThreadType.GROUP,
        **kwargs
    ) -> bool:
        if not self._socket or not self._socket.is_connected:
            raise ConnectionError('Socket chưa được kết nối.')
        is_grp = self._is_group_target(thread_type)
        return self._socket.recall_message(
            target_id=int(target_id),
            cli_msg_id=cli_msg_id,
            global_msg_id=global_msg_id,
            msg_type=msg_type,
            is_group=is_grp,
            **kwargs
        )

    recallMessage = recall_message
    undo_message = recall_message
    undoMessage = recall_message

    def delete_message(
        self,
        target_id: int,
        cli_msg_id: Union[int, str],
        global_msg_id: Union[int, str] = '',
        only_me: bool = False,
        thread_type: Union[ThreadType, str] = ThreadType.GROUP,
        **kwargs
    ) -> bool:
        if not self._socket or not self._socket.is_connected:
            raise ConnectionError('Socket chưa được kết nối.')
        is_grp = self._is_group_target(thread_type)
        return self._socket.delete_message(
            group_id=int(target_id),
            cli_msg_id=cli_msg_id,
            global_msg_id=global_msg_id,
            is_group=is_grp,
            only_me=only_me,
            **kwargs
        )

    deleteMessage = delete_message
