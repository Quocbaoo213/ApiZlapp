import os
import json
import base64
import logging
import time
from typing import Optional, Callable, Dict, Any, List, Union
from core.socket.client import ZaloSocketClient, DEFAULT_SERVERS
from core.models.enums import ThreadType, ReactionIcon
from core.models.user import UserProfile
from core.models.message import Message, Quote
from core.api.handle.api import SendAPI
from core.api.group.api import GroupAPI
from core.api.group.action.api import GroupActionAPI
from core.api.group.message.api import GroupMessageAPI
from core.api.group.info import GroupInfoAPI
from core.api.properties.api import PropertiesAPI
from core.api.user import UserAPI
from core.api.message import MessageAPI
logger = logging.getLogger('core.client')

class ZaloClient:

    def __init__(self, session: Optional[Union[str, Dict[str, Any]]]=None, session_path: Optional[str]=None, frame0_path: Optional[str]=None, debug: bool=False):
        self.session_source = session if session is not None else session_path
        self.session_path = self.session_source if isinstance(self.session_source, str) else None
        self.frame0_path = frame0_path
        self.debug = debug
        self.session_data: Dict[str, Any] = {}
        self.uid: int = 0
        self._load_session_data()
        self._message_handlers: List[Callable[[Message], None]] = []
        self._socket: Optional[ZaloSocketClient] = None
        self._init_socket_client()
        active_session_arg = self.session_data if self.session_data else self.session_source
        self.send = SendAPI(session_path=active_session_arg, socket_client=self._socket)
        self.group = GroupAPI(session_path=active_session_arg, socket_client=self._socket)
        self.group_action = GroupActionAPI(session_path=active_session_arg, socket_client=self._socket)
        self.group_message = GroupMessageAPI(session_path=active_session_arg, socket_client=self._socket)
        self.group_info = GroupInfoAPI(session_path=active_session_arg, socket_client=self._socket)
        self.properties = PropertiesAPI(session_path=active_session_arg, socket_client=self._socket)
        self.users = UserAPI(session_path=active_session_arg, socket_client=self._socket)
        self.user = self.users
        self.messages = MessageAPI(self._socket)
        self.groups = self.group

    @property
    def socket(self) -> Optional[ZaloSocketClient]:
        return self._socket

    @socket.setter
    def socket(self, sock: Optional[ZaloSocketClient]):
        self._socket = sock
        for attr in ('send', 'group', 'group_action', 'group_message', 'group_info', 'properties', 'messages', 'groups', 'users', 'user'):
            if hasattr(self, attr):
                obj = getattr(self, attr)
                if obj and hasattr(obj, '_socket'):
                    obj._socket = sock

    def _load_session_data(self):
        if isinstance(self.session_source, dict):
            data = self.session_source
        else:
            resolved_path = None
            search_paths = []
            if isinstance(self.session_source, str) and self.session_source:
                search_paths.append(self.session_source)
            search_paths.extend([os.path.join(os.getcwd(), 'fresh_session.json'), 'fresh_session.json', os.path.expanduser('~/.zalo/fresh_session.json'), '/root/zalo/fresh_session.json', '/sdcard/Download/Zalo/zm/fresh_session.json', '/sdcard/Download/Zalo/active_session.json'])
            for p in search_paths:
                if p and os.path.isfile(p):
                    resolved_path = p
                    break
            if not resolved_path:
                raise FileNotFoundError(f'Không tìm thấy file session. Hãy chỉ định đường dẫn hoặc đăng nhập qua `python -m core.login`')
            self.session_path = resolved_path
            with open(resolved_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        self.session_data = data
        self.uid = int(data.get('uid') or (data.get('data') or {}).get('userId') or 0)
        dk_hex = data.get('dk_hex')
        dk_b64 = data.get('dk_b64')
        self.dk = bytes.fromhex(dk_hex) if dk_hex else base64.b64decode(dk_b64) if dk_b64 else None
        cryptkey_b64 = data.get('cryptkey')
        self.cryptkey = base64.b64decode(cryptkey_b64) if cryptkey_b64 else None
        self.session_key = data.get('session_key')
        self.ksid = data.get('ksid')
        self.servers = data.get('socketServers') or data.get('servers') or DEFAULT_SERVERS

    def _init_socket_client(self):
        self._socket = ZaloSocketClient(uid=self.uid, dk=self.dk, session_key=self.session_key, ksid=self.ksid, cryptkey=self.cryptkey, frame0_path=self.frame0_path, server_pool=self.servers, on_message_callback=self._on_raw_socket_frame, debug=self.debug)

    def _update_services_socket(self):
        if hasattr(self, 'send'):
            self.send.set_socket_client(self._socket)
        if hasattr(self, 'group'):
            self.group.set_socket_client(self._socket)
        if hasattr(self, 'group_action'):
            self.group_action.set_socket_client(self._socket)
        if hasattr(self, 'group_message'):
            self.group_message.set_socket_client(self._socket)
        if hasattr(self, 'group_info'):
            self.group_info.set_socket_client(self._socket)
        if hasattr(self, 'properties'):
            self.properties.set_socket_client(self._socket)
        if hasattr(self, 'messages'):
            self.messages._socket = self._socket

    def _on_raw_socket_frame(self, parsed_frame: Dict[str, Any]):
        cmd = parsed_frame.get('cmd')
        parsed_data = parsed_frame.get('parsed_data')
        if cmd in (101, 201, 1865, 1867) and parsed_data:
            messages = parsed_data.get('messages', [])
            for m in messages:
                from_u = m.get('from_uid')
                if not from_u or from_u == self.uid:
                    continue
                to_g = m.get('to_group')
                from_d = m.get('from_display') or m.get('from_name') or str(from_u)
                content = m.get('content', '') or m.get('text', '')
                self.users.register_seen_user(from_u, display_name=from_d)
                msg_obj = Message(text=content, from_uid=int(from_u), from_name=from_d, group_id=int(to_g) if to_g else None, is_group=bool(to_g), msg_id=int(m.get('msg_id') or 0), cli_msg_id=int(m.get('cli_msg_id') or 0), timestamp=int(m.get('ts') or time.time() * 1000), mentions=m.get('mentions') or [], quote=m.get('quote'), raw=m)
                for handler in self._message_handlers:
                    try:
                        handler(msg_obj)
                    except Exception as ex:
                        logger.error(f'Lỗi trong message handler: {ex}')

    def connect(self) -> bool:
        if not self._socket:
            self._init_socket_client()
        self._update_services_socket()
        return self._socket.connect()

    def add_message_listener(self, handler: Callable[[Message], None]):
        self._message_handlers.append(handler)

    def send_message(self, target_id: Union[int, str, Any] = 0, text: Union[str, Any] = "", thread_type: ThreadType = ThreadType.GROUP, ttl_seconds: int = 0, quote: Optional[Union[Quote, Dict[str, Any], bool]] = None, **kwargs) -> bool:
        q_dict = quote.to_dict() if hasattr(quote, 'to_dict') else (quote if isinstance(quote, dict) else None)
        return self.send.send_message(thread_id=target_id, text=text, thread_type=thread_type, ttl=ttl_seconds, quote_data=q_dict, **kwargs)

    sendMessage = send_message

    def send_group_message(self, group_id: int, text: str, ttl_seconds: int=0, quote: Optional[Quote | Dict[str, Any]]=None) -> bool:
        return self.send_message(group_id, text, thread_type=ThreadType.GROUP, ttl_seconds=ttl_seconds, quote=quote)

    def send_1to1_message(self, user_id: int, text: str, ttl_seconds: int=0, quote: Optional[Quote | Dict[str, Any]]=None) -> bool:
        return self.send_message(user_id, text, thread_type=ThreadType.USER, ttl_seconds=ttl_seconds, quote=quote)

    def send_sticker(self, target_id: int, cat_id: Union[int, str], sticker_id: Union[int, str], thread_type: ThreadType=ThreadType.GROUP, sticker_type: int=7, ttl_seconds: int=0, quote: Optional[Quote | Dict[str, Any]]=None, **kwargs) -> bool:
        if self._socket and self._socket.is_connected:
            is_grp = thread_type == ThreadType.GROUP
            ttl_ms = ttl_seconds * 1000 if ttl_seconds > 0 else 0
            q_dict = quote.to_dict() if isinstance(quote, Quote) else quote
            return self._socket.send_sticker(target_id=target_id, cat_id=cat_id, sticker_id=sticker_id, is_group=is_grp, sticker_type=sticker_type, ttl_ms=ttl_ms, quote_data=q_dict, **kwargs)
        return False

    def send_group_sticker(self, group_id: int, cat_id: Union[int, str], sticker_id: Union[int, str], sticker_type: int=7, ttl_seconds: int=0, quote: Optional[Quote | Dict[str, Any]]=None, **kwargs) -> bool:
        return self.send_sticker(target_id=group_id, cat_id=cat_id, sticker_id=sticker_id, thread_type=ThreadType.GROUP, sticker_type=sticker_type, ttl_seconds=ttl_seconds, quote=quote, **kwargs)

    def send_1to1_sticker(self, user_id: int, cat_id: Union[int, str], sticker_id: Union[int, str], sticker_type: int=7, ttl_seconds: int=0, quote: Optional[Quote | Dict[str, Any]]=None, **kwargs) -> bool:
        return self.send_sticker(target_id=user_id, cat_id=cat_id, sticker_id=sticker_id, thread_type=ThreadType.USER, sticker_type=sticker_type, ttl_seconds=ttl_seconds, quote=quote, **kwargs)

    sendSticker = send_sticker

    def send_typing(self, target_id: int, is_group: bool=True) -> bool:
        return self.send.send_typing(target_id=target_id, is_group=is_group)

    def send_reaction(self, target_id: int, cli_msg_id: int, global_msg_id: int=0, icon: ReactionIcon | str=ReactionIcon.HEART, is_group: bool=True) -> bool:
        return self.send.send_reaction(target_id=target_id, cli_msg_id=cli_msg_id, global_msg_id=global_msg_id, icon=icon.value if isinstance(icon, ReactionIcon) else str(icon), is_group=is_group)

    def pin_message(self, group_id: int, title: str='', cli_msg_id: int=0, global_msg_id: int=0, sender_name: str='Member', sender_uid: int=0) -> bool:
        return self.group_message.pin_message(group_id=group_id, title=title, cli_msg_id=cli_msg_id, global_msg_id=global_msg_id, sender_name=sender_name, sender_uid=sender_uid)

    def unpin_message(self, group_id: int, topic_id: int=0, global_msg_id: int=0, cli_msg_id: int=0, **kwargs) -> bool:
        return self.group_message.unpin_message(group_id=group_id, topic_id=topic_id, global_msg_id=global_msg_id, cli_msg_id=cli_msg_id, **kwargs)

    def remove_member(self, group_id: int, member_uids: Union[int, List[int]]) -> bool:
        return self._socket.remove_member(group_id=int(group_id), member_uids=member_uids) if self._socket else False

    def kick_member(self, group_id: int, member_uids: Union[int, List[int]], is_block: bool=False) -> bool:
        return self.group_action.kick_member(group_id=group_id, member_uids=member_uids, is_block=is_block)

    def block_group_member(self, group_id: int, member_uids: Union[int, List[int]]) -> bool:
        return self.group_action.block_group_member(group_id=group_id, member_uids=member_uids)

    def block_user(self, target_uid: int, is_block: bool=True) -> bool:
        return self.send.block_user(target_uid=target_uid, is_block=is_block)

    def unblock_user(self, target_uid: int) -> bool:
        return self.send.unblock_user(target_uid=target_uid)

    def leave_group(self, group_id: int, new_owner_id: int=0, silent: bool=False, block_readd: bool=False, wait_response: bool=False, timeout: float=8.0):
        if wait_response and self._socket:
            return self._socket.leave_group(group_id=int(group_id), new_owner_id=new_owner_id, silent=silent, block_readd=block_readd, wait_response=True, timeout=timeout)
        return self.group_action.leave_group(group_id=group_id, new_owner_id=new_owner_id, silent=silent, block_readd=block_readd)

    def delete_message(self, group_id: int, cli_msg_id: Union[int, str], global_msg_id: Union[int, str]='', owner_id: Optional[Union[int, str]]=None, is_group: bool=True, only_me: bool=False) -> bool:
        return self.send.delete_message(group_id=group_id, cli_msg_id=cli_msg_id, global_msg_id=global_msg_id, owner_id=owner_id, is_group=is_group, only_me=only_me)

    def recall_message(self, group_id: int, cli_msg_id: Union[int, str], global_msg_id: Union[int, str]=0, owner_id: Optional[Union[int, str]]=None, is_group: bool=True) -> bool:
        return self.send.recall_message(group_id=group_id, cli_msg_id=cli_msg_id, global_msg_id=global_msg_id, owner_id=owner_id, is_group=is_group)

    def disband_group(self, group_id: int) -> bool:
        return self.group_action.disband_group(group_id=group_id)

    def add_member(self, group_id: int, member_uids: Union[int, List[int]], is_invite: bool=False) -> bool:
        return self.group_action.add_member(group_id=group_id, member_uids=member_uids, is_invite=is_invite)

    def join_group(self, target: Union[int, str], msg: str='') -> Dict[str, Any]:
        return self.group_action.join_group(target=target, msg=msg)

    def preview_group_link(self, link_or_code: str) -> Dict[str, Any]:
        return self.group_info.preview_group_link(link_or_code=link_or_code)

    def resolve_group_id_from_link(self, link_or_code: str) -> Optional[int]:
        return self.group_info.resolve_group_id_from_link(link_or_code=link_or_code)

    def get_group_list(self, page: int=1, last_group_id: Union[int, str]=0, avatar_size: int=160) -> Optional[Dict[str, Any]]:
        return self.group_info.get_group_list(page=page, last_group_id=last_group_id, avatar_size=avatar_size)

    def get_all_groups(self, force_refresh: bool=False) -> List[Dict[str, Any]]:
        return self.group_info.get_all_groups(force_refresh=force_refresh)

    def get_group_detail(self, group_id: Union[int, str], force_refresh: bool=False) -> Optional[Dict[str, Any]]:
        return self.group_info.get_group_detail(group_id=group_id, force_refresh=force_refresh)

    def get_user_profile(self, user_id: Union[int, str], force_refresh: bool=False) -> Optional[UserProfile]:
        return self.users.get_user_profile(target_uid=user_id, force_refresh=force_refresh)

    def get_friends(self, force_refresh: bool=False) -> List[UserProfile]:
        return self.users.get_all_friends(force_refresh=force_refresh)

    def get_friend_list(self, page: int=1, count: int=50) -> Optional[Dict[str, Any]]:
        return self.users.get_friend_list(page=page, count=count)

    def remove_friend(self, user_id: Union[int, str]) -> Optional[Dict[str, Any]]:
        return self.users.remove_friend(user_id=user_id)

    def find_user_by_phone(self, phone: str) -> Optional[Dict[str, Any]]:
        return self.users.find_user_by_phone(phone=phone)

    def discover_contacts(self, phones: List[str]) -> Optional[Dict[str, Any]]:
        return self.users.discover_contacts(phones=phones)

    def send_friend_request(self, user_id: Union[int, str], message: str='') -> Optional[Dict[str, Any]]:
        return self.users.send_friend_request(user_id=user_id, message=message)

    def accept_friend_request(self, user_id: Union[int, str]) -> Optional[Dict[str, Any]]:
        return self.users.accept_friend_request(user_id=user_id)

    def reject_friend_request(self, user_id: Union[int, str]) -> Optional[Dict[str, Any]]:
        return self.users.reject_friend_request(user_id=user_id)

    def get_friend_requests(self, page: int=1) -> Optional[Dict[str, Any]]:
        return self.users.get_friend_requests(page=page)

    def create_poll(self, group_id: int, question: str, options: List[str]) -> bool:
        return self.group_message.create_poll(group_id=group_id, question=question, options=options)

    def send_photo(self, target_id: Union[int, str], photo_url_or_path: str, thread_type: Union[ThreadType, int]=ThreadType.GROUP, caption: str='', title: Optional[str]=None, description: Optional[str]=None, width: int=0, height: int=0, total_size: int=0, thumb_url: Optional[str]=None, hd_url: Optional[str]=None, ttl: int=0, quote_data: Optional[Dict[str, Any]]=None, native: bool=True, sub_type: int=32, is_original: bool=False) -> bool:
        return self.send.send_photo(target_id=target_id, photo_url_or_path=photo_url_or_path, thread_type=thread_type, caption=caption, title=title, description=description, width=width, height=height, total_size=total_size, thumb_url=thumb_url, hd_url=hd_url, ttl=ttl, quote_data=quote_data, native=native, sub_type=sub_type, is_original=is_original)

    def send_group_photo(self, group_id: Union[int, str], photo_url_or_path: str, caption: str='', **kwargs) -> bool:
        return self.send.send_group_photo(group_id=group_id, photo_url_or_path=photo_url_or_path, caption=caption, **kwargs)

    def send_1to1_photo(self, to_uid: Union[int, str], photo_url_or_path: str, caption: str='', **kwargs) -> bool:
        return self.send.send_1to1_photo(to_uid=to_uid, photo_url_or_path=photo_url_or_path, caption=caption, **kwargs)
    send_image = send_photo
    send_group_image = send_group_photo
    send_1to1_image = send_1to1_photo

    def send_doodle(self, target_id: Union[int, str], doodle_url_or_path: str, thread_type: Union[ThreadType, int]=ThreadType.GROUP, caption: str='', title: Optional[str]=None, description: Optional[str]=None, thumb_url: Optional[str]=None, hd_url: Optional[str]=None, width: int=0, height: int=0, total_size: int=0, ttl: int=0, quote_data: Optional[Dict[str, Any]]=None, native: bool=True, sub_type: int=37, is_original: bool=False) -> bool:
        return self.send.send_doodle(target_id=target_id, doodle_url_or_path=doodle_url_or_path, thread_type=thread_type, caption=caption, title=title, description=description, thumb_url=thumb_url, hd_url=hd_url, width=width, height=height, total_size=total_size, ttl=ttl, quote_data=quote_data, native=native, sub_type=sub_type, is_original=is_original)

    def send_group_doodle(self, group_id: Union[int, str], doodle_url_or_path: str, caption: str='', **kwargs) -> bool:
        return self.send.send_group_doodle(group_id=group_id, doodle_url_or_path=doodle_url_or_path, caption=caption, **kwargs)

    def send_1to1_doodle(self, to_uid: Union[int, str], doodle_url_or_path: str, caption: str='', **kwargs) -> bool:
        return self.send.send_1to1_doodle(to_uid=to_uid, doodle_url_or_path=doodle_url_or_path, caption=caption, **kwargs)

    def send_video(self, target_id: Union[int, str], video_url_or_path: str, thread_type: Union[ThreadType, int]=ThreadType.GROUP, caption: str='', title: Optional[str]=None, description: Optional[str]=None, thumb_url: Optional[str]=None, width: int=0, height: int=0, duration_ms: int=0, total_size: int=0, ttl: int=0, quote_data: Optional[Dict[str, Any]]=None, native: bool=True, sub_type: int=44) -> bool:
        return self.send.send_video(target_id=target_id, video_url_or_path=video_url_or_path, thread_type=thread_type, caption=caption, title=title, description=description, thumb_url=thumb_url, width=width, height=height, duration_ms=duration_ms, total_size=total_size, ttl=ttl, quote_data=quote_data, native=native, sub_type=sub_type)

    def send_group_video(self, group_id: Union[int, str], video_url_or_path: str, caption: str='', **kwargs) -> bool:
        return self.send.send_group_video(group_id=group_id, video_url_or_path=video_url_or_path, caption=caption, **kwargs)

    def send_1to1_video(self, to_uid: Union[int, str], video_url_or_path: str, caption: str='', **kwargs) -> bool:
        return self.send.send_1to1_video(to_uid=to_uid, video_url_or_path=video_url_or_path, caption=caption, **kwargs)

    def close(self):
        if self._socket:
            self._socket.close()

    def disconnect(self):
        self.close()

    send_msg = send_message
    send_group_msg = send_group_message
    send_user_message = send_1to1_message
    send_direct_message = send_1to1_message
    send_dm = send_1to1_message

    react = send_reaction
    pin = pin_message
    unpin = unpin_message
    kick = remove_member
    ban_member = block_group_member
    ban = block_group_member
    leave = leave_group
    disband = disband_group

    delete_msg = delete_message
    recall_msg = recall_message
    revoke_message = recall_message
    revoke_msg = recall_message

    preview_group = preview_group_link
    preview_link = preview_group_link
    resolve_group_id = resolve_group_id_from_link

    list_groups = get_group_list
    list_all_groups = get_all_groups
    all_groups = get_all_groups
    get_group = get_group_detail

    get_profile = get_user_profile
    fetch_profile = get_user_profile
    list_friends = get_friends
    list_friend_pages = get_friend_list
    add_friend = send_friend_request
    request_friend = send_friend_request
    accept_friend = accept_friend_request
    reject_friend = reject_friend_request

    send_img = send_photo
    send_group_img = send_group_photo
    send_1to1_img = send_1to1_photo
    send_vid = send_video
    send_group_vid = send_group_video
    send_1to1_vid = send_1to1_video


ZaloAPI = ZaloClient
