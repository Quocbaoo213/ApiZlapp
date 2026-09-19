from typing import Optional, Dict, Any, Union, List
from core.api.group.action.api import GroupActionAPI
from core.api.group.message.api import GroupMessageAPI
from core.api.group.info import GroupInfoAPI
from core.api.handle.send_reaction import SendReactionAPI
from core.api.handle.undo_message import UndoMessageAPI

class GroupAPI(GroupActionAPI, GroupMessageAPI, GroupInfoAPI, SendReactionAPI, UndoMessageAPI):
    """
    Unified Group API Factory for Zalo (inspired by zBug GroupAPi).
    Provides actions, group messaging, member moderation, poll, and media sending.
    """

    def ban(self, group_id: int, member_uids: Union[int, List[int]]):
        return self.ban_member(group_id=group_id, member_uids=member_uids)

    def block_user(self, target_uid: int, is_block: bool = True) -> bool:
        if self._socket and getattr(self._socket, 'is_connected', False):
            return self._socket.block_user(target_uid=target_uid, is_block=is_block)
        return False

    def send_sticker(self, group_id: int, cat_id: Union[int, str], sticker_id: Union[int, str], sticker_type: int = 7, ttl_seconds: int = 0, quote = None, **kwargs) -> bool:
        if self._socket and getattr(self._socket, 'is_connected', False):
            ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
            q_dict = quote.to_dict() if hasattr(quote, 'to_dict') else quote
            return self._socket.send_group_sticker(group_id=int(group_id), cat_id=cat_id, sticker_id=sticker_id, sticker_type=sticker_type, ttl_ms=ttl_ms, quote_data=q_dict, **kwargs)
        return False

    def send_location(self, group_id: int, lat: Union[float, int, str], lon: Union[float, int, str], address: str = '', place_id: str = '', ttl_seconds: int = 0, quote = None, **kwargs) -> bool:
        if self._socket and getattr(self._socket, 'is_connected', False):
            ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
            q_dict = quote.to_dict() if hasattr(quote, 'to_dict') else quote
            return self._socket.send_location(target_id=int(group_id), lat=lat, lon=lon, address=address, place_id=place_id, is_group=True, ttl_ms=ttl_ms, quote_data=q_dict, **kwargs)
        return False

    def send_file(self, group_id: int, file_url: str, file_name: str, file_size: Union[int, str] = 0, checksum: str = '', file_ext: str = '', ttl_seconds: int = 0, quote = None, **kwargs) -> bool:
        if self._socket and getattr(self._socket, 'is_connected', False):
            ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
            q_dict = quote.to_dict() if hasattr(quote, 'to_dict') else quote
            return self._socket.send_file(target_id=int(group_id), file_url=file_url, file_name=file_name, file_size=file_size, checksum=checksum, file_ext=file_ext, is_group=True, ttl_ms=ttl_ms, quote_data=q_dict, **kwargs)
        return False

    def send_contact(self, group_id: int, contact_uid: Union[int, str], contact_name: str = '', avatar_url: str = '', qr_code_url: str = '', ttl_seconds: int = 0, quote = None, **kwargs) -> bool:
        if self._socket and getattr(self._socket, 'is_connected', False):
            ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
            q_dict = quote.to_dict() if hasattr(quote, 'to_dict') else quote
            return self._socket.send_contact(target_id=int(group_id), contact_uid=contact_uid, contact_name=contact_name, avatar_url=avatar_url, qr_code_url=qr_code_url, is_group=True, ttl_ms=ttl_ms, quote_data=q_dict, **kwargs)
        return False

    def send_photo(self, group_id: int, photo_url: str, caption: str = '', title: Optional[str] = None, description: Optional[str] = None, width: int = 0, height: int = 0, total_size: int = 0, thumb_url: Optional[str] = None, hd_url: Optional[str] = None, ttl_seconds: int = 0, quote = None, is_original: bool = False, **kwargs) -> bool:
        if self._socket and getattr(self._socket, 'is_connected', False):
            ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
            q_dict = quote.to_dict() if hasattr(quote, 'to_dict') else quote
            return self._socket.send_photo(target_id=int(group_id), photo_url_or_path=photo_url, is_group=True, caption=caption, title=title, description=description, width=width, height=height, total_size=total_size, thumb_url=thumb_url, hd_url=hd_url, ttl_ms=ttl_ms, quote_data=q_dict, is_original=is_original, **kwargs)
        return False

    def send_video(self, group_id: int, video_url: str, caption: str = '', title: Optional[str] = None, description: Optional[str] = None, thumb_url: Optional[str] = None, width: int = 1280, height: int = 720, duration_ms: int = 0, total_size: int = 0, ttl_seconds: int = 0, quote = None, **kwargs) -> bool:
        if self._socket and getattr(self._socket, 'is_connected', False):
            ttl_ms = int(ttl_seconds * 1000) if ttl_seconds > 0 else 0
            q_dict = quote.to_dict() if hasattr(quote, 'to_dict') else quote
            return self._socket.send_video(target_id=int(group_id), video_url=video_url, is_group=True, caption=caption, title=title, description=description, thumb_url=thumb_url, width=width, height=height, duration_ms=duration_ms, total_size=total_size, ttl_ms=ttl_ms, quote_data=q_dict, **kwargs)
        return False

    def kickUsers(self, *args, **kwargs):
        return self.kick_member(*args, **kwargs)

    def addUsersToGroup(self, *args, **kwargs):
        return self.add_member(*args, **kwargs)

    def blockUsers(self, *args, **kwargs):
        return self.block_group_member(*args, **kwargs)

    def leaveGroup(self, *args, **kwargs):
        return self.leave_group(*args, **kwargs)

    def joinGroup(self, *args, **kwargs):
        return self.join_group(*args, **kwargs)

    def disperseGroup(self, *args, **kwargs):
        return self.disband(*args, **kwargs)

    def pinMessage(self, *args, **kwargs):
        return self.pin_message(*args, **kwargs)

    def unpinMessage(self, *args, **kwargs):
        return self.unpin_message(*args, **kwargs)

    def createPoll(self, *args, **kwargs):
        return self.create_poll(*args, **kwargs)

    def undoMessage(self, *args, **kwargs):
        return self.recall_message(*args, **kwargs)

    def deleteMessage(self, *args, **kwargs):
        return self.delete_message(*args, **kwargs)

    def sendReaction(self, *args, **kwargs):
        return self.send_reaction(*args, **kwargs)

    sendSticker = send_sticker
    sendLocation = send_location
    sendFile = send_file
    sendContact = send_contact
    sendBusinessCard = send_contact
    sendPhoto = send_photo
    send_image = send_photo
    sendImage = send_photo
    sendVideo = send_video

    def _call_group_api(self, endpoint: str, params: dict) -> dict:
        link_id = params.get('linkId') or params.get('grid') or ''
        return self.get_group_info_by_link(str(link_id)) or {}

__all__ = ['GroupAPI', 'GroupActionAPI', 'GroupMessageAPI', 'GroupInfoAPI']
