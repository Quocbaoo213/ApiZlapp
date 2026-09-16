from typing import Optional, Dict, Any
from core.socket.protocol import SUB_DOODLE_MSG
from core.socket.tcp.send_image import build_photo_attach, build_photo_binary_payload, build_photo_message_packet

def build_doodle_attach(url: str, width: int=0, height: int=0, total_size: int=0, title: str='', description: str='', thumb_url: Optional[str]=None) -> Dict[str, Any]:
    return build_photo_attach(url=url, width=width, height=height, total_size=total_size, title=title, description=description, thumb_url=thumb_url)

def build_doodle_message_packet(uid: int, target_id: int, doodle_url: str, seq: int, ck_val: Optional[int]=None, cmsg_id: int=0, is_group: bool=True, caption: str='', title: Optional[str]=None, description: Optional[str]=None, width: int=0, height: int=0, total_size: int=0, thumb_url: Optional[str]=None, ttl_ms: int=0, quote_data: Optional[dict]=None, cryptkey: Optional[bytes]=None, native: bool=True, sub_type: int=SUB_DOODLE_MSG, is_original: bool=False) -> bytes:
    return build_photo_message_packet(uid=uid, target_id=target_id, photo_url=doodle_url, seq=seq, ck_val=ck_val, cmsg_id=cmsg_id, is_group=is_group, caption=caption, title=title, description=description, width=width, height=height, total_size=total_size, thumb_url=thumb_url, ttl_ms=ttl_ms, quote_data=quote_data, cryptkey=cryptkey, native=native, sub_type=sub_type, is_original=is_original)
