from typing import Optional, Any
from core.socket.protocol import SUB_DOODLE_MSG

class SendDoodleActionMixin:

    def send_doodle(self, target_id: int, doodle_url_or_path: str, is_group: bool=True, caption: str='', title: Optional[str]=None, description: Optional[str]=None, width: int=0, height: int=0, total_size: int=0, thumb_url: Optional[str]=None, hd_url: Optional[str]=None, ttl_ms: int=0, ttl: Optional[int]=None, quote_data: Optional[dict]=None, native: bool=True, sub_type: int=SUB_DOODLE_MSG, is_original: bool=False, thread_type: Optional[Any]=None, **kwargs) -> bool:
        return self.send_photo(target_id=target_id, photo_url_or_path=doodle_url_or_path, is_group=is_group, caption=caption, title=title, description=description, width=width, height=height, total_size=total_size, thumb_url=thumb_url, hd_url=hd_url, ttl_ms=ttl_ms, ttl=ttl, quote_data=quote_data, native=native, sub_type=sub_type, is_original=is_original, thread_type=thread_type, **kwargs)
