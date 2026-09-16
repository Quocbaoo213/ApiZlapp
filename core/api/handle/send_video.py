import logging
from typing import Optional, Dict, Any, Union
from core.api.common import BaseAPI
from core.models.enums import ThreadType
logger = logging.getLogger('core.api.handle.send_video')

class SendVideoAPI(BaseAPI):

    def send_video(self, target_id: Union[int, str], video_url_or_path: str, thread_type: Union[ThreadType, int]=ThreadType.GROUP, caption: str='', title: Optional[str]=None, description: Optional[str]=None, thumb_url: Optional[str]=None, width: int=0, height: int=0, duration_ms: int=0, total_size: int=0, ttl: int=0, quote_data: Optional[Dict[str, Any]]=None, native: bool=True, sub_type: int=44) -> bool:
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning('Socket client chưa kết nối để gửi video.')
            return False
        t_id = int(target_id)
        is_group = thread_type == ThreadType.GROUP or thread_type in ('group', 'GROUP', 2, 4)
        try:
            if not width or not height or (not duration_ms) or (not total_size):
                from core.utils.helpers import resolve_video_metadata
                resolved_url, w, h, dur, sz = resolve_video_metadata(video_url_or_path)
                video_url_or_path = resolved_url or video_url_or_path
                width = width or w
                height = height or h
                duration_ms = duration_ms or dur
                total_size = total_size or sz
            return self._socket.send_video(target_id=t_id, video_url_or_path=video_url_or_path, is_group=is_group, caption=caption, title=title, description=description, thumb_url=thumb_url, width=width, height=height, duration_ms=duration_ms, total_size=total_size, ttl=ttl, quote_data=quote_data, native=native, sub_type=sub_type)
        except Exception as e:
            logger.error(f'[!] Lỗi khi gửi video tới {t_id}: {e}')
            return False

    def send_group_video(self, group_id: Union[int, str], video_url_or_path: str, caption: str='', **kwargs) -> bool:
        return self.send_video(target_id=group_id, video_url_or_path=video_url_or_path, thread_type=ThreadType.GROUP, caption=caption, **kwargs)

    def send_1to1_video(self, to_uid: Union[int, str], video_url_or_path: str, caption: str='', **kwargs) -> bool:
        return self.send_video(target_id=to_uid, video_url_or_path=video_url_or_path, thread_type=ThreadType.USER, caption=caption, **kwargs)
