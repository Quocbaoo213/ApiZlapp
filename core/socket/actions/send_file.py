import logging
import time
from typing import Optional, Union, Dict, Any
from core.socket.protocol import SUB_FILE_MSG, build_outer_frame
from core.socket.tcp.send_file import build_file_message_packet

logger = logging.getLogger('core.socket.actions.send_file')

class SendFileActionMixin:

    def send_file(self, target_id: int, file_url: str, file_name: str, file_size: Union[int, str] = 0, checksum: str = '', file_ext: str = '', duration: int = 0, f_type: int = 1, thumb: str = '', is_group: bool = True, text: str = '', ttl_ms: int = 0, ttl: Optional[int] = None, quote_data: Optional[dict] = None, thread_type: Optional[Any] = None, sub_type: int = SUB_FILE_MSG, **kwargs) -> bool:
        if thread_type is not None:
            is_group = thread_type == 2 or thread_type == 4 or str(thread_type).lower() in ('group', 'threadtype.group')
        if ttl is not None and ttl_ms == 0:
            ttl_ms = ttl * 1000 if ttl < 100000 else ttl
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            inner = build_file_message_packet(
                uid=self.uid,
                target_id=int(target_id),
                file_url=file_url,
                file_name=file_name,
                seq=seq,
                cmsg_id=cmsg,
                file_size=file_size,
                checksum=checksum,
                file_ext=file_ext,
                duration=duration,
                f_type=f_type,
                thumb=thumb,
                is_group=is_group,
                text=text,
                ttl_ms=ttl_ms,
                quote_data=quote_data,
                cryptkey=self.cryptkey if not is_group else None,
                sub_type=sub_type
            )
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            return True
        except Exception as e:
            logger.error(f'Lỗi gửi file tới {target_id}: {e}')
            return False

    def send_group_file(self, group_id: int, file_url: str, file_name: str, file_size: Union[int, str] = 0, checksum: str = '', file_ext: str = '', text: str = '', ttl_ms: int = 0, ttl: Optional[int] = None, quote_data: Optional[dict] = None, **kwargs) -> bool:
        return self.send_file(target_id=group_id, file_url=file_url, file_name=file_name, file_size=file_size, checksum=checksum, file_ext=file_ext, is_group=True, text=text, ttl_ms=ttl_ms, ttl=ttl, quote_data=quote_data, **kwargs)

    def send_1to1_file(self, target_uid: int, file_url: str, file_name: str, file_size: Union[int, str] = 0, checksum: str = '', file_ext: str = '', text: str = '', ttl_ms: int = 0, ttl: Optional[int] = None, quote_data: Optional[dict] = None, **kwargs) -> bool:
        return self.send_file(target_id=target_uid, file_url=file_url, file_name=file_name, file_size=file_size, checksum=checksum, file_ext=file_ext, is_group=False, text=text, ttl_ms=ttl_ms, ttl=ttl, quote_data=quote_data, **kwargs)

    sendFile = send_file
