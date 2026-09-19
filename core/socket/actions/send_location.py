import logging
import time
from typing import Optional, Union, Dict, Any
from core.socket.protocol import SUB_LOCATION_MSG, build_outer_frame
from core.socket.tcp.send_location import build_location_message_packet

logger = logging.getLogger('core.socket.actions.send_location')

class SendLocationActionMixin:

    def send_location(self, target_id: int, lat: Union[float, int, str], lon: Union[float, int, str], address: str = '', place_id: str = '', is_user_location: int = 1, is_group: bool = True, text: str = '', ttl_ms: int = 0, ttl: Optional[int] = None, quote_data: Optional[dict] = None, thread_type: Optional[Any] = None, sub_type: int = SUB_LOCATION_MSG, **kwargs) -> bool:
        if thread_type is not None:
            is_group = thread_type == 2 or thread_type == 4 or str(thread_type).lower() in ('group', 'threadtype.group')
        if ttl is not None and ttl_ms == 0:
            ttl_ms = ttl * 1000 if ttl < 100000 else ttl
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            inner = build_location_message_packet(
                uid=self.uid,
                target_id=int(target_id),
                lat=lat,
                lon=lon,
                seq=seq,
                cmsg_id=cmsg,
                address=address,
                place_id=place_id,
                is_user_location=is_user_location,
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
            logger.error(f'Lỗi gửi vị trí tới {target_id}: {e}')
            return False

    def send_group_location(self, group_id: int, lat: Union[float, int, str], lon: Union[float, int, str], address: str = '', place_id: str = '', text: str = '', ttl_ms: int = 0, ttl: Optional[int] = None, quote_data: Optional[dict] = None, **kwargs) -> bool:
        return self.send_location(target_id=group_id, lat=lat, lon=lon, address=address, place_id=place_id, is_group=True, text=text, ttl_ms=ttl_ms, ttl=ttl, quote_data=quote_data, **kwargs)

    def send_1to1_location(self, target_uid: int, lat: Union[float, int, str], lon: Union[float, int, str], address: str = '', place_id: str = '', text: str = '', ttl_ms: int = 0, ttl: Optional[int] = None, quote_data: Optional[dict] = None, **kwargs) -> bool:
        return self.send_location(target_id=target_uid, lat=lat, lon=lon, address=address, place_id=place_id, is_group=False, text=text, ttl_ms=ttl_ms, ttl=ttl, quote_data=quote_data, **kwargs)

    sendLocation = send_location
