#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/api/handle/send_doodle.py — API gửi Doodle / Hình vẽ (SUB 37).
"""

import logging
from typing import Optional, Dict, Any, Union

from core.api.common import BaseAPI
from core.models.enums import ThreadType

logger = logging.getLogger("core.api.handle.send_doodle")


class SendDoodleAPI(BaseAPI):
    """API chuyên biệt cho gửi Doodle / Hình vẽ."""

    def send_doodle(
        self,
        target_id: Union[int, str],
        doodle_url_or_path: str,
        thread_type: Union[ThreadType, int] = ThreadType.GROUP,
        caption: str = "",
        title: Optional[str] = None,
        description: Optional[str] = None,
        thumb_url: Optional[str] = None,
        hd_url: Optional[str] = None,
        width: int = 0,
        height: int = 0,
        total_size: int = 0,
        ttl: int = 0,
        quote_data: Optional[Dict[str, Any]] = None,
        native: bool = True,
        sub_type: int = 37,
        is_original: bool = False
    ) -> bool:
        """Gửi hình vẽ (doodle / SUB 37) tới Nhóm hoặc Cá nhân 1-1."""
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning("Socket client chưa kết nối để gửi doodle.")
            return False

        t_id = int(target_id)
        is_group = (thread_type == ThreadType.GROUP or thread_type in ("group", "GROUP", 2, 4))

        try:
            return self._socket.send_photo(
                target_id=t_id,
                photo_url_or_path=doodle_url_or_path,
                is_group=is_group,
                caption=caption,
                title=title,
                description=description,
                thumb_url=thumb_url,
                hd_url=hd_url,
                width=width,
                height=height,
                total_size=total_size,
                ttl=ttl,
                quote_data=quote_data,
                native=native,
                sub_type=sub_type,
                is_original=is_original
            )
        except Exception as e:
            logger.error(f"[!] Lỗi khi gửi doodle tới {t_id}: {e}")
            return False

    def send_group_doodle(
        self,
        group_id: Union[int, str],
        doodle_url_or_path: str,
        caption: str = "",
        **kwargs
    ) -> bool:
        """Shortcut gửi hình vẽ (doodle) tới nhóm chat."""
        return self.send_doodle(
            target_id=group_id,
            doodle_url_or_path=doodle_url_or_path,
            thread_type=ThreadType.GROUP,
            caption=caption,
            **kwargs
        )

    def send_1to1_doodle(
        self,
        to_uid: Union[int, str],
        doodle_url_or_path: str,
        caption: str = "",
        **kwargs
    ) -> bool:
        """Shortcut gửi hình vẽ (doodle) tới cá nhân 1-1."""
        return self.send_doodle(
            target_id=to_uid,
            doodle_url_or_path=doodle_url_or_path,
            thread_type=ThreadType.USER,
            caption=caption,
            **kwargs
        )
