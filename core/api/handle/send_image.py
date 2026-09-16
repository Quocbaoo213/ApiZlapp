#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/api/handle/send_image.py — API gửi hình ảnh (Image / Photo / SUB 32).
"""

import logging
from typing import Optional, Dict, Any, Union

from core.api.common import BaseAPI
from core.models.enums import ThreadType

logger = logging.getLogger("core.api.handle.send_image")


class SendImageAPI(BaseAPI):
    """API chuyên biệt cho gửi hình ảnh (Image / Photo)."""

    def send_photo(
        self,
        target_id: Union[int, str],
        photo_url_or_path: str,
        thread_type: Union[ThreadType, int] = ThreadType.GROUP,
        caption: str = "",
        title: Optional[str] = None,
        description: Optional[str] = None,
        width: int = 0,
        height: int = 0,
        total_size: int = 0,
        thumb_url: Optional[str] = None,
        hd_url: Optional[str] = None,
        ttl: int = 0,
        quote_data: Optional[Dict[str, Any]] = None,
        native: bool = True,
        sub_type: int = 32,
        is_original: bool = False
    ) -> bool:
        """
        Gửi hình ảnh (photo / media attachment) tới Nhóm hoặc Cá nhân 1-1.
        Tự động phân giải kích thước ảnh (width, height, size) nếu chưa được chỉ định.
        """
        if not self._socket or not getattr(self._socket, 'is_connected', False):
            logger.warning("Socket client chưa kết nối để gửi ảnh.")
            return False

        t_id = int(target_id)
        is_group = (thread_type == ThreadType.GROUP or thread_type in ("group", "GROUP", 2, 4))

        try:
            if not width or not height or not total_size:
                from core.utils.helpers import resolve_photo_metadata
                resolved_url, w, h, sz = resolve_photo_metadata(photo_url_or_path)
                photo_url_or_path = resolved_url or photo_url_or_path
                width = width or w
                height = height or h
                total_size = total_size or sz

            return self._socket.send_photo(
                target_id=t_id,
                photo_url_or_path=photo_url_or_path,
                is_group=is_group,
                caption=caption,
                title=title,
                description=description,
                width=width,
                height=height,
                total_size=total_size,
                thumb_url=thumb_url,
                hd_url=hd_url,
                ttl=ttl,
                quote_data=quote_data,
                native=native,
                sub_type=sub_type,
                is_original=is_original
            )
        except Exception as e:
            logger.error(f"[!] Lỗi khi gửi ảnh tới {t_id}: {e}")
            return False

    def send_group_photo(
        self,
        group_id: Union[int, str],
        photo_url_or_path: str,
        caption: str = "",
        **kwargs
    ) -> bool:
        """Shortcut gửi hình ảnh tới nhóm chat."""
        return self.send_photo(
            target_id=group_id,
            photo_url_or_path=photo_url_or_path,
            thread_type=ThreadType.GROUP,
            caption=caption,
            **kwargs
        )

    def send_1to1_photo(
        self,
        to_uid: Union[int, str],
        photo_url_or_path: str,
        caption: str = "",
        **kwargs
    ) -> bool:
        """Shortcut gửi hình ảnh tới cá nhân 1-1."""
        return self.send_photo(
            target_id=to_uid,
            photo_url_or_path=photo_url_or_path,
            thread_type=ThreadType.USER,
            caption=caption,
            **kwargs
        )

    send_image = send_photo
    send_group_image = send_group_photo
    send_1to1_image = send_1to1_photo
