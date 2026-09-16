#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/socket/actions/send_image.py — Socket action mixin cho gửi Hình ảnh (Photo / Image).
"""

import logging
import time
from typing import Optional, Any

from core.socket.protocol import (
    SUB_PHOTO_MSG,
    build_photo_message_packet,
    build_outer_frame
)

logger = logging.getLogger("core.socket.actions.send_image")


class SendImageActionMixin:
    """Mixin xử lý gửi hình ảnh qua Socket."""

    def send_photo(
        self,
        target_id: int,
        photo_url_or_path: str,
        is_group: bool = True,
        caption: str = "",
        title: Optional[str] = None,
        description: Optional[str] = None,
        width: int = 0,
        height: int = 0,
        total_size: int = 0,
        thumb_url: Optional[str] = None,
        hd_url: Optional[str] = None,
        ttl_ms: int = 0,
        ttl: Optional[int] = None,
        quote_data: Optional[dict] = None,
        native: bool = True,
        sub_type: int = SUB_PHOTO_MSG,
        is_original: bool = False,
        thread_type: Optional[Any] = None,
        **kwargs
    ) -> bool:
        """
        Gửi hình ảnh (photo / media card) tới Group hoặc 1-1 qua TCP Socket Gateway.
        """
        if thread_type is not None:
            is_group = (thread_type == 2 or thread_type == 4 or str(thread_type).lower() in ("group", "threadtype.group"))
        if ttl is not None and ttl_ms == 0:
            ttl_ms = ttl * 1000 if ttl < 100000 else ttl
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            inner = build_photo_message_packet(
                uid=self.uid,
                target_id=int(target_id),
                photo_url=photo_url_or_path,
                seq=seq,
                cmsg_id=cmsg,
                is_group=is_group,
                caption=caption,
                title=title,
                description=description,
                width=width,
                height=height,
                total_size=total_size,
                thumb_url=thumb_url,
                hd_url=hd_url,
                ttl_ms=ttl_ms,
                quote_data=quote_data,
                cryptkey=self.cryptkey if not is_group else None,
                native=native,
                sub_type=sub_type,
                is_original=is_original
            )
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi gửi ảnh tới {target_id}: {e}")
            return False

    send_image = send_photo
