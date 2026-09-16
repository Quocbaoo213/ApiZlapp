#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/socket/actions/send_video.py — Socket action mixin cho gửi Video (SUB 44).
"""

import logging
import time
from typing import Optional, Any

from core.socket.protocol import (
    SUB_VIDEO_MSG,
    build_video_message_packet,
    build_outer_frame
)

logger = logging.getLogger("core.socket.actions.send_video")


class SendVideoActionMixin:
    """Mixin xử lý gửi video qua Socket."""

    def send_video(
        self,
        target_id: int,
        video_url_or_path: str,
        is_group: bool = True,
        caption: str = "",
        title: Optional[str] = None,
        description: Optional[str] = None,
        thumb_url: Optional[str] = None,
        width: int = 1280,
        height: int = 720,
        duration_ms: int = 0,
        total_size: int = 0,
        ttl_ms: int = 0,
        ttl: Optional[int] = None,
        quote_data: Optional[dict] = None,
        native: bool = True,
        sub_type: int = SUB_VIDEO_MSG,
        thread_type: Optional[Any] = None,
        **kwargs
    ) -> bool:
        """
        Gửi video (video / media card) tới Group hoặc 1-1 qua TCP Socket Gateway.
        """
        if thread_type is not None:
            is_group = (thread_type == 2 or thread_type == 4 or str(thread_type).lower() in ("group", "threadtype.group"))
        if ttl is not None and ttl_ms == 0:
            ttl_ms = ttl * 1000 if ttl < 100000 else ttl
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            inner = build_video_message_packet(
                uid=self.uid,
                target_id=int(target_id),
                video_url=video_url_or_path,
                seq=seq,
                cmsg_id=cmsg,
                is_group=is_group,
                caption=caption,
                title=title,
                description=description,
                thumb_url=thumb_url,
                width=width,
                height=height,
                duration_ms=duration_ms,
                total_size=total_size,
                ttl_ms=ttl_ms,
                quote_data=quote_data,
                cryptkey=self.cryptkey if not is_group else None,
                native=native,
                sub_type=sub_type
            )
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi gửi video tới {target_id}: {e}")
            return False
