#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/socket/actions/send_reaction.py — Socket action mixin cho thả cảm xúc (Reaction).
"""

import logging
import time
from typing import Optional

from core.socket.protocol import (
    compute_checksum,
    build_reaction_packet,
    build_outer_frame
)

logger = logging.getLogger("core.socket.actions.send_reaction")


class SendReactionActionMixin:
    """Mixin xử lý thả cảm xúc vào tin nhắn qua Socket."""

    def send_reaction(
        self,
        target_id: int,
        cli_msg_id: int,
        global_msg_id: int = 0,
        icon: str = "❤️",
        is_group: bool = True
    ) -> bool:
        if not self.is_connected or not self.sock:
            return False
        try:
            seq, cmsg, _ = self._get_next_counters()
            cmd = 1785 if is_group else 1780
            target_type = 4 if is_group else 3
            ck = compute_checksum(cmd, 0, seq, self.uid, target=int(target_id), target_type=target_type, cmsg=cmsg, bb=1, ty=2, ver=3)
            inner = build_reaction_packet(
                uid=self.uid,
                target_id=int(target_id),
                cli_msg_id=int(cli_msg_id),
                global_msg_id=int(global_msg_id or 0),
                icon=icon,
                is_group=is_group,
                seq=seq,
                ck_val=ck,
                cmsg_id=cmsg
            )
            outer = build_outer_frame(inner, self.dk)
            with self.send_lock:
                if self.sock:
                    self.sock.sendall(outer)
            self.last_traffic = time.time()
            return True
        except Exception as e:
            logger.error(f"[!] Lỗi gửi reaction: {e}")
            return False
