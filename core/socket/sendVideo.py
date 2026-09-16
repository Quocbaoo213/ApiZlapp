#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/socket/sendVideo.py — TCP Binary Protocol Builder & Handler cho Video.
"""

from core.socket.tcp.send_video import (
    build_video_attach,
    build_video_binary_payload,
    build_video_message_packet,
    build_video_attach as buildVideoAttach,
    build_video_binary_payload as buildVideoBinaryPayload,
    build_video_message_packet as buildVideoMessagePacket
)

__all__ = [
    "build_video_attach",
    "build_video_binary_payload",
    "build_video_message_packet",
    "buildVideoAttach",
    "buildVideoBinaryPayload",
    "buildVideoMessagePacket"
]
