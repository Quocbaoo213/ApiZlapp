#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/socket/sendDoodle.py — TCP Binary Protocol Builder & Handler cho Doodle.
"""

from core.socket.tcp.send_doodle import (
    build_doodle_attach,
    build_doodle_message_packet,
    build_doodle_attach as buildDoodleAttach,
    build_doodle_message_packet as buildDoodleMessagePacket
)

__all__ = [
    "build_doodle_attach",
    "build_doodle_message_packet",
    "buildDoodleAttach",
    "buildDoodleMessagePacket"
]
