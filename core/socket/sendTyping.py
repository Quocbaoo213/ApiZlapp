#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/socket/sendTyping.py — TCP Binary Protocol Builder & Handler cho Typing Status.
"""

from core.socket.protocol import (
    build_typing_packet,
    build_typing_packet as buildTypingPacket
)

__all__ = ["build_typing_packet", "buildTypingPacket"]
