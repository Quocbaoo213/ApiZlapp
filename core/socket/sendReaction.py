#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/socket/sendReaction.py — TCP Binary Protocol Builder & Handler cho Message Reactions.
"""

from core.socket.protocol import (
    build_reaction_packet,
    build_reaction_packet as buildReactionPacket
)

__all__ = ["build_reaction_packet", "buildReactionPacket"]
