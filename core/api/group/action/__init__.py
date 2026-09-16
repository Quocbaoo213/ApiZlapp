#!/usr/bin/env python3
"""
core/api/group/action/__init__.py — GroupActionAPI: Tổng hợp các thao tác quản trị nhóm.
Tương ứng Go reference: internal/api/group/action/
"""

from core.api.group.action.kick import KickAPI
from core.api.group.action.ban import BanAPI
from core.api.group.action.add import AddAPI
from core.api.group.action.leave import LeaveAPI
from core.api.group.action.join import JoinAPI
from core.api.group.action.disband import DisbandAPI


class GroupActionAPI(KickAPI, BanAPI, AddAPI, LeaveAPI, JoinAPI, DisbandAPI):
    """Facade service cho các hành động quản trị nhóm (Kick, Ban, Add, Leave, Join, Disband)."""
    pass


__all__ = [
    "GroupActionAPI",
    "KickAPI",
    "BanAPI",
    "AddAPI",
    "LeaveAPI",
    "JoinAPI",
    "DisbandAPI"
]
