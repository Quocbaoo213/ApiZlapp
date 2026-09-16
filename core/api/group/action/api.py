from core.api.group.action.kick import KickAPI
from core.api.group.action.ban import BanAPI
from core.api.group.action.add import AddAPI
from core.api.group.action.leave import LeaveAPI
from core.api.group.action.join import JoinAPI
from core.api.group.action.disband import DisbandAPI

class GroupActionAPI(KickAPI, BanAPI, AddAPI, LeaveAPI, JoinAPI, DisbandAPI):
    pass
__all__ = ['GroupActionAPI', 'KickAPI', 'BanAPI', 'AddAPI', 'LeaveAPI', 'JoinAPI', 'DisbandAPI']
