from core.api.group.message.pin import PinAPI
from core.api.group.message.unpin import UnpinAPI
from core.api.group.message.poll import PollAPI

class GroupMessageAPI(PinAPI, UnpinAPI, PollAPI):
    pass
__all__ = ['GroupMessageAPI', 'PinAPI', 'UnpinAPI', 'PollAPI']
