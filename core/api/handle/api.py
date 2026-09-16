from core.api.handle.send_messages import SendMessagesAPI
from core.api.handle.send_image import SendImageAPI
from core.api.handle.send_video import SendVideoAPI
from core.api.handle.send_doodle import SendDoodleAPI
from core.api.handle.send_typing import SendTypingAPI
from core.api.handle.send_reaction import SendReactionAPI
from core.api.handle.undo_message import UndoMessageAPI
from core.api.handle.block_user import BlockUserAPI

class SendAPI(SendMessagesAPI, SendImageAPI, SendVideoAPI, SendDoodleAPI, SendTypingAPI, SendReactionAPI, UndoMessageAPI, BlockUserAPI):
    pass
__all__ = ['SendAPI', 'SendMessagesAPI', 'SendImageAPI', 'SendVideoAPI', 'SendDoodleAPI', 'SendTypingAPI', 'SendReactionAPI', 'UndoMessageAPI', 'BlockUserAPI']
