from core.api.properties.typing import TypingAPI
from core.api.properties.receipts import ReceiptsAPI
from core.api.handle.undo_message import UndoMessageAPI

class PropertiesAPI(TypingAPI, ReceiptsAPI, UndoMessageAPI):
    pass
__all__ = ['PropertiesAPI', 'TypingAPI', 'ReceiptsAPI', 'UndoMessageAPI']
