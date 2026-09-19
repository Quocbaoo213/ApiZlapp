import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Callable, Union

logger = logging.getLogger('core.socket.events')

@dataclass
class MessageEvent:
    msg_id: int = 0
    cli_msg_id: int = 0
    from_uid: int = 0
    from_display: str = ""
    to_id: Optional[int] = None
    to_group: Optional[int] = None
    is_group: bool = False
    is_self: bool = False
    text: str = ""
    content: str = ""
    msg_type: str = "webchat"
    type: str = "webchat"
    ttl: int = 0
    ts: int = 0
    attach: Any = None
    mentions: List[Dict[str, Any]] = field(default_factory=list)
    quote: Optional[Dict[str, Any]] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MessageEvent':
        return cls(
            msg_id=data.get('msg_id', 0),
            cli_msg_id=data.get('cli_msg_id', 0),
            from_uid=data.get('from_uid', 0),
            from_display=data.get('from_display') or data.get('from_name') or "",
            to_id=data.get('to_id'),
            to_group=data.get('to_group'),
            is_group=bool(data.get('is_group')),
            is_self=bool(data.get('is_self')),
            text=data.get('text') or data.get('content') or "",
            content=data.get('content') or data.get('text') or "",
            msg_type=data.get('type') or data.get('msg_type') or "webchat",
            type=data.get('type') or data.get('msg_type') or "webchat",
            ttl=data.get('ttl', 0),
            ts=data.get('ts', 0),
            attach=data.get('attach'),
            mentions=data.get('mentions') or [],
            quote=data.get('quote'),
            raw=data.get('raw') or data
        )

@dataclass
class ReactionEvent:
    from_uid: int = 0
    from_display: str = ""
    to_id: Optional[int] = None
    to_group: Optional[int] = None
    is_group: bool = False
    is_self: bool = False
    r_icon: str = ""
    r_type: Optional[int] = None
    target_cli_msg_id: int = 0
    target_global_msg_id: int = 0
    ts: int = 0
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReactionEvent':
        return cls(
            from_uid=data.get('from_uid', 0),
            from_display=data.get('from_display') or data.get('from_name') or "",
            to_id=data.get('to_id'),
            to_group=data.get('to_group'),
            is_group=bool(data.get('is_group')),
            is_self=bool(data.get('is_self')),
            r_icon=data.get('r_icon', ''),
            r_type=data.get('r_type'),
            target_cli_msg_id=data.get('target_cli_msg_id', 0),
            target_global_msg_id=data.get('target_global_msg_id', 0),
            ts=data.get('ts', 0),
            raw=data.get('raw') or data
        )

    @property
    def icon(self) -> str:
        return self.r_icon

class EventHub:
    """Pub/Sub Event Hub cho Socket Client (tương tự worker.Hub trong NBT Platform)."""

    def __init__(self):
        self._handlers: Dict[str, List[Callable]] = {
            'message': [],
            'reaction': [],
            'group_event': [],
            'delivery': [],
            'error': [],
            'frame': []
        }

    def on(self, event_name: str, handler: Callable):
        evt = str(event_name).lower().strip()
        if evt not in self._handlers:
            self._handlers[evt] = []
        self._handlers[evt].append(handler)
        return handler

    def emit(self, event_name: str, *args, **kwargs):
        evt = str(event_name).lower().strip()
        handlers = self._handlers.get(evt, [])
        for h in handlers:
            try:
                h(*args, **kwargs)
            except Exception as e:
                logger.error(f"Lỗi khi thực thi event handler '{evt}': {e}", exc_info=True)

    def on_message(self, handler: Callable[[MessageEvent], None]):
        return self.on('message', handler)

    def on_reaction(self, handler: Callable[[ReactionEvent], None]):
        return self.on('reaction', handler)

    def on_delivery(self, handler: Callable[[Dict[str, Any]], None]):
        return self.on('delivery', handler)

    def on_error(self, handler: Callable[[Exception], None]):
        return self.on('error', handler)

    def on_frame(self, handler: Callable[[Dict[str, Any]], None]):
        return self.on('frame', handler)
