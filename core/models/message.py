from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
import time

@dataclass
class Quote:
    owner_uid: int
    owner_name: str
    msg_text: str
    msg_id: int = 0
    cli_msg_id: int = 0
    group_id: Optional[int] = None
    msg_type: int = 1
    attach: str = ''
    ttl: int = 0

    def to_dict(self) -> Dict[str, Any]:
        clean_name = (self.owner_name or '').strip()
        if clean_name.endswith(')') and ' (' in clean_name:
            clean_name = clean_name.split(' (')[0].strip()
        if not clean_name or clean_name.lower() in ('null', 'none'):
            clean_name = str(self.owner_uid)
        return {'cliMsgType': int(self.msg_type) if self.msg_type else 1, 'cliMsgId': int(self.cli_msg_id) if self.cli_msg_id else int(time.time() * 1000), 'globalMsgId': int(self.msg_id) if self.msg_id else 0, 'ownerId': int(self.owner_uid), 'gOwnerId': int(self.group_id) if self.group_id else None, 'fromD': clean_name, 'ts': int(time.time() * 1000), 'msg': str(self.msg_text) if self.msg_text else '', 'attach': str(self.attach) if self.attach else '', 'ttl': int(self.ttl) if self.ttl else 0}

@dataclass
class Message:
    text: str
    from_uid: int
    from_name: str
    group_id: Optional[int] = None
    is_group: bool = False
    msg_id: int = 0
    cli_msg_id: int = 0
    timestamp: int = 0
    mentions: List[Dict[str, Any]] = field(default_factory=list)
    quote: Optional[Dict[str, Any]] = None
    raw: Dict[str, Any] = field(default_factory=dict)
