from enum import Enum, IntEnum
from typing import Optional

class ThreadType(Enum):
    USER = 'user'
    GROUP = 'group'

class Gender(IntEnum):
    MALE = 0
    FEMALE = 1
    UNKNOWN = 2

    @classmethod
    def to_display_string(cls, code: Optional[int]) -> str:
        if code == cls.MALE:
            return 'Nam'
        elif code == cls.FEMALE:
            return 'Nữ'
        return 'Không công khai'

class MessageType(IntEnum):
    TEXT = 1
    PHOTO = 2
    VIDEO = 3
    VOICE = 4
    STICKER = 6
    CLI_PHOTO = 32
    CLI_STICKER = 36
    CLI_DOODLE = 37
    CLI_VIDEO = 44

class ReactionIcon(str, Enum):
    HEART = '/-heart'
    LIKE = ':>'
    HAHA = ':-D'
    WOW = ':-O'
    CRY = ':-(('
    ANGRY = ':-t'
    DISLIKE = '/-weak'
    BROKEN_HEART = '/-break'
    ROSE = '/-rose'
    BEER = '/-beer'
    COFFEE = '/-coffee'
    HANDCLAP = ':handclap'
    KISS = ':-*'
    SUN = '/-sun'
    CAKE = '/-cake'
    SHOWLOVE = '/-showlove'

    @classmethod
    def resolve(cls, val: str) -> tuple[int, str, str]:
        raw = val.strip()
        clean = raw.lower()
        details_map = {'❤️': (5, '/-heart', '❤️'), 'tim': (5, '/-heart', '❤️'), 'love': (5, '/-heart', '❤️'), 'heart': (5, '/-heart', '❤️'), '/-heart': (5, '/-heart', '❤️'), '👍': (0, ':>', '👍'), 'like': (0, ':>', '👍'), 'thich': (0, ':>', '👍'), ':>': (0, ':>', '👍'), '/-strong': (0, ':>', '👍'), '😂': (3, ':-D', '😂'), 'haha': (3, ':-D', '😂'), 'cuoi': (3, ':-D', '😂'), 'laugh': (3, ':-D', '😂'), '😆': (3, ':-D', '😂'), ':-d': (3, ':-D', '😂'), ':d': (3, ':-D', '😂'), ':))': (3, ':-D', '😂'), '😮': (32, ':-O', '😮'), 'wow': (32, ':-O', '😮'), 'batngo': (32, ':-O', '😮'), '😲': (32, ':-O', '😮'), ':-o': (32, ':-O', '😮'), ':o': (32, ':-O', '😮'), '😭': (2, ':-((', '😭'), 'cry': (2, ':-((', '😭'), 'sad': (2, ':-((', '😭'), 'khoc': (2, ':-((', '😭'), '😢': (2, ':-((', '😭'), ':-((': (2, ':-((', '😭'), ':((': (2, ':-((', '😭'), '😡': (4, ':-t', '😡'), 'angry': (4, ':-t', '😡'), 'tuc': (4, ':-t', '😡'), 'phanno': (4, ':-t', '😡'), 'giận': (4, ':-t', '😡'), 'gian': (4, ':-t', '😡'), '🤬': (4, ':-t', '😡'), ':-t': (4, ':-t', '😡'), ':@': (4, ':-t', '😡'), '👎': (1, '/-weak', '👎'), 'dislike': (1, '/-weak', '👎'), '/-weak': (1, '/-weak', '👎'), '💔': (6, '/-break', '💔'), 'broken': (6, '/-break', '💔'), 'votu': (6, '/-break', '💔'), '/-break': (6, '/-break', '💔'), '🌹': (75, '/-rose', '🌹'), 'rose': (75, '/-rose', '🌹'), 'hoa': (75, '/-rose', '🌹'), '/-rose': (75, '/-rose', '🌹'), '🍻': (75, '/-beer', '🍻'), 'beer': (75, '/-beer', '🍻'), 'bia': (75, '/-beer', '🍻'), '/-beer': (75, '/-beer', '🍻'), '☕': (75, '/-coffee', '☕'), 'coffee': (75, '/-coffee', '☕'), 'cafe': (75, '/-coffee', '☕'), '/-coffee': (75, '/-coffee', '☕'), '👏': (75, ':handclap', '👏'), 'clap': (75, ':handclap', '👏'), 'vo tay': (75, ':handclap', '👏'), ':handclap': (75, ':handclap', '👏'), '😘': (75, ':-*', '😘'), 'kiss': (75, ':-*', '😘'), 'hon': (75, ':-*', '😘'), ':-*': (75, ':-*', '😘'), '☀️': (75, '/-sun', '☀️'), 'sun': (75, '/-sun', '☀️'), '/-sun': (75, '/-sun', '☀️'), '🎂': (75, '/-cake', '🎂'), 'cake': (75, '/-cake', '🎂'), '/-cake': (75, '/-cake', '🎂'), '😍': (75, '/-showlove', '😍'), 'love2': (75, '/-showlove', '😍'), '/-showlove': (75, '/-showlove', '😍'), 'remove': (-1, '', 'Hủy cảm xúc'), 'delete': (-1, '', 'Hủy cảm xúc'), 'hủy': (-1, '', 'Hủy cảm xúc'), 'huy': (-1, '', 'Hủy cảm xúc'), '': (-1, '', 'Hủy cảm xúc')}
        if clean in details_map:
            return details_map[clean]
        if raw in details_map:
            return details_map[raw]
        if raw in ('🧡', '💛', '💚', '💙', '💜', '🖤', '🤍', '🤎', '💖', '💘'):
            return (5, '/-heart', raw)
        return (75, raw, raw)

    @classmethod
    def from_str(cls, val: str) -> str:
        _, r_icon, _ = cls.resolve(val)
        return r_icon

class ZaloGroupErrorCode(IntEnum):
    SUCCESS = 0
    GROUP_NOT_EXISTED = 17002
    GROUP_FULL = 17003
    GROUP_BLOCKED = 17005
    LINK_EXPIRED = 17006
    NEED_APPROVAL = 17008
    ALREADY_MEMBER = 17009
    OVER_JOIN_LIMIT = 17017
    OVER_OWN_LIMIT = 17018
    COMMUNITY_FULL = 17026
    ALREADY_IN_GROUP = 18004

    @classmethod
    def get_message(cls, code: int) -> str:
        messages = {0: 'Thao tác thành công', 17002: 'Nhóm không còn tồn tại (17002)', 17003: 'Nhóm đã đạt giới hạn tối đa số thành viên (17003)', 17005: 'Tài khoản của bạn đã bị chặn khỏi nhóm này (17005)', 17006: 'Liên kết tham gia nhóm đã hết hạn hoặc bị thu hồi (17006)', 17008: 'Yêu cầu tham gia nhóm đang ở hàng đợi chờ Trưởng/Phó nhóm duyệt (17008)', 17009: 'Bạn đã là thành viên của nhóm này rồi (17009)', 17017: 'Tài khoản đã đạt giới hạn tối đa số nhóm có thể tham gia (17017)', 17018: 'Tài khoản đã đạt giới hạn tối đa số nhóm có thể tạo/sở hữu (17018)', 17026: 'Cộng đồng đã đạt giới hạn thành viên (17026)', 18004: 'Tài khoản đã là thành viên của nhóm này rồi (18004)'}
        return messages.get(code, f'Lỗi Zalo mã {code}')
