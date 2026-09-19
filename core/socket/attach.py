import json
from typing import Optional, Dict, Any, Union

def build_photo_attach(url: str, width: int=0, height: int=0, total_size: int=0, title: str='', description: str='', thumb_url: Optional[str]=None, hd_url: Optional[str]=None, is_original: bool=False) -> Dict[str, Any]:
    thumb = str(thumb_url or url)
    hd = str(hd_url or url)
    u = str(url)
    res = {
        'title': str(title or ''),
        'description': str(description or ''),
        'href': u,
        'thumb': thumb,
        'hdUrl': hd,
        'normalUrl': u,
        'url': u,
        'thumbs': [thumb],
        'media': {
            'url': u,
            'thumb': thumb,
            'hdUrl': hd,
            'width': int(width or 0),
            'height': int(height or 0),
            'totalSize': int(total_size or 0)
        },
        'tType': 2,
        'tWidth': int(width or 0),
        'tHeight': int(height or 0),
        'width': int(width or 0),
        'height': int(height or 0),
        'totalSize': int(total_size or 0),
        'actionId': 0
    }
    if is_original:
        res['is_original'] = 1
        res['isOriginal'] = True
        res['media']['is_original'] = 1
    return res

def build_video_attach(url: str, width: int=1280, height: int=720, duration: int=0, total_size: int=0, title: str='', description: str='', thumb_url: Optional[str]=None) -> Dict[str, Any]:
    thumb = str(thumb_url or url)
    u = str(url)
    return {
        'title': str(title or ''),
        'description': str(description or ''),
        'href': u,
        'thumb': thumb,
        'normalUrl': u,
        'url': u,
        'thumbs': [thumb],
        'media': {
            'url': u,
            'thumb': thumb,
            'width': int(width or 1280),
            'height': int(height or 720),
            'duration': int(duration or 0),
            'totalSize': int(total_size or 0)
        },
        'tType': 4,
        'tWidth': int(width or 1280),
        'tHeight': int(height or 720),
        'width': int(width or 1280),
        'height': int(height or 720),
        'duration': int(duration or 0),
        'totalSize': int(total_size or 0),
        'actionId': 0
    }

def build_sticker_attach(cat_id: Union[int, str], sticker_id: Union[int, str], sticker_type: int=7) -> Dict[str, Any]:
    return {'id': int(sticker_id), 'catId': int(cat_id), 'type': int(sticker_type)}

def build_location_attach(lat: Union[float, int, str], lon: Union[float, int, str], address: str='', place_id: str='', is_user_location: int=1, title: str='', href: str='', thumb: str='') -> Dict[str, Any]:
    params = {
        'longitude': str(lon),
        'latitude': str(lat),
        'placeId': str(place_id or ''),
        'isUserLocation': int(is_user_location)
    }
    return {
        'title': str(title or ''),
        'description': str(address or ''),
        'href': str(href or ''),
        'thumb': str(thumb or ''),
        'childnumber': 0,
        'action': '',
        'params': json.dumps(params, separators=(',', ':'), ensure_ascii=False),
        'type': ''
    }

def build_file_attach(file_url: str, file_name: str, file_size: Union[int, str]=0, checksum: str='', file_ext: str='', duration: int=0, f_type: int=1, thumb: str='') -> Dict[str, Any]:
    fname = str(file_name or '')
    if not file_ext and '.' in fname:
        file_ext = fname.rsplit('.', 1)[1]
    params = {
        'fileSize': str(file_size or 0),
        'checksum': str(checksum or ''),
        'fileExt': str(file_ext or ''),
        'tWidth': 0,
        'tHeight': 0,
        'duration': int(duration or 0),
        'fType': int(f_type or 1),
        'fdata': ''
    }
    return {
        'title': fname,
        'description': '',
        'href': str(file_url or ''),
        'thumb': str(thumb or ''),
        'childnumber': 0,
        'action': '',
        'params': json.dumps(params, separators=(',', ':'), ensure_ascii=False),
        'type': ''
    }

def build_contact_attach(contact_uid: Union[int, str], contact_name: str='', avatar_url: str='', qr_code_url: str='', href: str='https://zalo.me') -> Dict[str, Any]:
    desc = json.dumps({'qrCodeUrl': str(qr_code_url or '')}, separators=(',', ':')) if qr_code_url else ''
    return {
        'title': str(contact_name or str(contact_uid)),
        'description': desc,
        'href': str(href or 'https://zalo.me'),
        'thumb': str(avatar_url or ''),
        'childnumber': 0,
        'action': 'recommened.user',
        'params': str(contact_uid),
        'type': ''
    }
